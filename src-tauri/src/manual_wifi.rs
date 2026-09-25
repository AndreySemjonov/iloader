use crate::{
    device::{DeviceInfo, DeviceInfoMutex},
    phone_transport::{PhoneIdentity, SavedPhone, WrongPhone},
};
use idevice::{
    Idevice, IdeviceError, IdeviceService,
    afc::AfcClient,
    installation_proxy::InstallationProxyClient,
    lockdown::LockdownClient,
    pairing_file::PairingFile,
    provider::IdeviceProvider,
    usbmuxd::{Connection, UsbmuxdAddr, UsbmuxdDevice},
};
use serde::Serialize;
use std::{future::Future, pin::Pin, time::Duration};
use tauri::State;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum Stage {
    Selection,
    NetworkInventory,
    PairingRecord,
    Identity,
    AfcStart,
    AfcRead,
    InstallationProxyStart,
    InstallationProxyRead,
    WatchTransport,
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum Problem {
    WifiRequired,
    NetworkDeviceUnavailable,
    SavedPairingUnavailable,
    TrustRejected,
    DeviceLocked,
    WrongDevice,
    TimedOut,
    ServiceFailed,
    WatchTransportUnavailable,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CheckReport {
    pub transport: Option<&'static str>,
    pub connected: bool,
    pub stage: Stage,
    pub problem: Option<Problem>,
    pub afc_read: bool,
    pub installation_proxy_read: bool,
    pub watch_verified: bool,
}
impl Default for CheckReport {
    fn default() -> Self {
        Self {
            transport: None,
            connected: false,
            stage: Stage::Selection,
            problem: None,
            afc_read: false,
            installation_proxy_read: false,
            watch_verified: false,
        }
    }
}

fn problem(error: IdeviceError) -> Problem {
    match error {
        IdeviceError::InvalidHostID
        | IdeviceError::UserDeniedPairing
        | IdeviceError::PairingDialogResponsePending => Problem::TrustRejected,
        IdeviceError::PasswordProtected | IdeviceError::DeviceLocked => Problem::DeviceLocked,
        IdeviceError::Timeout => Problem::TimedOut,
        IdeviceError::Socket(ref error)
            if error.get_ref().is_some_and(|e| e.is::<WrongPhone>()) =>
        {
            Problem::WrongDevice
        }
        IdeviceError::NotFound => Problem::NetworkDeviceUnavailable,
        _ => Problem::ServiceFailed,
    }
}

async fn step<T>(
    report: &mut CheckReport,
    stage: Stage,
    work: impl Future<Output = Result<T, IdeviceError>>,
) -> Result<T, Problem> {
    report.stage = stage;
    match tokio::time::timeout(Duration::from_secs(12), work).await {
        Ok(Ok(value)) => Ok(value),
        value => {
            let failure = match value {
                Ok(Err(error)) => problem(error),
                _ => Problem::TimedOut,
            };
            report.problem = Some(failure);
            Err(failure)
        }
    }
}

fn exact_network(
    devices: &[UsbmuxdDevice],
    udid: &str,
    id: Option<u32>,
) -> Result<u32, IdeviceError> {
    let mut candidates = devices
        .iter()
        .filter(|d| d.udid == udid && matches!(d.connection_type, Connection::Network(_)));
    let candidate = candidates.next().ok_or(IdeviceError::NotFound)?;
    if candidates.next().is_some() || id.is_some_and(|id| id != candidate.device_id) {
        return Err(IdeviceError::NotFound);
    }
    Ok(candidate.device_id)
}

/// Only daemon Network handles are admitted, including on every later service
/// socket. This follows the currently validated AFC route without USB fallback.
#[derive(Clone, Debug)]
pub(crate) struct NetworkPhone {
    address: UsbmuxdAddr,
    id: u32,
    udid: String,
    pairing: PairingFile,
}

impl IdeviceProvider for NetworkPhone {
    fn connect(
        &self,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<Idevice, IdeviceError>> + Send>> {
        let provider = self.clone();
        Box::pin(async move {
            let mut mux = provider.address.connect(0).await?;
            let devices = mux.get_devices().await?;
            exact_network(&devices, &provider.udid, Some(provider.id))?;
            mux.connect_to_device(provider.id, port, "iloader-manual-wifi")
                .await
        })
    }
    fn label(&self) -> &str {
        "iloader-manual-wifi"
    }
    fn get_pairing_file(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<PairingFile, IdeviceError>> + Send>> {
        let pairing = self.pairing.clone();
        Box::pin(async move { Ok(pairing) })
    }
}

impl PhoneIdentity for NetworkPhone {
    fn authenticated_identity(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<String, IdeviceError>> + Send>> {
        let provider = self.clone();
        Box::pin(async move {
            let mut lockdown = LockdownClient::connect(&provider).await?;
            lockdown.start_session(&provider.pairing).await?;
            let value = lockdown.get_value(Some("UniqueDeviceID"), None).await?;
            value
                .as_string()
                .filter(|id| !id.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| IdeviceError::Socket(std::io::Error::other(WrongPhone)))
        })
    }
}

pub(crate) struct PhoneConnection {
    pub provider: SavedPhone<NetworkPhone>,
    // The successful diagnostic retained its parent lockdown session. Keep the
    // same lifetime for service checks and the subsequent low-level installer.
    _lockdown: LockdownClient,
}

pub(crate) async fn connect_phone(
    device: &DeviceInfo,
    report: &mut CheckReport,
) -> Result<PhoneConnection, Problem> {
    if device.connection_type != "Network" || device.udid.is_empty() {
        report.problem = Some(Problem::WifiRequired);
        return Err(Problem::WifiRequired);
    }
    connect_saved_phone(&device.udid, report).await
}

/// Shared saved-enrollment route: exact authenticated daemon Network identity,
/// with the same retained lockdown lifetime and service guards as manual renewal.
pub(crate) async fn connect_saved_phone(
    phone_id: &str,
    report: &mut CheckReport,
) -> Result<PhoneConnection, Problem> {
    if phone_id.is_empty() {
        return Err(Problem::WrongDevice);
    }
    report.transport = Some("appleDaemonNetwork");
    let address = UsbmuxdAddr::from_env_var().map_err(|_| {
        report.problem = Some(Problem::NetworkDeviceUnavailable);
        Problem::NetworkDeviceUnavailable
    })?;
    let mut mux = step(report, Stage::NetworkInventory, address.connect(0)).await?;
    let devices = step(report, Stage::NetworkInventory, mux.get_devices()).await?;
    let id = exact_network(&devices, phone_id, None).map_err(|error| {
        let error = problem(error);
        report.problem = Some(error);
        error
    })?;
    let mut pairing = step(report, Stage::PairingRecord, mux.get_pair_record(phone_id))
        .await
        .map_err(|error| {
            let error = if error == Problem::TimedOut {
                error
            } else {
                Problem::SavedPairingUnavailable
            };
            report.problem = Some(error);
            error
        })?;
    if pairing.udid.as_deref().is_some_and(|id| id != phone_id) {
        report.problem = Some(Problem::WrongDevice);
        return Err(Problem::WrongDevice);
    }
    pairing.udid = Some(phone_id.to_owned());
    let provider = SavedPhone::new(
        NetworkPhone {
            address,
            id,
            udid: phone_id.to_owned(),
            pairing: pairing.clone(),
        },
        phone_id.to_owned(),
    )
    .map_err(|_| Problem::WrongDevice)?;
    let mut lockdown = step(report, Stage::Identity, LockdownClient::connect(&provider)).await?;
    step(report, Stage::Identity, lockdown.start_session(&pairing)).await?;
    let identity = step(
        report,
        Stage::Identity,
        lockdown.get_value(Some("UniqueDeviceID"), None),
    )
    .await?;
    if identity.as_string() != Some(phone_id) {
        report.problem = Some(Problem::WrongDevice);
        return Err(Problem::WrongDevice);
    }
    Ok(PhoneConnection {
        provider,
        _lockdown: lockdown,
    })
}

pub(crate) async fn phone_services(
    device: &DeviceInfo,
    report: &mut CheckReport,
) -> Result<PhoneConnection, Problem> {
    let phone = connect_phone(device, report).await?;
    let mut afc = step(report, Stage::AfcStart, AfcClient::connect(&phone.provider)).await?;
    step(report, Stage::AfcRead, afc.get_device_info()).await?;
    report.afc_read = true;
    let mut proxy = step(
        report,
        Stage::InstallationProxyStart,
        InstallationProxyClient::connect(&phone.provider),
    )
    .await?;
    step(
        report,
        Stage::InstallationProxyRead,
        proxy.get_apps(
            Some("User"),
            Some(vec!["com.iloader.connection-check.nonexistent".into()]),
        ),
    )
    .await?;
    report.installation_proxy_read = true;
    report.stage = Stage::Complete;
    report.connected = true;
    Ok(phone)
}

#[tauri::command]
pub(crate) async fn check_wifi_connection(
    state: State<'_, DeviceInfoMutex>,
) -> Result<CheckReport, crate::error::AppError> {
    let device = state
        .lock()
        .ok()
        .and_then(|d| d.as_ref().map(|d| d.info.clone()));
    let mut report = CheckReport::default();
    let Some(device) = device else {
        report.problem = Some(Problem::WifiRequired);
        return Ok(report);
    };
    let _ = Box::pin(route(
        false,
        || phone_services(&device, &mut report),
        || async { Err::<(), _>(Problem::WatchTransportUnavailable) },
    ))
    .await;
    Ok(report)
}

/// Own only a freshly created per-attempt directory. Drop never touches the
/// user's original IPA, another setup's archive, or a previous interrupted job.
pub(crate) struct Original {
    directory: std::path::PathBuf,
    path: std::path::PathBuf,
    watch: bool,
}
impl Original {
    pub(crate) fn retain(
        source: &std::path::Path,
        app_directory: &std::path::Path,
    ) -> Result<Self, crate::error::AppError> {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| {
                crate::error::AppError::Misc("Unable to snapshot the original IPA".into())
            })?
            .as_nanos();
        let directory = app_directory.join(format!("manual-wifi-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&directory).map_err(|_| {
            crate::error::AppError::Misc("Unable to snapshot the original IPA".into())
        })?;
        let mut original = Self {
            directory,
            path: std::path::PathBuf::new(),
            watch: false,
        };
        let identity =
            crate::renewal::archive::retain(source, &original.directory).map_err(|_| {
                crate::error::AppError::Misc(
                    "Original IPA is unreadable or its app structure is invalid".into(),
                )
            })?;
        original.path = identity.path(&original.directory).map_err(|_| {
            crate::error::AppError::Misc("Unable to verify the original IPA".into())
        })?;
        original.watch = identity.has_watch;
        Ok(original)
    }
    pub(crate) fn has_watch(&self) -> bool {
        self.watch
    }
    pub(crate) fn path(&self) -> std::path::PathBuf {
        self.path.clone()
    }
}
impl Drop for Original {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

pub(crate) fn require_watch_content(
    original: bool,
    signed: bool,
) -> Result<(), crate::error::AppError> {
    if original != signed {
        return Err(crate::error::AppError::Misc(
            "Signed app Watch content differs from the original IPA; installation stopped.".into(),
        ));
    }
    Ok(())
}

pub(crate) async fn install_checked<T, F>(
    original: bool,
    signed: bool,
    install: impl FnOnce() -> F,
) -> Result<T, crate::error::AppError>
where
    F: Future<Output = Result<T, crate::error::AppError>>,
{
    require_watch_content(original, signed)?;
    install().await
}

pub(crate) enum Route<P, W> {
    Phone(P),
    Watch(W),
}

// Shared manual check/install dispatch. I/O is supplied lazily so the regression
// can represent a working phone transport with absent RemotePairing discovery.
pub(crate) async fn route<P, W, E, PF, WF>(
    has_watch: bool,
    phone: impl FnOnce() -> PF,
    watch: impl FnOnce() -> WF,
) -> Result<Route<P, W>, E>
where
    PF: Future<Output = Result<P, E>>,
    WF: Future<Output = Result<W, E>>,
{
    if has_watch {
        watch().await.map(Route::Watch)
    } else {
        phone().await.map(Route::Phone)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[tokio::test]
    async fn manual_phone_check_accepts_working_afc_without_remote_pairing_advertisement() {
        let phone_checked = Cell::new(false);
        let remote_discovery = Cell::new(false);
        let result = route(
            false,
            || async {
                phone_checked.set(true);
                Ok::<_, &'static str>("authenticated AFC and install proxy")
            },
            || async {
                remote_discovery.set(true);
                Err::<(), _>("RemotePairing advertisement absent")
            },
        )
        .await;
        assert!(
            matches!(result, Ok(Route::Phone(_))),
            "manual check rejected working phone services because RemotePairing was absent"
        );
        assert!(phone_checked.get());
        assert!(!remote_discovery.get());
    }

    #[tokio::test]
    async fn watch_archive_never_downgrades_and_phone_error_never_falls_back() {
        let result = route(
            true,
            || async {
                panic!("Watch archive reached phone-only installer");
                #[allow(unreachable_code)]
                Ok::<(), _>(())
            },
            || async { Err::<(), _>(Problem::WatchTransportUnavailable) },
        )
        .await;
        assert!(matches!(result, Err(Problem::WatchTransportUnavailable)));
        let result = route(
            false,
            || async { Err::<(), _>(Problem::TrustRejected) },
            || async {
                panic!("Phone failure started Watch/RemotePairing transport");
                #[allow(unreachable_code)]
                Ok::<(), _>(())
            },
        )
        .await;
        assert!(matches!(result, Err(Problem::TrustRejected)));
    }

    #[tokio::test]
    async fn original_signed_watch_mismatch_prevents_upload_callback() {
        for (original, signed) in [(true, false), (false, true)] {
            let uploaded = Cell::new(false);
            let result = install_checked(original, signed, || async {
                uploaded.set(true);
                Ok(())
            })
            .await;
            assert!(result.is_err());
            assert!(!uploaded.get());
        }
        let uploaded = Cell::new(false);
        install_checked(false, false, || async {
            uploaded.set(true);
            Ok(())
        })
        .await
        .unwrap();
        assert!(uploaded.get());
    }

    #[test]
    fn every_daemon_connection_requires_one_exact_network_handle() {
        let usb = UsbmuxdDevice {
            device_id: 7,
            udid: "selected".into(),
            connection_type: Connection::Usb,
        };
        let network = UsbmuxdDevice {
            device_id: 8,
            udid: "selected".into(),
            connection_type: Connection::Network("127.0.0.1".parse().unwrap()),
        };
        let wrong = UsbmuxdDevice {
            udid: "other".into(),
            ..network.clone()
        };
        assert_eq!(
            exact_network(&[usb.clone(), network.clone()], "selected", Some(8)).unwrap(),
            8
        );
        assert!(exact_network(&[usb], "selected", None).is_err());
        assert!(exact_network(&[wrong], "selected", Some(8)).is_err());
        assert!(exact_network(&[network.clone()], "selected", Some(7)).is_err());
        assert!(exact_network(&[network.clone(), network], "selected", None).is_err());
    }

    #[tokio::test]
    async fn failed_service_keeps_exact_stage_and_sanitized_problem() {
        let mut report = CheckReport::default();
        report.afc_read = true;
        let result = step(&mut report, Stage::InstallationProxyStart, async {
            Err::<(), _>(IdeviceError::UnexpectedResponse(
                "secret sentinel 192.0.2.1".into(),
            ))
        })
        .await;
        assert_eq!(result, Err(Problem::ServiceFailed));
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["stage"], "installationProxyStart");
        assert_eq!(value["problem"], "serviceFailed");
        assert_eq!(value["afcRead"], true);
        assert_eq!(value["watchVerified"], false);
        assert!(!value.to_string().contains("sentinel"));
        assert!(!value.to_string().contains("192.0.2.1"));
        assert!(!report.connected);
    }

    #[test]
    fn immutable_original_preserves_watch_and_cleans_only_its_own_copy() {
        use std::{fs, io::Write};
        use zip::{ZipWriter, write::SimpleFileOptions};
        let root = std::env::temp_dir().join(format!(
            "iloader-manual-original-test-{}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let source = root.join("original.ipa");
        let mut zip = ZipWriter::new(fs::File::create(&source).unwrap());
        for (path, id) in [
            ("Payload/Main.app/Info.plist", "test.main"),
            ("Payload/Main.app/Watch/Watch.app/Info.plist", "test.watch"),
        ] {
            zip.start_file(path, SimpleFileOptions::default()).unwrap();
            write!(zip,"<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>{id}</string></dict></plist>").unwrap();
        }
        zip.finish().unwrap();
        let original = Original::retain(&source, &root).unwrap();
        assert!(original.has_watch());
        fs::write(&source, b"user replaced the original file").unwrap();
        assert!(
            crate::renewal::archive::inspect(&original.path())
                .unwrap()
                .has_watch
        );
        assert!(require_watch_content(original.has_watch(), false).is_err());
        assert!(require_watch_content(false, true).is_err());
        assert!(require_watch_content(true, true).is_ok());
        let copy = original.path();
        drop(original);
        assert!(!copy.exists());
        assert_eq!(
            fs::read(&source).unwrap(),
            b"user replaced the original file"
        );
        fs::remove_file(&source).unwrap();
        fs::remove_dir(root).unwrap();
    }
}
