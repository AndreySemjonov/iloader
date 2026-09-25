//! Explicit foreground USB host-pair repair. Never called by discovery or renewal.
use std::{future::Future, sync::Mutex, time::Duration};

use idevice::{
    IdeviceError, lockdown::LockdownClient, pairing_file::PairingFile, usbmuxd::Connection,
};
use serde::Serialize;
use tauri::{AppHandle, Manager, State};
use tokio_util::sync::CancellationToken;
mod persistence;

use crate::{
    device::{DeviceInfo, DeviceInfoMutex, get_usbmuxd},
    error::AppError,
    install_lock::InstallLease,
};

/// Serializes selection/setup and repair so an old selection cannot overwrite
/// the repaired in-memory pairing after the command finishes.
pub type PairingOperation = tokio::sync::Mutex<()>;
#[derive(Default)]
pub struct RepairCancellation(Mutex<Option<CancellationToken>>);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RepairStatus {
    Completed,
    Pending,
    Locked,
    Denied,
    DeviceGone,
    WrongDevice,
    Cancelled,
    Failed,
    Uncertain,
    Partial,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RepairResult {
    status: RepairStatus,
    stage: &'static str,
    pair_accepted: bool,
    record_saved: bool,
    // USB verification is never presented as Wi-Fi service verification.
    wifi_services_verified: bool,
}

type Step<T> = Result<T, RepairStatus>;

trait RepairBackend {
    type Record;
    fn prepare(&mut self) -> impl Future<Output = Step<()>> + Send;
    fn pair_once(&mut self) -> impl Future<Output = Step<Self::Record>> + Send;
    fn persist(&mut self, record: &Self::Record) -> impl Future<Output = Step<()>> + Send;
    fn verify(&mut self, record: &Self::Record) -> impl Future<Output = Step<()>> + Send;
}

async fn run<B: RepairBackend>(backend: &mut B, cancel: &CancellationToken) -> RepairResult {
    run_with_pair_timeout(backend, cancel, Duration::from_secs(60)).await
}

async fn run_with_pair_timeout<B: RepairBackend>(
    backend: &mut B,
    cancel: &CancellationToken,
    pair_timeout: Duration,
) -> RepairResult {
    let mut result = RepairResult {
        status: RepairStatus::Failed,
        stage: "prepare",
        pair_accepted: false,
        record_saved: false,
        wifi_services_verified: false,
    };
    let prepared = tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(RepairStatus::Cancelled),
        value = tokio::time::timeout(Duration::from_secs(15), backend.prepare()) =>
            value.unwrap_or(Err(RepairStatus::Failed)),
    };
    if let Err(status) = prepared {
        result.status = status;
        return result;
    }
    if cancel.is_cancelled() {
        result.status = RepairStatus::Cancelled;
        return result;
    }

    result.stage = "pair";
    // Once sent, do not cancel between a successful Pair and SavePairRecord.
    // A timeout/disconnection may mean the phone accepted a request whose reply
    // was lost. Report uncertainty and never automatically resend it.
    let record = match tokio::time::timeout(pair_timeout, backend.pair_once()).await {
        Ok(Ok(record)) => record,
        Ok(Err(status)) => {
            result.status = status;
            return result;
        }
        Err(_) => {
            result.status = RepairStatus::Uncertain;
            return result;
        }
    };
    result.pair_accepted = true;
    result.stage = "save";
    match tokio::time::timeout(Duration::from_secs(15), backend.persist(&record)).await {
        Ok(Ok(())) => result.record_saved = true,
        _ => {
            result.status = RepairStatus::Partial;
            return result;
        }
    }
    result.stage = "verifyUsb";
    match tokio::time::timeout(Duration::from_secs(20), backend.verify(&record)).await {
        Ok(Ok(())) => result.status = RepairStatus::Completed,
        _ => result.status = RepairStatus::Partial,
    }
    result
}

fn valid_usb_target(device: &DeviceInfo) -> bool {
    device.connection_type == "USB"
        && device.network_address.is_none()
        && !device.udid.is_empty()
        && device.id != 0
}

fn usb_matches(device: &DeviceInfo, id: u32, udid: &str, connection: &Connection) -> bool {
    valid_usb_target(device)
        && device.id == id
        && device.udid == udid
        && matches!(connection, Connection::Usb)
}

fn pair_error(error: IdeviceError) -> RepairStatus {
    match error {
        IdeviceError::PairingDialogResponsePending => RepairStatus::Pending,
        IdeviceError::PasswordProtected => RepairStatus::Locked,
        IdeviceError::UserDeniedPairing => RepairStatus::Denied,
        // Do not format device/library error text into logs or frontend output.
        _ => RepairStatus::Uncertain,
    }
}

async fn connect_exact(device: &DeviceInfo) -> Step<LockdownClient> {
    let mut mux = get_usbmuxd().await.map_err(|_| RepairStatus::DeviceGone)?;
    let devices = mux
        .get_devices()
        .await
        .map_err(|_| RepairStatus::DeviceGone)?;
    let matches = devices
        .iter()
        .filter(|candidate| {
            usb_matches(
                device,
                candidate.device_id,
                &candidate.udid,
                &candidate.connection_type,
            )
        })
        .count();
    if matches != 1 {
        return Err(RepairStatus::DeviceGone);
    }
    // Deliberately bypass provider fallback and automatic session/pair helpers.
    let stream = mux
        .connect_to_device(device.id, 62078, "iloader-usb-repair")
        .await
        .map_err(|_| RepairStatus::DeviceGone)?;
    let mut client = LockdownClient::new(stream);
    require_identity(&mut client, &device.udid).await?;
    Ok(client)
}

async fn require_identity(client: &mut LockdownClient, udid: &str) -> Step<()> {
    let value = client
        .get_value(Some("UniqueDeviceID"), None)
        .await
        .map_err(|_| RepairStatus::DeviceGone)?;
    if value.as_string() != Some(udid) {
        return Err(RepairStatus::WrongDevice);
    }
    Ok(())
}

struct UsbRepair<'a> {
    device: DeviceInfo,
    selected: &'a DeviceInfoMutex,
    client: Option<LockdownClient>,
    previous: Option<PairingFile>,
}

impl RepairBackend for UsbRepair<'_> {
    type Record = PairingFile;

    async fn prepare(&mut self) -> Step<()> {
        let mut mux = get_usbmuxd().await.map_err(|_| RepairStatus::DeviceGone)?;
        // This repair deliberately requires the existing host identity. Missing
        // or malformed records need initial setup; never reset/delete them here.
        let mut old = mux
            .get_pair_record(&self.device.udid)
            .await
            .map_err(|_| RepairStatus::Failed)?;
        if old.udid.as_deref().is_some_and(|id| id != self.device.udid) {
            return Err(RepairStatus::WrongDevice);
        }
        if old.host_id.is_empty() || old.system_buid.is_empty() {
            return Err(RepairStatus::Failed);
        }
        old.system_buid = mux.get_buid().await.map_err(|_| RepairStatus::Failed)?;
        if old.system_buid.is_empty() {
            return Err(RepairStatus::Failed);
        }
        self.previous = Some(old);
        self.client = Some(connect_exact(&self.device).await?);
        Ok(())
    }

    async fn pair_once(&mut self) -> Step<PairingFile> {
        let old = self.previous.as_ref().ok_or(RepairStatus::Failed)?;
        let client = self.client.as_mut().ok_or(RepairStatus::Failed)?;
        let mut record = client
            .pair_once(&old.host_id, &old.system_buid, Some("iLoader"))
            .await
            .map_err(pair_error)?;
        record.udid = Some(self.device.udid.clone());
        Ok(record)
    }

    async fn persist(&mut self, record: &PairingFile) -> Step<()> {
        let bytes = record
            .clone()
            .serialize()
            .map_err(|_| RepairStatus::Failed)?;
        // Use the host's normal pairing store, never plaintext app storage or
        // an export path. Include the selected USB handle for the standard
        // daemon pairing notification, which idevice's convenience API omits.
        persistence::save(&self.device, &bytes).await?;

        // Immediately replace cached Lockdown fields, preserving independent RP
        // data. Invalidate selection on a cache error rather than use stale keys.
        {
            let mut selected = self.selected.lock().map_err(|_| RepairStatus::Failed)?;
            if let Some(current) = selected.as_mut()
                && current.info.udid == self.device.udid
            {
                match refresh_export(&current.pairing, &bytes) {
                    Ok(pairing) => current.pairing = pairing,
                    Err(_) => {
                        *selected = None;
                        return Err(RepairStatus::Failed);
                    }
                }
            }
        }
        let mut mux = get_usbmuxd().await.map_err(|_| RepairStatus::Failed)?;
        let mut saved = mux
            .get_pair_record(&self.device.udid)
            .await
            .map_err(|_| RepairStatus::Failed)?;
        saved.udid = Some(self.device.udid.clone());
        if saved.serialize().map_err(|_| RepairStatus::Failed)? != bytes {
            return Err(RepairStatus::Failed);
        }
        Ok(())
    }

    async fn verify(&mut self, record: &PairingFile) -> Step<()> {
        // A new socket must authenticate with the newly saved identity.
        self.client = None;
        let mut client = connect_exact(&self.device).await?;
        client
            .start_session(record)
            .await
            .map_err(|_| RepairStatus::Failed)?;
        require_identity(&mut client, &self.device.udid).await?;
        for key in ["EnableWifiConnections", "EnableWifiDebugging"] {
            client
                .set_value(key, true.into(), Some("com.apple.mobile.wireless_lockdown"))
                .await
                .map_err(|_| RepairStatus::Failed)?;
            if client
                .get_value(Some(key), Some("com.apple.mobile.wireless_lockdown"))
                .await
                .map_err(|_| RepairStatus::Failed)?
                .as_boolean()
                != Some(true)
            {
                return Err(RepairStatus::Failed);
            }
        }
        Ok(())
    }
}

fn refresh_export(old: &[u8], replacement: &[u8]) -> Step<Vec<u8>> {
    let old =
        plist::Value::from_reader(std::io::Cursor::new(old)).map_err(|_| RepairStatus::Failed)?;
    let mut merged = old.into_dictionary().ok_or(RepairStatus::Failed)?;
    let new = plist::Value::from_reader(std::io::Cursor::new(replacement))
        .map_err(|_| RepairStatus::Failed)?;
    let new = new.into_dictionary().ok_or(RepairStatus::Failed)?;
    // Optional old fields must not survive if absent from the new record.
    merged.remove("EscrowBag");
    merged.extend(new);
    let mut bytes = Vec::new();
    plist::Value::Dictionary(merged)
        .to_writer_xml(&mut bytes)
        .map_err(|_| RepairStatus::Failed)?;
    Ok(bytes)
}

#[tauri::command]
pub async fn repair_wifi_pairing(
    app: AppHandle,
    device: DeviceInfo,
    selected: State<'_, DeviceInfoMutex>,
    operation: State<'_, PairingOperation>,
    cancellation: State<'_, RepairCancellation>,
) -> Result<RepairResult, AppError> {
    let _operation = operation
        .try_lock()
        .map_err(|_| AppError::Misc("Device setup is busy. Wait for it to finish.".into()))?;
    // The repair dialog has its own explicit USB target. Normal device selection
    // may itself fail when the host pairing needs repair.
    if !valid_usb_target(&device) {
        return Err(AppError::Misc(
            "Select an exact USB device in the repair dialog.".into(),
        ));
    }
    let directory = app
        .path()
        .app_data_dir()
        .map_err(|_| AppError::Misc("App directory unavailable".into()))?;
    let _lease = InstallLease::acquire(&directory)?;
    let cancel = CancellationToken::new();
    *cancellation
        .0
        .lock()
        .map_err(|_| AppError::Misc("Repair state unavailable".into()))? = Some(cancel.clone());
    let mut backend = UsbRepair {
        device,
        selected: &selected,
        client: None,
        previous: None,
    };
    let result = run(&mut backend, &cancel).await;
    if matches!(
        result.status,
        RepairStatus::Partial | RepairStatus::Uncertain
    ) && let Ok(mut selected) = selected.lock()
    {
        // No export/install consumer may keep an old pairing after an ambiguous
        // phone/host commit. The UI also suppresses automatic re-selection.
        *selected = None;
    }
    if let Ok(mut token) = cancellation.0.lock() {
        *token = None;
    }
    Ok(result)
}

#[tauri::command]
pub fn cancel_wifi_pairing_repair(cancellation: State<'_, RepairCancellation>) {
    if let Ok(token) = cancellation.0.lock()
        && let Some(token) = token.as_ref()
    {
        token.cancel();
    }
}

#[cfg(test)]
mod tests;
