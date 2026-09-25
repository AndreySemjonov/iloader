use std::{
    collections::HashSet,
    future::Future,
    net::{IpAddr, Ipv4Addr},
    pin::Pin,
    sync::Mutex,
    time::Duration,
};

use idevice::{
    Idevice, IdeviceError, IdeviceService,
    lockdown::LockdownClient,
    pairing_file::PairingFile,
    provider::{IdeviceProvider, TcpProvider, UsbmuxdProvider},
    usbmuxd::{Connection, UsbmuxdAddr, UsbmuxdConnection},
};
use mdns_sd::{ServiceDaemon, ServiceEvent};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, State};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::{
    error::AppError,
    pairing::{existing_wifi_pairing_file, pairing_file},
    wifi_rsd::{bootstrap_remote_pairing, known_remote_pairing_udids},
};

const MOBDEV2_SERVICE: &str = "_apple-mobdev2._tcp.local.";
const WIFI_DISCOVERY_TIMEOUT: Duration = Duration::from_millis(1500);
const WIFI_CONNECT_TIMEOUT: Duration = Duration::from_millis(1000);

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfo {
    pub name: String,
    pub id: u32,
    pub udid: String,
    pub connection_type: String,
    pub version: String,
    #[serde(default)]
    pub network_address: Option<String>,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfoWithPairing {
    pub info: DeviceInfo,
    pub pairing: Vec<u8>,
}

pub type DeviceInfoMutex = Mutex<Option<DeviceInfoWithPairing>>;
pub type PairingCancelToken = Mutex<Option<CancellationToken>>;

#[derive(Debug)]
pub enum DeviceProvider {
    Usbmuxd(UsbmuxdProvider),
    Tcp(TcpProvider),
}

impl IdeviceProvider for DeviceProvider {
    fn connect(
        &self,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<Idevice, IdeviceError>> + Send>> {
        match self {
            Self::Usbmuxd(provider) => provider.connect(port),
            Self::Tcp(provider) => provider.connect(port),
        }
    }

    fn label(&self) -> &str {
        match self {
            Self::Usbmuxd(provider) => provider.label(),
            Self::Tcp(provider) => provider.label(),
        }
    }

    fn get_pairing_file(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<PairingFile, IdeviceError>> + Send>> {
        match self {
            Self::Usbmuxd(provider) => provider.get_pairing_file(),
            Self::Tcp(provider) => provider.get_pairing_file(),
        }
    }
}

pub(crate) async fn discover_wifi_addresses() -> Result<Vec<Ipv4Addr>, AppError> {
    let mdns = ServiceDaemon::new().map_err(|e| {
        AppError::DeviceComsWithMessage(
            "Failed to start Bonjour/mDNS discovery".into(),
            e.to_string(),
        )
    })?;
    let receiver = mdns.browse(MOBDEV2_SERVICE).map_err(|e| {
        AppError::DeviceComsWithMessage(
            "Failed to browse for Wi-Fi iOS devices".into(),
            e.to_string(),
        )
    })?;

    let deadline = tokio::time::Instant::now() + WIFI_DISCOVERY_TIMEOUT;
    let mut addresses = HashSet::new();

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        match tokio::time::timeout(remaining, receiver.recv_async()).await {
            Ok(Ok(ServiceEvent::ServiceResolved(service))) => {
                addresses.extend(service.get_addresses_v4());
            }
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                warn!("Bonjour/mDNS receiver stopped: {e}");
                break;
            }
            Err(_) => break,
        }
    }

    let _ = mdns.stop_browse(MOBDEV2_SERVICE);
    let _ = mdns.shutdown();
    Ok(addresses.into_iter().collect())
}

pub(crate) async fn inspect_wifi_device(
    addr: Ipv4Addr,
    pairing_file: &PairingFile,
) -> Result<DeviceInfo, AppError> {
    inspect_wifi_device_observed(addr, pairing_file, |_| {}).await
}

/// Observes the typed session error before AppError's string conversion. The
/// observer does not alter requests, retry, or create trust.
pub(crate) async fn start_wifi_session(
    client: &mut LockdownClient,
    pairing_file: &PairingFile,
    mut observe: impl FnMut(&IdeviceError),
) -> Result<bool, IdeviceError> {
    client
        .start_session(pairing_file)
        .await
        .inspect_err(|error| observe(error))
}

pub(crate) async fn inspect_wifi_device_observed(
    addr: Ipv4Addr,
    pairing_file: &PairingFile,
    observe: impl FnMut(&IdeviceError),
) -> Result<DeviceInfo, AppError> {
    let stream = tokio::time::timeout(
        WIFI_CONNECT_TIMEOUT,
        tokio::net::TcpStream::connect((addr, LockdownClient::LOCKDOWND_PORT)),
    )
    .await
    .map_err(|e| {
        AppError::DeviceComsWithMessage(
            format!("Timed out connecting to Wi-Fi device {addr}"),
            e.to_string(),
        )
    })?
    .map_err(|e| {
        AppError::DeviceComsWithMessage(
            format!("Failed to connect to Wi-Fi device {addr}"),
            e.to_string(),
        )
    })?;

    let idevice = Idevice::new(Box::new(stream), "iloader".to_string());
    let mut lockdown_client = LockdownClient::new(idevice);

    start_wifi_session(&mut lockdown_client, pairing_file, observe)
        .await
        .map_err(|e| {
            AppError::DeviceComsWithMessage(
                format!("Failed to authenticate Wi-Fi device {addr}"),
                e.to_string(),
            )
        })?;

    let udid_value = lockdown_client
        .get_value(Some("UniqueDeviceID"), None)
        .await
        .map_err(|e| {
            AppError::DeviceComsWithMessage(
                format!("Failed to read UDID from Wi-Fi device {addr}"),
                e.to_string(),
            )
        })?;
    let udid = udid_value
        .as_string()
        .ok_or_else(|| AppError::DeviceComs("Wi-Fi device UDID was not a string".into()))?;

    let name_value = lockdown_client
        .get_value(Some("DeviceName"), None)
        .await
        .map_err(|e| {
            AppError::DeviceComsWithMessage(
                format!("Failed to read name from Wi-Fi device {addr}"),
                e.to_string(),
            )
        })?;
    let name = name_value
        .as_string()
        .ok_or_else(|| AppError::DeviceComs("Wi-Fi device name was not a string".into()))?;

    let version_value = lockdown_client
        .get_value(Some("ProductVersion"), None)
        .await
        .map_err(|e| {
            AppError::DeviceComsWithMessage(
                format!("Failed to read version from Wi-Fi device {addr}"),
                e.to_string(),
            )
        })?;
    let version = version_value
        .as_string()
        .ok_or_else(|| AppError::DeviceComs("Product version was not a string".into()))?;

    Ok(DeviceInfo {
        name: name.to_string(),
        id: u32::from_be_bytes(addr.octets()),
        udid: udid.to_string(),
        connection_type: "Network".to_string(),
        version: version.to_string(),
        network_address: Some(addr.to_string()),
    })
}

async fn enable_wifi_connections(
    device: &DeviceInfo,
    usbmuxd: &mut UsbmuxdConnection,
) -> Result<(), AppError> {
    if device.connection_type != "USB" {
        return Ok(());
    }

    let provider = get_provider_from_connection(device, usbmuxd).await?;
    let mut pairing_file = usbmuxd.get_pair_record(&device.udid).await.map_err(|e| {
        AppError::LockdownPairing(
            "Failed to get pairing record while enabling Wi-Fi connections".into(),
            e.to_string(),
        )
    })?;
    pairing_file.udid = Some(device.udid.clone());

    let mut lockdown_client = LockdownClient::connect(&provider).await.map_err(|e| {
        AppError::DeviceComsWithMessage(
            "Failed to connect to lockdown while enabling Wi-Fi connections".into(),
            e.to_string(),
        )
    })?;

    lockdown_client
        .start_session(&pairing_file)
        .await
        .map_err(|e| {
            AppError::DeviceComsWithMessage(
                "Failed to start lockdown session while enabling Wi-Fi connections".into(),
                e.to_string(),
            )
        })?;

    lockdown_client
        .set_value(
            "EnableWifiConnections",
            true.into(),
            Some("com.apple.mobile.wireless_lockdown"),
        )
        .await
        .map_err(|e| {
            AppError::LockdownPairing("Failed to enable Wi-Fi connections".into(), e.to_string())
        })?;

    info!("Enabled wireless lockdown connections for the selected device");
    Ok(())
}

#[tauri::command]
pub async fn list_devices(
    app: AppHandle,
    device_state: State<'_, DeviceInfoMutex>,
) -> Result<Vec<Result<DeviceInfo, AppError>>, AppError> {
    let mut usbmuxd = get_usbmuxd().await?;

    let selected_udid = {
        let guard = device_state.lock().unwrap();
        guard.as_ref().map(|selected| selected.info.udid.clone())
    };

    let mut known_udids: HashSet<String> = known_remote_pairing_udids(&app)?.into_iter().collect();

    if let Some(udid) = selected_udid.as_ref() {
        known_udids.insert(udid.clone());
    }

    let mut known_pairings = Vec::new();

    for udid in known_udids {
        match usbmuxd.get_pair_record(&udid).await {
            Ok(mut pairing_file) => {
                pairing_file.udid = Some(udid.clone());
                known_pairings.push((udid, pairing_file));
            }
            Err(e) => {
                warn!("Unable to load lockdown pairing record for a known Wi-Fi device: {e}");
            }
        }
    }
    let devs = usbmuxd.get_devices().await.map_err(|e| {
        AppError::Usbmuxd("Failed to list devices from usbmuxd".into(), e.to_string())
    })?;

    let usbmuxd_addr = UsbmuxdAddr::from_env_var().map_err(|e| {
        AppError::Usbmuxd(
            "Invalid usbmuxd address from environment".into(),
            e.to_string(),
        )
    })?;

    let device_info_futures: Vec<_> = devs
        .iter()
        .map(|d| {
            let usbmuxd_addr = usbmuxd_addr.clone();
            async move {
                let provider = d.to_provider(usbmuxd_addr, "iloader");
                let device_uid = d.device_id;
                let connection_type = match d.connection_type {
                    Connection::Usb => "USB",
                    Connection::Network(_) => "Network",
                    Connection::Unknown(_) => "Unknown",
                }
                .to_string();

                let mut lockdown_client =
                    LockdownClient::connect(&provider).await.map_err(|e| {
                        eprintln!("Unable to connect to lockdown for {}: {e:?}", d.udid);
                        AppError::DeviceComsWithMessage(
                            "Unable to connect to lockdown".into(),
                            e.to_string(),
                        )
                    })?;

                let device_name_value = lockdown_client
                    .get_value(Some("DeviceName"), None)
                    .await
                    .map_err(|e| {
                    eprintln!("Failed to fetch DeviceName for {}: {e:?}", d.udid);
                    AppError::DeviceComsWithMessage(
                        "Failed to fetch DeviceName".into(),
                        e.to_string(),
                    )
                })?;

                let device_name = device_name_value.as_string().ok_or_else(|| {
                    eprintln!("DeviceName for {} was not a string", d.udid);
                    AppError::DeviceComs("DeviceName was not a string".into())
                })?;

                let version_value = lockdown_client
                    .get_value(Some("ProductVersion"), None)
                    .await
                    .map_err(|e| {
                        eprintln!("Failed to fetch ProductVersion for {}: {e:?}", d.udid);
                        AppError::DeviceComsWithMessage(
                            "Failed to fetch ProductVersion".into(),
                            e.to_string(),
                        )
                    })?;

                let version = version_value.as_string().ok_or_else(|| {
                    eprintln!("ProductVersion for {} was not a string", d.udid);
                    AppError::DeviceComs("Product version was not a string".into())
                })?;

                Ok::<DeviceInfo, AppError>(DeviceInfo {
                    name: device_name.to_string(),
                    id: device_uid,
                    udid: d.udid.clone(),
                    connection_type,
                    version: version.to_string(),
                    network_address: None,
                })
            }
        })
        .collect();

    let mut device_infos = futures::future::join_all(device_info_futures).await;

    if !known_pairings.is_empty() {
        match discover_wifi_addresses().await {
            Ok(addresses) => {
                for address in addresses {
                    let mut matched = false;

                    for (expected_udid, pairing_file) in &known_pairings {
                        let device = match inspect_wifi_device(address, pairing_file).await {
                            Ok(device) => device,
                            Err(_) => continue,
                        };

                        if device.udid != *expected_udid {
                            continue;
                        }

                        matched = true;

                        // Keep the authenticated direct address even when usbmuxd also
                        // advertises this phone. RSD renewal needs the direct transport.
                        prefer_direct_wifi(&mut device_infos, device);

                        break;
                    }

                    if !matched {
                        warn!("Ignoring a Wi-Fi candidate because no known pairing record matched");
                    }
                }
            }
            Err(e) => warn!("Unable to discover Wi-Fi devices with Bonjour/mDNS: {e}"),
        }
    }
    Ok(device_infos)
}

fn prefer_direct_wifi(devices: &mut Vec<Result<DeviceInfo, AppError>>, direct: DeviceInfo) {
    if let Some(existing) = devices.iter_mut().find(|entry| {
        matches!(entry, Ok(device) if device.udid == direct.udid && device.connection_type == "Network")
    }) {
        *existing = Ok(direct);
    } else {
        devices.push(Ok(direct));
    }
}

#[tauri::command]
pub async fn set_selected_device(
    app: AppHandle,
    device_state: State<'_, DeviceInfoMutex>,
    cancel_state: State<'_, PairingCancelToken>,
    device: Option<DeviceInfo>,
    operation: State<'_, crate::wifi_pairing::PairingOperation>,
) -> Result<(), AppError> {
    let _operation = operation
        .try_lock()
        .map_err(|_| AppError::Misc("Device setup is busy. Wait for it to finish.".into()))?;
    Box::pin(set_selected_device_impl(
        app,
        device_state,
        cancel_state,
        device,
    ))
    .await
}

async fn set_selected_device_impl(
    app: AppHandle,
    device_state: State<'_, DeviceInfoMutex>,
    cancel_state: State<'_, PairingCancelToken>,
    device: Option<DeviceInfo>,
) -> Result<(), AppError> {
    if device.is_none() {
        let mut device_state = device_state.lock().unwrap();
        *device_state = None;
        return Ok(());
    }

    if let Some(next_device) = device.as_ref() {
        let existing_pairing = {
            let guard = device_state.lock().unwrap();
            guard
                .as_ref()
                .filter(|current| current.info.udid == next_device.udid)
                .map(|current| current.pairing.clone())
        };

        if let Some(pairing) = existing_pairing {
            info!(
                "Reusing existing pairing while switching to {} transport",
                next_device.connection_type
            );
            let mut guard = device_state.lock().unwrap();
            *guard = Some(DeviceInfoWithPairing {
                info: next_device.clone(),
                pairing,
            });
            return Ok(());
        }
    }

    let mut usbmuxd = get_usbmuxd().await?;

    let token = tokio_util::sync::CancellationToken::new();
    {
        let mut guard = cancel_state.lock().unwrap();
        if let Some(old) = guard.replace(token.clone()) {
            old.cancel();
        }
    }

    let pairing_result = selection_pairing(
        device.as_ref().unwrap(),
        || existing_wifi_pairing_file(&app, device.as_ref().unwrap()),
        || pairing_file(&app, device.as_ref().unwrap(), &mut usbmuxd, token.clone()),
    )
    .await;

    if !token.is_cancelled() {
        let mut guard = cancel_state.lock().unwrap();
        *guard = None;
    }

    let pairing = pairing_result?;

    let device_with_pairing = DeviceInfoWithPairing {
        info: device.unwrap(),
        pairing,
    };
    let mut device_state = device_state.lock().unwrap();
    *device_state = Some(device_with_pairing);
    Ok(())
}

/// Explicit, user-requested Wi-Fi setup for the selected USB phone. It turns on
/// the phone's Wi-Fi connections setting and creates the RemotePairing trust used
/// for Wi-Fi installs. Selecting a device never changes the phone by itself.
#[tauri::command]
pub async fn setup_wifi(
    app: AppHandle,
    device_state: State<'_, DeviceInfoMutex>,
    operation: State<'_, crate::wifi_pairing::PairingOperation>,
) -> Result<(), AppError> {
    let _operation = operation
        .try_lock()
        .map_err(|_| AppError::Misc("Device setup is busy. Wait for it to finish.".into()))?;
    let selected = {
        let guard = device_state.lock().unwrap();
        guard.as_ref().map(|current| current.info.clone())
    }
    .ok_or(AppError::NoDeviceSelected)?;
    if selected.connection_type != "USB" || selected.network_address.is_some() {
        return Err(AppError::Misc(
            "Connect the phone with a USB cable and select its USB entry to set up Wi-Fi.".into(),
        ));
    }
    let mut usbmuxd = get_usbmuxd().await?;
    enable_wifi_connections(&selected, &mut usbmuxd).await?;
    let provider = get_provider_from_connection(&selected, &mut usbmuxd).await?;
    bootstrap_remote_pairing(&app, &selected, &provider).await?;
    info!("Wi-Fi setup completed for the selected USB device");
    Ok(())
}

#[tauri::command]
pub async fn cancel_pairing(cancel_state: State<'_, PairingCancelToken>) -> Result<(), AppError> {
    let mut guard = cancel_state.lock().unwrap();
    if let Some(token) = guard.take() {
        token.cancel();
    }
    Ok(())
}

pub async fn get_usbmuxd() -> Result<UsbmuxdConnection, AppError> {
    UsbmuxdConnection::default()
        .await
        .map_err(|e| AppError::Usbmuxd("Failed to connect to usbmuxd".into(), e.to_string()))
}

pub async fn get_provider(device_info: &DeviceInfo) -> Result<DeviceProvider, AppError> {
    get_provider_from_connection(device_info, &mut (get_usbmuxd().await?)).await
}

pub async fn get_provider_from_connection(
    device_info: &DeviceInfo,
    connection: &mut UsbmuxdConnection,
) -> Result<DeviceProvider, AppError> {
    if let Some(network_address) = device_info.network_address.as_deref() {
        let addr = network_address.parse::<IpAddr>().map_err(|e| {
            AppError::DeviceComsWithMessage("Invalid Wi-Fi device address".into(), e.to_string())
        })?;
        let mut pairing_file = connection
            .get_pair_record(&device_info.udid)
            .await
            .map_err(|e| {
                AppError::LockdownPairing(
                    "Failed to get pairing record for Wi-Fi device".into(),
                    e.to_string(),
                )
            })?;
        pairing_file.udid = Some(device_info.udid.clone());

        info!("Using direct Wi-Fi lockdown transport");
        return Ok(DeviceProvider::Tcp(TcpProvider {
            addr,
            scope_id: None,
            pairing_file,
            label: "iloader".to_string(),
        }));
    }

    let devices = connection.get_devices().await.map_err(|e| {
        AppError::DeviceComsWithMessage("Failed to list devices".into(), e.to_string())
    })?;

    let mut exact = None;
    let mut same_udid = None;

    for device in devices {
        if device.udid != device_info.udid {
            continue;
        }
        // A refreshed usbmuxd id may change; the chosen transport must not.
        if !transport_matches(&device_info.connection_type, &device.connection_type) {
            continue;
        }

        if device.device_id == device_info.id {
            exact = Some(device);
            break;
        }

        if same_udid.is_none() {
            same_udid = Some(device);
        }
    }

    let device = exact.or(same_udid).ok_or_else(|| {
        AppError::DeviceComsWithMessage(
            "Selected device connection is no longer available".into(),
            format!(
                "No usbmuxd connection is available for {} ({})",
                device_info.udid, device_info.connection_type
            ),
        )
    })?;

    if device.device_id != device_info.id {
        info!("Device changed usbmuxd connection id; continuing on the same UDID");
    }

    let provider = device.to_provider(UsbmuxdAddr::from_env_var().unwrap(), "iloader");
    Ok(DeviceProvider::Usbmuxd(provider))
}

fn transport_matches(selected: &str, connection: &Connection) -> bool {
    matches!(
        (selected, connection),
        ("USB", Connection::Usb) | ("Network", Connection::Network(_))
    )
}

async fn selection_pairing<Read, ReadFuture, Setup, SetupFuture>(
    device: &DeviceInfo,
    read: Read,
    setup: Setup,
) -> Result<Vec<u8>, AppError>
where
    Read: FnOnce() -> ReadFuture,
    ReadFuture: Future<Output = Result<Vec<u8>, AppError>>,
    Setup: FnOnce() -> SetupFuture,
    SetupFuture: Future<Output = Result<Vec<u8>, AppError>>,
{
    if device.connection_type == "Network" {
        read().await
    } else {
        setup().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(connection: &str, address: Option<&str>) -> DeviceInfo {
        DeviceInfo {
            name: "test".into(),
            id: 1,
            udid: "test-device".into(),
            connection_type: connection.into(),
            version: "27".into(),
            network_address: address.map(str::to_owned),
        }
    }

    #[test]
    fn selected_network_transport_refuses_usb_fallback() {
        assert!(!transport_matches("Network", &Connection::Usb));
        assert!(transport_matches("USB", &Connection::Usb));
    }

    #[test]
    fn direct_discovery_replaces_mux_network_without_hiding_usb() {
        let mut devices = vec![Ok(device("USB", None)), Ok(device("Network", None))];
        prefer_direct_wifi(&mut devices, device("Network", Some("192.0.2.1")));
        prefer_direct_wifi(&mut devices, device("Network", Some("192.0.2.2")));
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].as_ref().unwrap().connection_type, "USB");
        assert_eq!(
            devices[1].as_ref().unwrap().network_address.as_deref(),
            Some("192.0.2.2")
        );
    }

    #[tokio::test]
    async fn wifi_selection_never_invokes_setup_even_when_records_are_missing() {
        for present in [true, false] {
            let result = selection_pairing(
                &device("Network", Some("192.0.2.1")),
                || async {
                    if present {
                        Ok(vec![1])
                    } else {
                        Err(AppError::RemotePairing("missing".into()))
                    }
                },
                || async { panic!("Wi-Fi selection must not configure debugging or create trust") },
            )
            .await;
            assert_eq!(result.is_ok(), present);
        }
    }

    #[tokio::test]
    async fn usb_selection_keeps_explicit_onboarding_path() {
        let result = selection_pairing(
            &device("USB", None),
            || async { panic!("USB onboarding should use its existing setup path") },
            || async { Ok(vec![1]) },
        )
        .await
        .unwrap();
        assert_eq!(result, vec![1]);
    }
}
