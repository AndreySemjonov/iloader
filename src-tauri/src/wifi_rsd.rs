use std::{
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    time::Duration,
};

use idevice::{
    Idevice, IdeviceError, IdeviceService,
    provider::IdeviceProvider,
    remote_pairing::{
        RemotePairingClient, RpPairingFile, RpPairingSocket, RpPairingSocketProvider,
        connect_tls_psk_tunnel_native,
    },
    rsd::RsdHandshake,
    tcp::{adapter::Adapter, handle::AdapterHandle},
};
use mdns_sd::{ServiceDaemon, ServiceEvent};
use tauri::{AppHandle, Manager};
use tokio::net::TcpStream;
use tracing::{info, warn};

use crate::{device::DeviceInfo, error::AppError};

const REMOTE_PAIRING_SERVICE: &str = "_remotepairing._tcp.local.";
const REMOTE_PAIRING_HOST: &str = "iloader";
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(3);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug)]
struct RemotePairingLockdownServiceCompat {
    idevice: Idevice,
}

impl IdeviceService for RemotePairingLockdownServiceCompat {
    fn service_name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("com.apple.dt.remotepairingdeviced.lockdown")
    }

    async fn from_stream(idevice: Idevice) -> Result<Self, IdeviceError> {
        Ok(Self { idevice })
    }
}

fn remote_error(context: &str, error: impl std::fmt::Display) -> AppError {
    AppError::RemotePairing(format!("{context}: {error}"))
}

/// Folder with one empty `<udid>.known` marker per phone set up for Wi-Fi. It holds
/// no secrets; the pairing record itself lives in the protected pairing storage.
fn remote_pairing_dir(app: &AppHandle) -> Result<PathBuf, AppError> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| {
            AppError::Filesystem(
                "Failed to get app data directory for RemotePairing".into(),
                e.to_string(),
            )
        })?
        .join("remote-pairing");

    std::fs::create_dir_all(&dir).map_err(|e| {
        AppError::Filesystem(
            "Failed to create RemotePairing directory".into(),
            e.to_string(),
        )
    })?;

    Ok(dir)
}

fn wifi_pairing_key(udid: &str) -> String {
    format!("wifi_rppairing_{udid}")
}

/// The saved Wi-Fi RemotePairing record, if this phone was set up over USB.
pub(crate) fn load_wifi_pairing(
    app: &AppHandle,
    udid: &str,
) -> Result<Option<RpPairingFile>, AppError> {
    let bytes = crate::pairing::with_pairing_storage(app, |storage| {
        storage.retrieve_data(&wifi_pairing_key(udid)).map_err(|e| {
            AppError::Storage("Failed to read saved Wi-Fi pairing".into(), e.to_string())
        })
    })?;
    match bytes {
        // Deleting a storage entry leaves an empty value behind.
        Some(bytes) if !bytes.is_empty() => RpPairingFile::from_bytes(&bytes)
            .map(Some)
            .map_err(|e| remote_error("Saved Wi-Fi pairing is unreadable", e)),
        _ => Ok(None),
    }
}

fn save_wifi_pairing(app: &AppHandle, udid: &str, pairing: &RpPairingFile) -> Result<(), AppError> {
    crate::pairing::with_pairing_storage(app, |storage| {
        storage
            .store_data(&wifi_pairing_key(udid), &pairing.to_bytes())
            .map_err(|e| AppError::Storage("Failed to save Wi-Fi pairing".into(), e.to_string()))
    })?;
    std::fs::write(remote_pairing_dir(app)?.join(format!("{udid}.known")), b"").map_err(|e| {
        AppError::Filesystem("Failed to record Wi-Fi setup".into(), e.to_string())
    })
}

/// Removes the saved Wi-Fi pairing and its discovery marker.
pub(crate) fn forget_wifi_pairing(app: &AppHandle, udid: &str) -> Result<(), AppError> {
    crate::pairing::with_pairing_storage(app, |storage| {
        storage.delete(&wifi_pairing_key(udid)).map_err(|e| {
            AppError::Storage("Failed to delete saved Wi-Fi pairing".into(), e.to_string())
        })
    })?;
    let marker = remote_pairing_dir(app)?.join(format!("{udid}.known"));
    match std::fs::remove_file(&marker) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(AppError::Filesystem(
            "Failed to remove Wi-Fi setup record".into(),
            e.to_string(),
        )),
        _ => Ok(()),
    }
}

pub fn known_remote_pairing_udids(app: &AppHandle) -> Result<Vec<String>, AppError> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| {
            AppError::Filesystem(
                "Failed to get app data directory for RemotePairing discovery".into(),
                e.to_string(),
            )
        })?
        .join("remote-pairing");

    known_remote_pairing_udids_in(&dir)
}

pub fn known_remote_pairing_udids_in(dir: &Path) -> Result<Vec<String>, AppError> {
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let entries = std::fs::read_dir(&dir).map_err(|e| {
        AppError::Filesystem(
            "Failed to read RemotePairing directory".into(),
            e.to_string(),
        )
    })?;

    let mut udids = Vec::new();

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                warn!("Ignoring unreadable RemotePairing directory entry: {e}");
                continue;
            }
        };

        let path = entry.path();

        if path.extension().and_then(|value| value.to_str()) != Some("known") {
            continue;
        }

        if let Some(udid) = path.file_stem().and_then(|value| value.to_str())
            && !udid.is_empty()
        {
            udids.push(udid.to_string());
        }
    }

    Ok(udids)
}
async fn connect_tcp(address: Ipv4Addr, port: u16, context: &str) -> Result<TcpStream, AppError> {
    tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((address, port)))
        .await
        .map_err(|e| remote_error(&format!("{context} timed out"), e))?
        .map_err(|e| remote_error(context, e))
}

async fn discover_remote_pairing_port(target: Ipv4Addr) -> Result<u16, AppError> {
    let mdns = ServiceDaemon::new()
        .map_err(|e| remote_error("Failed to start RemotePairing mDNS discovery", e))?;

    let receiver = mdns
        .browse(REMOTE_PAIRING_SERVICE)
        .map_err(|e| remote_error("Failed to browse RemotePairing service", e))?;

    let deadline = tokio::time::Instant::now() + DISCOVERY_TIMEOUT;
    let mut found = None;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        match tokio::time::timeout(remaining, receiver.recv_async()).await {
            Ok(Ok(ServiceEvent::ServiceResolved(service))) => {
                let matches = service
                    .get_addresses_v4()
                    .into_iter()
                    .any(|candidate| candidate == target);

                if matches {
                    found = Some(service.get_port());
                    break;
                }
            }
            Ok(Ok(_)) => {}
            Ok(Err(_)) | Err(_) => break,
        }
    }

    let _ = mdns.stop_browse(REMOTE_PAIRING_SERVICE);
    let _ = mdns.shutdown();

    found.ok_or_else(|| {
        AppError::RemotePairing(format!(
            "No _remotepairing._tcp service found for Wi-Fi device {target}"
        ))
    })
}

pub async fn bootstrap_remote_pairing(
    app: &AppHandle,
    device: &DeviceInfo,
    provider: &impl IdeviceProvider,
) -> Result<(), AppError> {
    if device.connection_type != "USB" {
        return Ok(());
    }

    let mut pairing = match load_wifi_pairing(app, &device.udid)? {
        Some(pairing) => pairing,
        None => RpPairingFile::generate(REMOTE_PAIRING_HOST),
    };

    let service = RemotePairingLockdownServiceCompat::connect(provider)
        .await
        .map_err(|e| remote_error("Failed to open USB RemotePairing control service", e))?;

    let socket = service.idevice.get_socket().ok_or_else(|| {
        AppError::RemotePairing("USB RemotePairing service returned no socket".into())
    })?;

    let mut client = RemotePairingClient::new(RpPairingSocket::new(socket), REMOTE_PAIRING_HOST);

    client
        .connect(&mut pairing, || async { "000000".to_string() })
        .await
        .map_err(|e| remote_error("Failed to bootstrap RemotePairing over USB", e))?;

    save_wifi_pairing(app, &device.udid, &pairing)?;

    info!("RemotePairing identity prepared for the selected device");

    Ok(())
}

pub async fn open_rsd_tunnel(
    app: &AppHandle,
    device: &DeviceInfo,
) -> Result<(AdapterHandle, RsdHandshake), AppError> {
    let network_address = device.network_address.as_deref().ok_or_else(|| {
        AppError::RemotePairing("Selected network device has no Wi-Fi address".into())
    })?;

    let address = network_address.parse::<Ipv4Addr>().map_err(|e| {
        AppError::RemotePairing(format!(
            "Invalid RemotePairing IPv4 address {network_address}: {e}"
        ))
    })?;

    let mut pairing = load_wifi_pairing(app, &device.udid)?.ok_or_else(|| {
        AppError::RemotePairing(
            "This phone is not set up for Wi-Fi yet. Connect it by USB and choose Set up Wi-Fi."
                .into(),
        )
    })?;

    let pairing_port = discover_remote_pairing_port(address).await?;
    info!("Opening RemotePairing transport");

    let pairing_stream = connect_tcp(
        address,
        pairing_port,
        "Failed to connect to RemotePairing service",
    )
    .await?;

    let pairing_socket = RpPairingSocket::new(pairing_stream);
    let mut client = RemotePairingClient::new(pairing_socket, REMOTE_PAIRING_HOST);

    client
        .attempt_pair_verify()
        .await
        .map_err(|e| remote_error("RemotePairing handshake failed", e))?;

    client.validate_pairing(&mut pairing).await.map_err(|e| {
        remote_error(
            "RemotePairing pair-verify failed; reconnect the iPhone over USB once",
            e,
        )
    })?;

    Box::pin(finish_rsd_tunnel(&mut client, address)).await
}

async fn finish_rsd_tunnel<R: RpPairingSocketProvider>(
    client: &mut RemotePairingClient<R>,
    address: Ipv4Addr,
) -> Result<(AdapterHandle, RsdHandshake), AppError> {
    let tunnel_port = client
        .create_tcp_listener()
        .await
        .map_err(|e| remote_error("Failed to create RemotePairing TCP tunnel listener", e))?;

    let tunnel_stream = connect_tcp(
        address,
        tunnel_port,
        "Failed to connect to RemotePairing tunnel",
    )
    .await?;

    let tunnel = connect_tls_psk_tunnel_native(tunnel_stream, client.encryption_key())
        .await
        .map_err(|e| remote_error("TLS-PSK/CDTunnel handshake failed", e))?;

    let client_ip = tunnel
        .info
        .client_address
        .parse::<IpAddr>()
        .map_err(|e| remote_error("Invalid CDTunnel client address", e))?;

    let server_ip = tunnel
        .info
        .server_address
        .parse::<IpAddr>()
        .map_err(|e| remote_error("Invalid CDTunnel server address", e))?;

    let rsd_port = tunnel.info.server_rsd_port;
    let mtu = tunnel.info.mtu as usize;

    info!("RemotePairing CDTunnel established");

    let raw = tunnel.into_inner();
    let mut adapter = Adapter::new(Box::new(raw), client_ip, server_ip);
    adapter.set_mss(mtu.saturating_sub(60));

    let mut provider = adapter.to_async_handle();

    let rsd_stream = provider
        .connect(rsd_port)
        .await
        .map_err(|e| remote_error("Failed to connect to RSD through userspace tunnel", e))?;

    let handshake = RsdHandshake::new(rsd_stream)
        .await
        .map_err(|e| remote_error("RSD handshake failed", e))?;

    info!("RSD ready with {} services", handshake.services.len());

    Ok((provider, handshake))
}
