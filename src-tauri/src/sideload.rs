use std::{path::PathBuf, sync::Mutex};

use crate::{
    device::{DeviceInfoMutex, get_provider, get_provider_from_connection, get_usbmuxd},
    error::AppError,
    operation::Operation,
    pairing::{get_sidestore_info, place_file},
    wifi_rsd::open_rsd_tunnel,
};
use idevice::provider::IdeviceProvider;
use isideload::{
    dev::{device_type::DeveloperDeviceType, devices::DevicesApi},
    sideload::{
        application::SpecialApp, bundle::Bundle, install::install_app_rsd, sideloader::Sideloader,
        watch_install::install_watch_apps_rsd,
    },
};
use tauri::{AppHandle, Manager, State, Window};
use tracing::{info, warn};

pub type SideloaderMutex = Mutex<Option<Sideloader>>;

pub struct SideloaderGuard<'a> {
    state: &'a SideloaderMutex,
    sideloader: Option<Sideloader>,
}

impl<'a> SideloaderGuard<'a> {
    pub fn take(state: &'a SideloaderMutex) -> Result<Self, AppError> {
        let mut guard = state.lock().unwrap();
        let sideloader = guard.take().ok_or(AppError::NotLoggedIn)?;
        Ok(Self {
            state,
            sideloader: Some(sideloader),
        })
    }

    pub fn get_mut(&mut self) -> &mut Sideloader {
        self.sideloader
            .as_mut()
            .expect("Sideloader should be present")
    }
}

impl Drop for SideloaderGuard<'_> {
    fn drop(&mut self) {
        let mut guard = self.state.lock().unwrap();
        *guard = self.sideloader.take();
    }
}

pub async fn sideload(
    handle: &AppHandle,
    device_state: State<'_, DeviceInfoMutex>,
    sideloader_state: State<'_, SideloaderMutex>,
    app_path: String,
) -> Result<Option<SpecialApp>, AppError> {
    let device = {
        let device_lock = device_state.lock().unwrap();
        match &*device_lock {
            Some(d) => d.clone(),
            None => return Err(AppError::NoDeviceSelected),
        }
    };

    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;

    if device.info.connection_type == "Network" && device.info.network_address.is_some() {
        info!("Installing {} over RemotePairing/RSD", device.info.udid);

        let (mut rsd_provider, mut handshake) = open_rsd_tunnel(handle, &device.info).await?;

        let team = sideloader.get_mut().get_team().await?;

        sideloader
            .get_mut()
            .get_dev_session()
            .ensure_device_registered(
                &team,
                &device.info.name,
                &device.info.udid,
                None::<DeveloperDeviceType>,
            )
            .await?;

        let (signed_app_path, special) = sideloader
            .get_mut()
            .sign_app(
                app_path.clone().into(),
                Some(team),
                false,
                None::<fn(f32) -> std::future::Ready<()>>,
            )
            .await?;

        install_app_rsd(
            &mut rsd_provider,
            &mut handshake,
            &signed_app_path,
            |progress| {
                info!("Installing over RSD: {}%", progress);
            },
        )
        .await?;

        let signed_bundle = Bundle::new(signed_app_path.clone())?;
        let watch_apps = signed_bundle.watch_apps().to_vec();

        let watch_result: Result<(), AppError> = async {
            if !watch_apps.is_empty() {
                info!("Installing Apple Watch companion app through the existing RSD tunnel...");

                let watch_provider = get_provider(&device.info).await?;
                let iphone_pairing = watch_provider.get_pairing_file().await.map_err(|e| {
                    AppError::LockdownPairing(
                        "Failed to get pairing record for Apple Watch RSD install".into(),
                        e.to_string(),
                    )
                })?;

                install_watch_apps_rsd(
                    &mut rsd_provider,
                    &mut handshake,
                    &iphone_pairing,
                    &watch_apps,
                    "iloader",
                    |progress| {
                        info!("Installing Apple Watch app over RSD: {}%", progress);
                    },
                )
                .await?;
            }

            Ok(())
        }
        .await;

        if let Err(e) = tokio::fs::remove_dir_all(&signed_app_path).await {
            warn!(
                "Failed to remove temporary RSD-signed app directory {}: {}",
                signed_app_path.display(),
                e
            );
        }

        watch_result?;
        return Ok(special);
    }

    let provider = get_provider(&device.info).await?;

    let special = sideloader
        .get_mut()
        .install_app(
            &provider,
            app_path.into(),
            false,
            None::<fn(f32) -> std::future::Ready<()>>,
        )
        .await?;

    Ok(special)
}

#[tauri::command]
pub async fn sideload_operation(
    window: Window,
    device_state: State<'_, DeviceInfoMutex>,
    sideloader_state: State<'_, SideloaderMutex>,
    app_path: String,
) -> Result<(), AppError> {
    Box::pin(sideload_operation_impl(
        window,
        device_state,
        sideloader_state,
        app_path,
    ))
    .await
}

async fn sideload_operation_impl(
    window: Window,
    device_state: State<'_, DeviceInfoMutex>,
    sideloader_state: State<'_, SideloaderMutex>,
    app_path: String,
) -> Result<(), AppError> {
    let op = Operation::new("sideload".to_string(), &window);
    op.start("install")?;
    op.fail_if_err(
        "install",
        sideload(
            window.app_handle(),
            device_state,
            sideloader_state,
            app_path,
        )
        .await,
    )?;
    op.complete("install")?;
    Ok(())
}

#[tauri::command]
pub async fn install_sidestore_operation(
    handle: AppHandle,
    window: Window,
    device_state: State<'_, DeviceInfoMutex>,
    sideloader_state: State<'_, SideloaderMutex>,
    nightly: bool,
    live_container: bool,
) -> Result<(), AppError> {
    let op = Operation::new("install_sidestore".to_string(), &window);
    op.start("download")?;
    // TODO: Cache & check version to avoid re-downloading
    let (filename, url) = if live_container {
        if nightly {
            (
                "LiveContainerSideStore-Nightly.ipa",
                "https://github.com/LiveContainer/LiveContainer/releases/download/nightly/LiveContainer+SideStore.ipa",
            )
        } else {
            (
                "LiveContainerSideStore.ipa",
                "https://github.com/LiveContainer/LiveContainer/releases/latest/download/LiveContainer+SideStore.ipa",
            )
        }
    } else if nightly {
        (
            "SideStore-Nightly.ipa",
            "https://github.com/SideStore/SideStore/releases/download/nightly/SideStore.ipa",
        )
    } else {
        (
            "SideStore.ipa",
            "https://github.com/SideStore/SideStore/releases/latest/download/SideStore.ipa",
        )
    };

    let dest = handle
        .path()
        .temp_dir()
        .map_err(|e| AppError::Filesystem("Failed to get temp dir".into(), e.to_string()))?
        .join(filename);
    op.fail_if_err("download", download(url, &dest).await)?;
    op.move_on("download", "install")?;
    let device = {
        let device_guard = device_state.lock().unwrap();
        match &*device_guard {
            Some(d) => d.clone(),
            None => return op.fail("install", AppError::NoDeviceSelected),
        }
    };
    op.fail_if_err(
        "install",
        sideload(
            &handle,
            device_state,
            sideloader_state,
            dest.to_string_lossy().to_string(),
        )
        .await,
    )?;
    op.move_on("install", "pairing")?;
    let sidestore_info = op.fail_if_err(
        "pairing",
        get_sidestore_info(&device.info, live_container).await,
    )?;
    if let Some(info) = sidestore_info {
        let mut usbmuxd = op.fail_if_err("pairing", get_usbmuxd().await)?;

        let provider = op.fail_if_err(
            "pairing",
            get_provider_from_connection(&device.info, &mut usbmuxd).await,
        )?;

        op.fail_if_err(
            "pairing",
            place_file(device.pairing, &provider, info.bundle_id, info.path).await,
        )?;
    } else {
        return op.fail(
            "pairing",
            AppError::HouseArrest(
                "SideStore's not found".into(),
                "The device did not report SideStore's bundle ID as installed".into(),
            ),
        );
    }

    op.complete("pairing")?;
    Ok(())
}

pub async fn download(url: impl AsRef<str>, dest: &PathBuf) -> Result<(), AppError> {
    let response = reqwest::get(url.as_ref())
        .await
        .map_err(|e| AppError::Download(e.to_string()))?;
    if !response.status().is_success() {
        return Err(AppError::Download(format!(
            "Failed to download file: HTTP {}",
            response.status()
        )));
    }

    let bytes = response
        .bytes()
        .await
        .map_err(|e| AppError::Download(e.to_string()))?;
    tokio::fs::write(dest, &bytes).await.map_err(|e| {
        AppError::Filesystem("Failed to write downloaded file".into(), e.to_string())
    })?;

    Ok(())
}
