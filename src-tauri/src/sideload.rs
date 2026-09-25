use std::{path::PathBuf, sync::Mutex};

use crate::{
    device::{DeviceInfoMutex, get_provider, get_provider_from_connection, get_usbmuxd},
    error::AppError,
    install_lock::InstallLease,
    manual_wifi::{self, Route},
    manual_signing::{self, Stage as SigningStage},
    operation::Operation,
    pairing::{get_sidestore_info, place_file},
    renewal_report::{RenewalProblem, RenewalReport, StepResult},
    wifi_rsd::open_rsd_tunnel,
};
use idevice::provider::IdeviceProvider;
use isideload::{
    dev::{device_type::DeveloperDeviceType, devices::DevicesApi},
    sideload::{
        application::SpecialApp,
        bundle::Bundle,
        install::install_app_rsd,
        sideloader::Sideloader,
        watch_install::{install_watch_apps_rsd, register_paired_watches_rsd},
    },
};
use tauri::{AppHandle, Manager, State, Window};
use tracing::{info, warn};

pub type SideloaderMutex = Mutex<Option<Sideloader>>;

pub struct SideloaderGuard<'a> {
    state: &'a SideloaderMutex,
    sideloader: Option<Sideloader>,
    restore_interactive_policy: bool,
}

impl<'a> SideloaderGuard<'a> {
    pub fn take(state: &'a SideloaderMutex) -> Result<Self, AppError> {
        let mut guard = state.lock().unwrap();
        let sideloader = guard.take().ok_or(AppError::NotLoggedIn)?;
        Ok(Self {
            state,
            sideloader: Some(sideloader),
            restore_interactive_policy: false,
        })
    }

    pub fn get_mut(&mut self) -> &mut Sideloader {
        self.sideloader
            .as_mut()
            .expect("Sideloader should be present")
    }

    pub(crate) fn require_existing_certificate(&mut self) -> Result<(), AppError> {
        use isideload::sideload::builder::CertificatePolicy;
        self.sideloader = self
            .sideloader
            .take()
            .map(|s| s.with_certificate_policy(CertificatePolicy::ReuseExistingOnly));
        // account.rs constructs this interactive session with the default
        // policy. Restore it on every exit, including signing failure.
        self.restore_interactive_policy = true;
        Ok(())
    }
}

impl Drop for SideloaderGuard<'_> {
    fn drop(&mut self) {
        if self.restore_interactive_policy {
            self.sideloader = self.sideloader.take().map(|s| {
                s.with_certificate_policy(
                        isideload::sideload::builder::CertificatePolicy::default(),
                    )
            });
        }
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
    sideload_with_report(
        handle,
        device_state,
        sideloader_state,
        app_path,
        false,
        &mut RenewalReport::default(),
    )
    .await
}

/// Explicit manual Wi-Fi renewal. A failed device step is returned in the report
/// so an iPhone success is not lost when the Watch fails afterwards.
#[tauri::command]
pub async fn renew_wifi(
    handle: AppHandle,
    device_state: State<'_, DeviceInfoMutex>,
    sideloader_state: State<'_, SideloaderMutex>,
    app_path: String,
) -> Result<RenewalReport, AppError> {
    let mut report = RenewalReport::default();
    if let Err(error) = Box::pin(sideload_with_report(
        &handle,
        device_state,
        sideloader_state,
        app_path,
        true,
        &mut report,
    ))
    .await
    {
        report.record_error(error);
    }
    report.completed_at = Some(chrono::Utc::now().timestamp());
    Ok(report)
}

async fn sideload_with_report(
    handle: &AppHandle,
    device_state: State<'_, DeviceInfoMutex>,
    sideloader_state: State<'_, SideloaderMutex>,
    app_path: String,
    wifi_only: bool,
    report: &mut RenewalReport,
) -> Result<Option<SpecialApp>, AppError> {
    let directory = handle
        .path()
        .app_data_dir()
        .map_err(|e| AppError::Misc(e.to_string()))?;
    let _lease = InstallLease::acquire(&directory).inspect_err(|_| {
        report.problem = Some(RenewalProblem::Busy);
    })?;
    let device = {
        let device_lock = device_state.lock().unwrap();
        match &*device_lock {
            Some(d) => d.clone(),
            None => return Err(AppError::NoDeviceSelected),
        }
    };

    if wifi_only {
        if device.info.connection_type != "Network" {
            report.problem = Some(RenewalProblem::WifiRequired);
            return Err(AppError::Misc(
                "Select the phone's Wi-Fi connection.".into(),
            ));
        }
        if !std::path::Path::new(&app_path).is_file() {
            report.problem = Some(RenewalProblem::LocalFiles);
            return Err(AppError::Misc(
                "Original IPA is missing or unreadable".into(),
            ));
        }
    }

    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;

    if device.info.connection_type == "Network" {
        // Snapshot the chosen original before routing/signing so replacing the
        // source path cannot introduce or remove Watch content mid-operation.
        let original = manual_wifi::Original::retain(std::path::Path::new(&app_path), &directory)?;
        let mut connection = manual_wifi::CheckReport::default();
        let transport_result = manual_wifi::route(
            original.has_watch(),
            || async {
                manual_wifi::phone_services(&device.info, &mut connection)
                    .await
                    .map_err(|_| {
                        AppError::RemotePairing(
                            "Phone Wi-Fi service check failed; see the connection stage.".into(),
                        )
                    })
            },
            || async {
                tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    open_rsd_tunnel(handle, &device.info),
                )
                .await
                .map_err(|_| {
                    AppError::RemotePairing("Watch transport connection timed out".into())
                })?
            },
        )
        .await;
        if original.has_watch() {
            connection.transport = Some("remotePairingRsd");
            connection.connected = transport_result.is_ok();
            connection.stage = manual_wifi::Stage::WatchTransport;
            connection.problem = transport_result
                .as_ref()
                .err()
                .map(|_| manual_wifi::Problem::WatchTransportUnavailable);
        }
        report.connection = Some(connection);
        let mut transport = transport_result?;
        report.wifi_connected = true;
        report.signing = StepResult::Failed;
        sideloader.require_existing_certificate().map_err(|_| {
            AppError::ManualSigning(manual_signing::Detail::policy_unavailable())
        })?;

        let team = manual_signing::result(SigningStage::TeamLookup,
            sideloader.get_mut().get_team().await)?;

        manual_signing::result(SigningStage::DeviceRegistration, sideloader
            .get_mut()
            .get_dev_session()
            .ensure_device_registered(
                &team,
                &device.info.name,
                &device.info.udid,
                None::<DeveloperDeviceType>,
            )
            .await)?;

        // Like the USB path: a Watch app can only be signed for Watches that are
        // registered with the team, so register the phone's paired Watches too.
        if original.has_watch() {
            let Route::Watch((rsd_provider, handshake)) = &mut transport else {
                return Err(AppError::Misc(
                    "Watch content cannot use the phone-only transport.".into(),
                ));
            };
            let watches = manual_signing::result(
                SigningStage::DeviceRegistration,
                register_paired_watches_rsd(
                    rsd_provider,
                    handshake,
                    sideloader.get_mut().get_dev_session(),
                    &team,
                )
                .await,
            )?;
            info!("Registered {watches} paired Apple Watch device(s) over Wi-Fi");
        }

        let (signed_app_path, special) = manual_signing::result(SigningStage::SignApp, sideloader
            .get_mut()
            .sign_app(
                original.path(),
                Some(team),
                false,
                None::<fn(f32) -> std::future::Ready<()>>,
            )
            .await)?;
        report.signing = StepResult::Signed;

        // Keep cleanup around every post-signing error, including iPhone failure.
        let install_result: Result<(), AppError> = async {
            let signed_bundle = Bundle::new(signed_app_path.clone())?;
            manual_wifi::install_checked(
                original.has_watch(),
                !signed_bundle.watch_apps().is_empty(),
                || async {
            report.record_profiles(&signed_bundle);
            let watch_apps = signed_bundle.watch_apps().to_vec();
            report.iphone = StepResult::Failed;
            match &mut transport {
                Route::Phone(phone) => {
                    crate::manual_install::install(&phone.provider, &signed_app_path)
                    .await?;
                }
                Route::Watch((rsd_provider, handshake)) => {
                    install_app_rsd(rsd_provider, handshake, &signed_app_path, |progress| {
                        info!("Installing over RSD: {}%", progress)
                    })
                    .await?;
                }
            }
            report.iphone = StepResult::Installed;
            if !watch_apps.is_empty() {
                let Route::Watch((rsd_provider, handshake)) = &mut transport else {
                    return Err(AppError::Misc(
                        "Watch content cannot use the phone-only transport.".into(),
                    ));
                };
                report.watch = StepResult::Failed;
                info!("Installing Apple Watch companion app through the existing RSD tunnel...");

                let watch_provider = get_provider(&device.info).await?;
                let iphone_pairing = watch_provider.get_pairing_file().await.map_err(|e| {
                    AppError::LockdownPairing(
                        "Failed to get pairing record for Apple Watch RSD install".into(),
                        e.to_string(),
                    )
                })?;

                info!("Using RSD-native CompanionProxy for Apple Watch install");
                install_watch_apps_rsd(
                    rsd_provider,
                    handshake,
                    &iphone_pairing,
                    &watch_apps,
                    "iloader",
                    |progress| {
                        info!("Installing Apple Watch app over RSD: {}%", progress);
                    },
                )
                .await?;
                report.watch = StepResult::Installed;
            }

            Ok(())
                },
            ).await
        }
        .await;

        if let Err(e) = tokio::fs::remove_dir_all(&signed_app_path).await {
            warn!(
                "Failed to remove temporary RSD-signed app directory {}: {}",
                signed_app_path.display(),
                e
            );
        }

        install_result?;
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
    // Keep the large signing/install future out of Tauri's main-thread command frame.
    Box::pin(install_sidestore_operation_impl(
        handle,
        window,
        device_state,
        sideloader_state,
        nightly,
        live_container,
    ))
    .await
}

async fn install_sidestore_operation_impl(
    handle: AppHandle,
    window: Window,
    device_state: State<'_, DeviceInfoMutex>,
    sideloader_state: State<'_, SideloaderMutex>,
    nightly: bool,
    live_container: bool,
) -> Result<(), AppError> {
    // This operation retains an export pairing across install and app placement.
    // A USB repair must not replace that identity in between the two steps.
    let operation = handle.state::<crate::wifi_pairing::PairingOperation>();
    let _operation = operation
        .try_lock()
        .map_err(|_| AppError::Misc("Device setup is busy. Wait for it to finish.".into()))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sidestore_future_size<F, Fut>(_: F) -> usize
    where
        F: FnOnce(
            AppHandle,
            Window,
            State<'static, DeviceInfoMutex>,
            State<'static, SideloaderMutex>,
            bool,
            bool,
        ) -> Fut,
    {
        std::mem::size_of::<Fut>()
    }

    #[test]
    fn sidestore_command_future_fits_main_thread_stack() {
        // Measure the actual command future without a device, account, or network call.
        let command = sidestore_future_size(install_sidestore_operation);
        let implementation = sidestore_future_size(install_sidestore_operation_impl);
        println!(
            "SideStore command future: {command} bytes; unboxed implementation: {implementation} bytes"
        );
        assert!(
            command <= 16 * 1024,
            "SideStore command future is {command} bytes; keep nested install work boxed"
        );
    }
}
