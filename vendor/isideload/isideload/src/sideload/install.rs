use idevice::{
    IdeviceService, RsdService,
    afc::AfcClient,
    installation_proxy::InstallationProxyClient,
    provider::{IdeviceProvider, RsdProvider},
    rsd::RsdHandshake,
};
use plist_macro::plist;
use rootcause::option_ext::OptionExt;
use rootcause::prelude::*;

use crate::SideloadError as Error;
use std::pin::Pin;
use std::{future::Future, path::Path};

const AFC_UPLOAD_CHUNK_SIZE: usize = if cfg!(target_arch = "wasm32") {
    8 * 1024
} else {
    1024 * 1024
};

/// Fixed phase markers; no paths or device information. The observer is passive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum InstallationStage {
    #[error("AFC service connection")]
    AfcConnect,
    #[error("Local staging preparation")]
    LocalPreparation,
    #[error("AFC bundle upload")]
    Upload,
    #[error("Installation proxy service connection")]
    ProxyConnect,
    #[error("Installation proxy Install request and completion")]
    ProxyInstall,
    #[error("Installation proxy confirmed completion")]
    Complete,
}

/// Installs an ***already signed*** app onto your device.
/// To sign and install an app, see [`crate::sideload::sideload_app`]
pub async fn install_app(
    provider: &impl IdeviceProvider,
    app_path: &Path,
    progress_callback: impl Fn(u64) + Send + Sync,
) -> Result<(), Report> {
    install_app_observed(provider, app_path, progress_callback, |_| {}).await
}

/// Same installer and protocol as install_app, with passive phase observation
/// and typed phase contexts on failures. No retry or alternate transport.
pub async fn install_app_observed(
    provider: &impl IdeviceProvider,
    app_path: &Path,
    progress_callback: impl Fn(u64) + Send + Sync,
    stage: impl Fn(InstallationStage) + Send + Sync,
) -> Result<(), Report> {
    stage(InstallationStage::AfcConnect);
    let mut afc_client = AfcClient::connect(provider)
        .await
        .map_err(Error::IdeviceError)
        .context(InstallationStage::AfcConnect)?;

    stage(InstallationStage::LocalPreparation);
    let dir = format!(
        "PublicStaging/{}",
        app_path
            .file_name()
            .ok_or_report()
            .context(InstallationStage::LocalPreparation)?
            .to_string_lossy()
    );
    let total_size = get_dir_size(app_path).unwrap_or(1) as f64;
    let mut uploaded = 0;
    let cb = |progress: f64| {
        progress_callback((progress * 70.0) as u64);
    };
    stage(InstallationStage::Upload);
    afc_upload_dir(
        &mut afc_client,
        app_path,
        &dir,
        &cb,
        &mut uploaded,
        total_size,
    )
    .await
    .context(InstallationStage::Upload)?;

    stage(InstallationStage::ProxyConnect);
    let mut instproxy_client = InstallationProxyClient::connect(provider)
        .await
        .map_err(Error::IdeviceError)
        .context(InstallationStage::ProxyConnect)?;

    let options = plist!(dict {
        "PackageType": "Developer"
    });

    stage(InstallationStage::ProxyInstall);
    instproxy_client
        .install_with_callback(
            dir,
            Some(plist::Value::Dictionary(options)),
            async |(percentage, _)| {
                progress_callback((70.0 + 0.3 * percentage as f64) as u64);
            },
            (),
        )
        .await
        .map_err(Error::IdeviceError)
        .context(InstallationStage::ProxyInstall)?;

    stage(InstallationStage::Complete);
    Ok(())
}

/// Installs an ***already signed*** app onto your device.
/// To sign and install an app, see [`crate::sideload::sideload_app`]
pub async fn install_app_rsd(
    provider: &mut impl RsdProvider,
    handshake: &mut RsdHandshake,
    app_path: &Path,
    progress_callback: impl Fn(u64) + Send + Sync,
) -> Result<(), Report> {
    let mut afc_client = AfcClient::connect_rsd(provider, handshake)
        .await
        .map_err(Error::IdeviceError)?;

    let dir = format!(
        "PublicStaging/{}",
        app_path.file_name().ok_or_report()?.to_string_lossy()
    );
    let total_size = get_dir_size(app_path).unwrap_or(1) as f64;
    let mut uploaded = 0;
    let cb = |pct: f64| {
        progress_callback((pct * 70.0) as u64);
    };
    afc_upload_dir(
        &mut afc_client,
        app_path,
        &dir,
        &cb,
        &mut uploaded,
        total_size,
    )
    .await?;

    let mut instproxy_client = InstallationProxyClient::connect_rsd(provider, handshake)
        .await
        .map_err(Error::IdeviceError)?;

    let options = plist!(dict {
        "PackageType": "Developer"
    });

    instproxy_client
        .install_with_callback(
            dir,
            Some(plist::Value::Dictionary(options)),
            async |(percentage, _)| {
                progress_callback((70.0 + 0.3 * percentage as f64) as u64);
            },
            (),
        )
        .await
        .map_err(Error::IdeviceError)?;

    Ok(())
}

fn get_dir_size(path: &Path) -> Result<u64, Report> {
    let mut size = 0;
    for entry in isideload_vfs::fs::read_dir(path)? {
        let entry = entry?;
        let path = entry.path();
        let meta = isideload_vfs::fs::metadata(&path)?;
        if meta.is_dir() {
            size += get_dir_size(&path)?;
        } else {
            size += meta.len();
        }
    }
    Ok(size)
}

fn afc_upload_dir<'a>(
    afc_client: &'a mut AfcClient,
    path: &'a Path,
    afc_path: &'a str,
    cb: &'a (dyn Fn(f64) + Send + Sync),
    uploaded: &'a mut u64,
    total: f64,
) -> Pin<Box<dyn Future<Output = Result<(), Report>> + Send + 'a>> {
    Box::pin(async move {
        let entries = isideload_vfs::fs::read_dir(path)?;
        afc_client
            .mk_dir(afc_path)
            .await
            .map_err(Error::IdeviceError)?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if isideload_vfs::fs::metadata(&path)?.is_dir() {
                let new_afc_path = format!(
                    "{}/{}",
                    afc_path,
                    path.file_name().ok_or_report()?.to_string_lossy()
                );
                afc_upload_dir(afc_client, &path, &new_afc_path, cb, uploaded, total).await?;
            } else {
                let mut file_handle = afc_client
                    .open(
                        format!(
                            "{}/{}",
                            afc_path,
                            path.file_name().ok_or_report()?.to_string_lossy()
                        ),
                        idevice::afc::opcode::AfcFopenMode::WrOnly,
                    )
                    .await
                    .map_err(Error::IdeviceError)?;

                let bytes = isideload_vfs::fs::read(&path)?;
                for chunk in bytes.chunks(AFC_UPLOAD_CHUNK_SIZE) {
                    file_handle
                        .write_entire(chunk)
                        .await
                        .map_err(Error::IdeviceError)?;
                    *uploaded += chunk.len() as u64;
                    cb(*uploaded as f64 / total);
                }
                file_handle.close().await.map_err(Error::IdeviceError)?;
            }
        }
        Ok(())
    })
}

#[cfg(all(test, not(feature = "wasm")))]
mod diagnostic_tests {
    use super::*;
    use idevice::{Idevice, IdeviceError, pairing_file::PairingFile};
    use std::sync::Mutex;

    #[derive(Debug)]
    struct UnavailableProvider;
    impl IdeviceProvider for UnavailableProvider {
        fn connect(
            &self,
            _: u16,
        ) -> Pin<Box<dyn Future<Output = Result<Idevice, IdeviceError>> + Send>> {
            Box::pin(async { Err(IdeviceError::DeviceLocked) })
        }
        fn get_pairing_file(
            &self,
        ) -> Pin<Box<dyn Future<Output = Result<PairingFile, IdeviceError>> + Send>> {
            panic!("No pairing access expected after failed service connection")
        }
        fn label(&self) -> &str {
            "synthetic"
        }
    }
    #[tokio::test]
    async fn shared_installer_observes_failure_phase_without_progress_retry_or_new_transport() {
        let stages = Mutex::new(vec![]);
        let failure = install_app_observed(
            &UnavailableProvider,
            Path::new("not-read.app"),
            |_| panic!("No upload expected"),
            |phase| stages.lock().unwrap().push(phase),
        )
        .await
        .unwrap_err();
        assert_eq!(*stages.lock().unwrap(), [InstallationStage::AfcConnect]);
        assert!(
            failure
                .iter_reports()
                .any(|r| r.downcast_current_context::<InstallationStage>()
                    == Some(&InstallationStage::AfcConnect))
        );
        assert!(failure.iter_reports().any(|r| matches!(
            r.downcast_current_context::<Error>(),
            Some(Error::IdeviceError(IdeviceError::DeviceLocked))
        )));
        // The original public API delegates to the same implementation.
        let ordinary = install_app(&UnavailableProvider, Path::new("not-read.app"), |_| {
            panic!("No upload expected")
        })
        .await
        .unwrap_err();
        assert!(
            ordinary
                .iter_reports()
                .any(|r| r.downcast_current_context::<InstallationStage>()
                    == Some(&InstallationStage::AfcConnect))
        );
    }
}
