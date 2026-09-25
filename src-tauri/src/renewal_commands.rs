//! Product app commands and local enrollment management.
use std::path::PathBuf;

use tauri::Emitter;
use tauri::{AppHandle, Manager};

use crate::{
    device::DeviceInfoMutex,
    renewal::management::{Catalog, Snapshot},
    sideload::SideloaderMutex,
};

fn directory(handle: &AppHandle) -> Result<PathBuf, String> {
    handle
        .path()
        .app_data_dir()
        .map_err(|_| "Unable to locate saved setups".into())
}

#[tauri::command]
pub async fn install_auto_renewal(
    handle: AppHandle,
    app_path: String,
    expected_phone: String,
    expected_account: String,
    anisette_url: String,
) -> Result<crate::renewal::product::ResultView, String> {
    crate::renewal::management::require_execution()?;
    let (phone, account) = selected_identity(&handle, &expected_phone, &expected_account)?;
    let name = handle
        .state::<DeviceInfoMutex>()
        .lock()
        .map_err(|_| "Device selection unavailable")?
        .as_ref()
        .map(|d| d.info.name.clone())
        .unwrap_or_else(|| "iPhone".into());
    product_action(
        handle,
        anisette_url,
        crate::renewal::product::Action::Install {
            source: app_path.into(),
            phone,
            name,
            account,
        },
    )
    .await
}

#[tauri::command]
pub async fn manage_renewal_app(
    handle: AppHandle,
    id: String,
    action: String,
    app_path: Option<String>,
    anisette_url: String,
) -> Result<crate::renewal::product::ResultView, String> {
    crate::renewal::management::require_execution()?;
    use crate::renewal::product::Action;
    let action = match action.as_str() {
        "renew" => Action::Renew { id },
        "replace" => Action::Replace {
            id,
            source: app_path.ok_or("Choose a replacement IPA")?.into(),
        },
        "recover" => Action::Recover { id },
        "resume" => Action::Resume { id },
        _ => return Err("Unknown app action".into()),
    };
    product_action(handle, anisette_url, action).await
}
async fn product_action(
    handle: AppHandle,
    anisette_url: String,
    action: crate::renewal::product::Action,
) -> Result<crate::renewal::product::ResultView, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("iloader-managed-app".into())
        .spawn(move || {
            let result = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| "Unable to start app action".to_string())
                .and_then(|runtime| {
                    runtime.block_on(crate::renewal::live::manage_product(
                        handle.clone(),
                        &anisette_url,
                        action,
                    ))
                });
            let _ = handle.emit("renewal-changed", ());
            let _ = tx.send(result);
        })
        .map_err(|_| "Unable to start app action")?;
    rx.await
        .map_err(|_| "App action stopped; review the saved outcome before retrying")?
}

async fn local_action<T: Send + 'static>(
    handle: AppHandle,
    action: impl FnOnce(Catalog) -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    let directory = directory(&handle)?;
    tauri::async_runtime::spawn_blocking(move || action(Catalog::acquire(&directory)?))
        .await
        .map_err(|_| "Unable to complete setup request")?
}

#[tauri::command]
pub async fn renewal_setups(handle: AppHandle) -> Result<Snapshot, String> {
    local_action(handle, |catalog| catalog.snapshot()).await
}

#[tauri::command]
pub async fn pause_renewal_setup(handle: AppHandle, id: String) -> Result<(), String> {
    let directory = directory(&handle)?;
    tauri::async_runtime::spawn_blocking(move || {
        crate::renewal::management::pause_setup(&directory, &id)
    })
    .await
    .map_err(|_| "Unable to save per-app pause")?
}

#[tauri::command]
pub async fn remove_renewal_setup(handle: AppHandle, id: String) -> Result<(), String> {
    local_action(handle, move |catalog| catalog.remove(&id)).await
}

pub(crate) fn selected_identity(
    handle: &AppHandle,
    expected_phone: &str,
    expected_account: &str,
) -> Result<(String, String), String> {
    let phone_state = handle.state::<DeviceInfoMutex>();
    let phone = phone_state
        .lock()
        .map_err(|_| "Device selection unavailable")?
        .as_ref()
        .map(|device| device.info.clone())
        .ok_or("Select the saved phone first")?;
    let account_state = handle.state::<SideloaderMutex>();
    let account = account_state
        .lock()
        .map_err(|_| "Account selection unavailable")?
        .as_ref()
        .map(|signer| signer.get_email().to_owned())
        .ok_or("Sign in to the saved account first")?;
    if phone.connection_type != "Network"
        || phone.udid != expected_phone
        || !account.eq_ignore_ascii_case(expected_account)
    {
        return Err("Select this setup's phone over Wi-Fi and sign in to its account first".into());
    }
    Ok((phone.udid, account))
}
