use std::sync::atomic::{AtomicBool, Ordering};

use isideload::util::{
    fs_storage::FsStorage, keyring_storage::KeyringStorage, storage::SideloadingStorage,
};
use tauri::{AppHandle, Manager};
use tracing::warn;

use crate::error::AppError;

/// Credential Manager service name. Deliberately different from the original
/// iloader's "iloader", so this fork never reads or overwrites its saved data.
pub(crate) const KEYRING_SERVICE: &str = "io.github.andreysemjonov.iloader";

static FORCE_DISABLE_KEYRING: AtomicBool = AtomicBool::new(false);

pub(crate) fn background_keyring_enabled() -> bool {
    !FORCE_DISABLE_KEYRING.load(Ordering::Relaxed)
}

#[tauri::command]
pub fn force_disable_keyring(force: bool) {
    FORCE_DISABLE_KEYRING.store(force, Ordering::Relaxed);

    if force {
        warn!("Keyring has been forcefully disabled by the user.");
    } else {
        let available = check_keyring_available();
        if !available {
            warn!("Keyring is not available and cannot be enabled.");
        }
    }
}

#[tauri::command]
pub fn keyring_available() -> bool {
    !FORCE_DISABLE_KEYRING.load(Ordering::Relaxed) && check_keyring_available()
}

fn check_keyring_available() -> bool {
    let entry = keyring::Entry::new(KEYRING_SERVICE, "test");
    if let Ok(entry) = entry {
        return entry.set_password("test").is_ok() && entry.get_password().is_ok();
    }
    false
}

pub fn create_sideloading_storage(
    app: &AppHandle,
) -> Result<Box<dyn SideloadingStorage>, AppError> {
    if keyring_available() {
        Ok(Box::new(KeyringStorage::new(KEYRING_SERVICE.to_string())))
    } else {
        warn!(
            "Keyring is not available, falling back to filesystem storage for sideloading data. This is insecure!"
        );
        Ok(Box::new(FsStorage::new(
            app.path().app_data_dir().map_err(|e| {
                AppError::Misc(format!("Failed to get app data directory: {:?}", e))
            })?,
        )))
    }
}

/// Read only the saved storage preference; never probe credentials at startup or scheduling.
pub(crate) fn saved_credentials_policy(
    app: &AppHandle,
) -> crate::renewal::session_diagnostic::StoragePolicy {
    use crate::renewal::session_diagnostic::StoragePolicy;
    use tauri_plugin_store::StoreExt;
    if FORCE_DISABLE_KEYRING.load(Ordering::Relaxed) {
        return StoragePolicy::Disabled;
    }
    let Ok(store) = app.store("preferences.json") else {
        return StoragePolicy::Unavailable;
    };
    match store.get("overrideKeyring") {
        None => StoragePolicy::Allowed,
        Some(value) => match value.as_bool() {
            Some(false) => StoragePolicy::Allowed,
            Some(true) => StoragePolicy::Disabled,
            None => StoragePolicy::Unavailable,
        },
    }
}
