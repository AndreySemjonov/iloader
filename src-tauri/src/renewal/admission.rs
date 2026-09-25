//! Per-app pause is independent of the install lease. The pause marker is
//! authoritative even if an in-flight journal write races its creation.
use std::{
    fs::{self, File, OpenOptions},
    path::Path,
};

pub(super) fn validate_id(id: &str) -> Result<(), String> {
    if id.is_empty() || id.len() > 64 || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err("Invalid enrollment id".into());
    }
    Ok(())
}
fn control_lock(directory: &Path) -> Result<File, String> {
    fs::create_dir_all(directory).map_err(|_| "Unable to save per-app pause")?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(directory.join("control.lock"))
        .map_err(|_| "Unable to open per-app controls")?;
    // This short lock only serializes Pause/Enable writes, never an active renewal.
    file.lock().map_err(|_| "Unable to save per-app controls")?;
    Ok(file)
}
pub(super) fn paused(directory: &Path, id: &str) -> Result<bool, String> {
    validate_id(id)?;
    match fs::read(directory.join("admission").join(format!("{id}.json"))) {
        Ok(bytes) => {
            serde_json::from_slice(&bytes).map_err(|_| "Saved per-app pause needs recovery".into())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err("Unable to read per-app pause".into()),
    }
}
pub(super) fn pause(directory: &Path, id: &str) -> Result<(), String> {
    validate_id(id)?;
    let controls = directory.join("admission");
    let _control = control_lock(&controls)?;
    super::journal::write_atomic(&controls, id, b"true")
}
pub(super) fn resume(
    directory: &Path,
    id: &str,
    persist_enabled: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    validate_id(id)?;
    let controls = directory.join("admission");
    let _control = control_lock(&controls)?;
    // A failed/crashed enable leaves the persisted pause in force.
    persist_enabled()?;
    match fs::remove_file(controls.join(format!("{id}.json"))) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("Unable to resume this app".into()),
    }
    #[cfg(unix)]
    File::open(&controls)
        .and_then(|file| file.sync_all())
        .map_err(|_| "Unable to flush app resume")?;
    Ok(())
}
