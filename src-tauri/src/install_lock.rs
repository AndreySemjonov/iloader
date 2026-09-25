use std::{
    fs::{File, OpenOptions},
    path::Path,
};

use crate::error::AppError;

/// An OS lock is released on exit/crash. Keep the file: removing a locked file
/// would let another process lock a different inode on Unix.
#[derive(Default)]
struct Admission {
    exiting: bool,
    active: usize,
}
#[derive(Default)]
struct Gate(std::sync::Mutex<Admission>);
static GATE: std::sync::OnceLock<std::sync::Arc<Gate>> = std::sync::OnceLock::new();
fn gate() -> &'static std::sync::Arc<Gate> {
    GATE.get_or_init(Default::default)
}
struct Operation(std::sync::Arc<Gate>);
impl Gate {
    fn enter(self: &std::sync::Arc<Self>) -> Result<Operation, AppError> {
        let mut state = self.0.lock().unwrap();
        if state.exiting {
            return Err(AppError::Misc(
                "iLoader is waiting for active work before exiting".into(),
            ));
        }
        state.active += 1;
        Ok(Operation(self.clone()))
    }
    fn stop(&self) -> bool {
        let mut state = self.0.lock().unwrap();
        let first = !state.exiting;
        state.exiting = true;
        first
    }
    fn idle(&self) -> bool {
        self.0.lock().unwrap().active == 0
    }
}
impl Drop for Operation {
    fn drop(&mut self) {
        self.0.0.lock().unwrap().active -= 1;
    }
}
pub(crate) fn request_exit() -> bool {
    gate().stop()
}
pub(crate) fn idle() -> bool {
    gate().idle()
}
pub(crate) fn exiting() -> bool {
    gate().0.lock().unwrap().exiting
}

pub struct InstallLease {
    file: File,
    _operation: Option<Operation>,
}

impl InstallLease {
    pub fn acquire(directory: &Path) -> Result<Self, AppError> {
        let operation = gate().enter()?;
        Self::open(directory, Some(operation))
    }
    // Long-lived service singleton locks do not represent an active install.
    pub(crate) fn acquire_service(directory: &Path) -> Result<Self, AppError> {
        Self::open(directory, None)
    }
    fn open(directory: &Path, operation: Option<Operation>) -> Result<Self, AppError> {
        std::fs::create_dir_all(directory).map_err(|e| {
            AppError::Filesystem(
                "Unable to create install lock directory".into(),
                e.to_string(),
            )
        })?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(directory.join("install.lock"))
            .map_err(|e| {
                AppError::Filesystem("Unable to open install lock".into(), e.to_string())
            })?;
        file.try_lock().map_err(|_| {
            AppError::Misc(
                "Another installation is running. Wait for it to finish and try again.".into(),
            )
        })?;
        Ok(Self {
            file,
            _operation: operation,
        })
    }
}

impl Drop for InstallLease {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_stops_admission_and_waits_for_every_owned_operation() {
        let gate = std::sync::Arc::new(Gate::default());
        let manual = gate.enter().unwrap();
        let one_shot = gate.enter().unwrap();
        assert!(gate.stop());
        assert!(
            !gate.stop(),
            "Repeated Quit must not start another exit waiter"
        );
        assert!(gate.enter().is_err());
        assert!(!gate.idle());
        drop(manual);
        assert!(!gate.idle());
        drop(one_shot);
        assert!(gate.idle());
        assert!(gate.enter().is_err());
    }
    #[test]
    fn competing_handles_are_excluded_and_release_recovers() {
        let dir = std::env::temp_dir().join(format!("iloader-lock-test-{}", std::process::id()));
        let first = InstallLease::acquire(&dir).unwrap();
        assert!(InstallLease::acquire(&dir).is_err());
        drop(first);
        assert!(InstallLease::acquire(&dir).is_ok());
        std::fs::remove_file(dir.join("install.lock")).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }
}
