//! Explicit Windows logon consent and owned registration, independent of renewal admission.
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub(crate) const ARGUMENT: &str = "--renewal-startup";
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Value {
    Command(String),
    Other,
}
pub(crate) trait Registry {
    fn read(&mut self) -> Result<Option<Value>, String>;
    fn replace(&mut self, expected: Option<&Value>, next: Option<&str>) -> Result<(), String>;
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    confirmed: Option<String>,
    pending: Option<Intent>,
}
impl Default for Record {
    fn default() -> Self {
        Self {
            version: 1,
            confirmed: None,
            pending: None,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
enum Intent {
    Enable(String),
    Disable(Option<String>),
}
#[derive(Default, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Status {
    pub available: bool,
    pub enabled: bool,
    pub verified: bool,
    pub can_enable: bool,
    pub can_disable: bool,
    pub notice: Option<String>,
}
pub(crate) struct Startup {
    directory: PathBuf,
    available: bool,
    current: Result<String, String>,
}
impl Startup {
    pub(crate) fn new(directory: &Path, available: bool, current: Result<String, String>) -> Self {
        Self {
            directory: directory.join("startup"),
            available,
            current,
        }
    }
    pub(crate) fn launch(
        &self,
        registry: &mut impl Registry,
        args: &[std::ffi::OsString],
        host_available: bool,
        surface: &mut impl super::desktop::lifecycle::Surface,
    ) -> Result<bool, String> {
        if args.is_empty() {
            return Ok(false);
        }
        let result = (|| -> Result<(), String> {
            if args.len() != 1 || args[0] != ARGUMENT {
                return Err("Unrecognized startup arguments; iLoader remains visible.".into());
            }
            if !host_available {
                return Err("The renewal host is unavailable or already open. Use Open iLoader in the existing tray, then quit this extra window.".into());
            }
            let status = self.snapshot(registry);
            if !status.verified {
                return Err(status.notice.unwrap_or_else(||"Startup consent or registration is missing. Enable startup from the stable copy in renewal settings.".into()));
            }
            surface.ensure_tray()?;
            surface.hide()
        })();
        if let Err(error) = result {
            let restore = surface.restore();
            return Err(match restore {
                Ok(()) => error,
                Err(restore) => format!("{error} {restore} Use tray Open to recover the window."),
            });
        }
        Ok(true)
    }
    fn load(&self) -> Result<Record, String> {
        let record: Record = match std::fs::read(self.directory.join("settings.json")) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|_| "Startup preferences need recovery; automatic hiding is off")?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Record::default(),
            Err(_) => {
                return Err("Unable to read startup preferences; automatic hiding is off".into());
            }
        };
        if record.version != 1
            || record.confirmed.as_ref().is_some_and(|c| !valid_command(c))
            || matches!(&record.pending,Some(Intent::Enable(c) | Intent::Disable(Some(c))) if !valid_command(c))
        {
            return Err("Unsupported startup preferences; automatic hiding is off".into());
        }
        Ok(record)
    }
    fn save(&self, record: &Record) -> Result<(), String> {
        std::fs::create_dir_all(&self.directory)
            .map_err(|_| "Unable to save startup preferences")?;
        super::journal::write_atomic(
            &self.directory,
            "settings",
            &serde_json::to_vec(record).map_err(|_| "Unable to encode startup preferences")?,
        )
    }
    pub(crate) fn configure(
        &self,
        registry: &mut impl Registry,
        enabled: bool,
    ) -> Result<(), String> {
        if !self.available {
            return Err("Windows startup is unavailable in this build".into());
        }
        let _lease = crate::install_lock::InstallLease::acquire_service(&self.directory)
            .map_err(|_| "Another startup preference change is in progress")?;
        let mut record = self.load()?;
        let actual = registry.read()?;
        if actual.as_ref().is_some_and(|value| !record.owns(value)) {
            return Err(CONFLICT.into());
        }
        let next = if enabled {
            let command = self.current.clone()?;
            if !valid_command(&command) {
                return Err("Invalid startup command".into());
            }
            Some(command)
        } else {
            None
        };
        if enabled && actual.is_some() && actual != next.clone().map(Value::Command) {
            return Err("Startup points to another copy. Turn it off here, then enable it from the stable copy.".into());
        }
        if record.pending.is_none()
            && record.confirmed == next
            && actual == next.clone().map(Value::Command)
        {
            return Ok(());
        }
        record.pending = Some(match &next {
            Some(command) => Intent::Enable(command.clone()),
            None => Intent::Disable(actual.as_ref().and_then(|value| match value {
                Value::Command(command) => Some(command.clone()),
                Value::Other => None,
            })),
        });
        self.save(&record)?;
        if actual != next.clone().map(Value::Command) {
            registry.replace(actual.as_ref(), next.as_deref())?;
        }
        if registry.read()? != next.clone().map(Value::Command) {
            return Err("Startup registration could not be verified. Review Windows Startup settings and retry.".into());
        }
        self.save(&Record {
            version: 1,
            confirmed: next,
            pending: None,
        })
    }
    pub(crate) fn snapshot(&self, registry: &mut impl Registry) -> Status {
        if !self.available {
            return Status {
                notice: Some("Windows startup is unavailable in this build".into()),
                ..Default::default()
            };
        }
        let result = (|| -> Result<Status, String> {
            let record = self.load()?;
            let actual = registry.read()?;
            if actual.as_ref().is_some_and(|value| !record.owns(value)) {
                return Err(CONFLICT.into());
            }
            let enabled = actual.is_some();
            let verified = enabled
                && record.pending.is_none()
                && self.current.as_ref().is_ok_and(|current| {
                    record.confirmed.as_ref() == Some(current)
                        && actual.as_ref() == Some(&Value::Command(current.clone()))
                });
            let notice = if record.pending.is_some() {
                Some(if enabled {"Startup is registered, but setup is incomplete. Turn it off, then on to finish; startup will stay visible until then."}else {"Startup is not registered; the preference change is incomplete. Turn it on to retry, or leave it off."}.into())
            } else if let Err(error) = &self.current {
                Some(error.clone())
            } else if enabled && !verified {
                Some("Startup points to another copy. Turn it off here, then enable it from the stable copy.".into())
            } else if record.confirmed.is_some() && !enabled {
                Some("The Windows startup entry is missing. Turn startup on to register this copy again.".into())
            } else {
                None
            };
            Ok(Status {
                available: true,
                enabled,
                verified,
                can_enable: self.current.is_ok(),
                can_disable: enabled,
                notice,
            })
        })();
        result.unwrap_or_else(|error| Status {
            available: true,
            notice: Some(error),
            ..Default::default()
        })
    }
}
const CONFLICT: &str = "The Windows startup entry was changed outside iLoader. It was left untouched; review it in Windows Startup settings.";
impl Record {
    fn owns(&self, value: &Value) -> bool {
        let Value::Command(command) = value else {
            return false;
        };
        self.confirmed.as_ref() == Some(command)
            || matches!(&self.pending,Some(Intent::Enable(pending) | Intent::Disable(Some(pending))) if pending==command)
    }
}
/// Registry command limits are UTF-16 units, not Unicode scalar or UTF-8 counts.
pub(crate) fn command_for(executable: &str, temporary_roots: &[String]) -> Result<String, String> {
    let path = executable.strip_prefix(r"\\?\").unwrap_or(executable);
    if path.len() < 7
        || !path.as_bytes()[0].is_ascii_alphabetic()
        || !path.starts_with(&format!("{}:\\", &path[..1]))
        || !path.to_ascii_lowercase().ends_with(".exe")
        || path.chars().any(|c| c == '"' || c.is_control())
    {
        return Err(
            "Startup needs an absolute local executable path without quotes or control characters."
                .into(),
        );
    }
    let normalized = path.replace('/', "\\").to_lowercase();
    if temporary_roots.iter().any(|root| {
        let root = root
            .strip_prefix(r"\\?\")
            .unwrap_or(root)
            .replace('/', "\\")
            .trim_end_matches('\\')
            .to_lowercase();
        normalized == root || normalized.starts_with(&(root + "\\"))
    }) {
        return Err(
            "Open the stable iLoader copy outside Temp before enabling Windows startup.".into(),
        );
    }
    let command = format!("\"{path}\" {ARGUMENT}");
    if command.encode_utf16().count() > 260 {
        return Err(
            "The startup path is too long. Move iLoader to a shorter stable folder.".into(),
        );
    }
    Ok(command)
}
fn valid_command(command: &str) -> bool {
    command
        .strip_suffix(&format!("\" {ARGUMENT}"))
        .and_then(|path| path.strip_prefix('"'))
        .is_some_and(|path| command_for(path, &[]).as_deref() == Ok(command))
}
pub(crate) fn current_command() -> Result<String, String> {
    let executable = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|_| "Unable to locate the current executable")?;
    let mut roots = vec![std::env::temp_dir()];
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        roots.push(PathBuf::from(local).join("Temp"));
    }
    let roots = roots
        .into_iter()
        .map(|root| {
            std::fs::canonicalize(&root)
                .unwrap_or(root)
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    command_for(
        executable
            .to_str()
            .ok_or("The executable path cannot be registered")?,
        &roots,
    )
}
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) use windows::NativeRegistry;
#[cfg(not(windows))]
pub(crate) struct NativeRegistry;
#[cfg(not(windows))]
impl Registry for NativeRegistry {
    fn read(&mut self) -> Result<Option<Value>, String> {
        Err("Windows startup is unavailable in this build".into())
    }
    fn replace(&mut self, _: Option<&Value>, _: Option<&str>) -> Result<(), String> {
        Err("Windows startup is unavailable in this build".into())
    }
}
#[cfg(test)]
mod tests;
