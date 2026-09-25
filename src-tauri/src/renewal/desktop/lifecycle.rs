//! Desktop preferences and close behavior, independent of renewal admission.
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Preferences {
    pub close_to_tray: bool,
}

#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub preferences: Preferences,
    pub notice: Option<String>,
}

pub(crate) trait Surface {
    fn tray_present(&self) -> bool;
    fn create_tray(&mut self) -> Result<(), String>;
    fn update_tray(&mut self) -> Result<(), String>;
    fn ensure_tray(&mut self) -> Result<(), String> {
        if self.tray_present() {
            self.update_tray()
        } else {
            self.create_tray()
        }
    }
    fn remove_tray(&mut self);
    fn unminimize(&mut self) -> Result<(), String>;
    fn show(&mut self) -> Result<(), String>;
    fn focus(&mut self) -> Result<(), String>;
    fn restore(&mut self) -> Result<(), String> {
        // Attempt every recovery step; never short-circuit show after an error.
        let restored = self.unminimize();
        let shown = self.show();
        let focused = self.focus();
        restored.and(shown).and(focused)
    }
    fn hide(&mut self) -> Result<(), String>;
}

#[derive(Debug, PartialEq)]
pub(crate) enum Close {
    Stay,
    Exit,
}

pub(crate) struct Desktop {
    directory: PathBuf,
    status: Status,
    available: bool,
    startup_session: bool,
}
impl Desktop {
    pub fn load(directory: &Path, available: bool) -> Self {
        let directory = directory.join("desktop");
        let mut status = Status::default();
        match std::fs::read(directory.join("settings.json")) {
            Ok(bytes) => match serde_json::from_slice(&bytes) {
                Ok(preferences) => status.preferences = preferences,
                Err(_) => {
                    status.notice =
                        Some("Desktop preferences need recovery; close-to-tray is off.".into())
                }
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                status.notice =
                    Some("Unable to read desktop preferences; close-to-tray is off.".into())
            }
        }
        // Effective preference only: preserve the stored opt-in for a strict build.
        // A default build always keeps its normal close-to-exit behavior.
        if !available {
            status.preferences.close_to_tray = false;
        }
        Self {
            directory,
            status,
            available,
            startup_session: false,
        }
    }
    pub fn snapshot(&self) -> Status {
        self.status.clone()
    }
    pub fn notice(&mut self, message: String) {
        self.status.notice = Some(message);
    }
    pub fn configure(&mut self, enabled: bool, surface: &mut impl Surface) -> Result<(), String> {
        if enabled && !self.available {
            return Err("Keeping iLoader in the tray is unavailable".into());
        }
        if enabled {
            surface.ensure_tray()?;
        } else {
            surface.restore()?;
        }
        let preferences = Preferences {
            close_to_tray: enabled,
        };
        std::fs::create_dir_all(&self.directory)
            .map_err(|_| "Unable to save desktop preferences")?;
        super::super::journal::write_atomic(
            &self.directory,
            "settings",
            &serde_json::to_vec(&preferences)
                .map_err(|_| "Unable to encode desktop preferences")?,
        )?;
        self.status.preferences = preferences;
        self.status.notice = None;
        if !enabled && !self.startup_session {
            surface.remove_tray();
        }
        Ok(())
    }
    pub fn tray_required(&self) -> bool {
        self.status.preferences.close_to_tray || self.startup_session
    }
    pub fn launch_startup(
        &mut self,
        startup: &super::super::startup::Startup,
        registry: &mut impl super::super::startup::Registry,
        args: &[std::ffi::OsString],
        host_available: bool,
        surface: &mut impl Surface,
    ) -> Result<(), String> {
        self.startup_session = startup.launch(registry, args, host_available, surface)?;
        Ok(())
    }
    pub fn configure_startup(
        &mut self,
        startup: &super::super::startup::Startup,
        registry: &mut impl super::super::startup::Registry,
        enabled: bool,
        surface: &mut impl Surface,
    ) -> Result<(), String> {
        // Establish a visible route before any startup-only icon can be removed.
        if !enabled {
            surface.restore()?;
        }
        startup.configure(registry, enabled)?;
        if !enabled {
            self.startup_session = false;
            if !self.status.preferences.close_to_tray {
                surface.remove_tray();
            }
        }
        Ok(())
    }
    pub fn close(&mut self, surface: &mut impl Surface, exiting: bool) -> Result<Close, String> {
        if exiting {
            surface.restore()?;
            return Ok(Close::Stay);
        }
        if !self.status.preferences.close_to_tray {
            return Ok(Close::Exit);
        }
        if let Err(error) = surface.ensure_tray().and_then(|_| surface.hide()) {
            let message = match surface.restore() {
                Ok(()) => format!("{error} iLoader remains open; close-to-tray was not completed."),
                Err(restore) => {
                    format!("{error} {restore} Use the tray Open command to recover the window.")
                }
            };
            self.notice(message.clone());
            return Err(message);
        }
        self.status.notice = None;
        Ok(Close::Stay)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Default)]
    struct Window {
        hidden: bool,
        tray: bool,
        unavailable: bool,
        hide_fails: bool,
        restore_fails: bool,
        minimized: bool,
        focused: bool,
        icons_created: usize,
        steps: Vec<&'static str>,
    }
    impl Surface for Window {
        fn tray_present(&self) -> bool {
            self.tray
        }
        fn create_tray(&mut self) -> Result<(), String> {
            if self.unavailable {
                return Err("No tray".into());
            }
            self.icons_created += 1;
            self.tray = true;
            Ok(())
        }
        fn update_tray(&mut self) -> Result<(), String> {
            if self.unavailable {
                return Err("Tray unavailable".into());
            }
            Ok(())
        }
        fn remove_tray(&mut self) {
            self.tray = false;
        }
        fn unminimize(&mut self) -> Result<(), String> {
            self.steps.push("unminimize");
            if self.restore_fails {
                return Err("Restore failed".into());
            }
            self.minimized = false;
            Ok(())
        }
        fn show(&mut self) -> Result<(), String> {
            self.steps.push("show");
            if self.restore_fails {
                return Err("Show failed".into());
            }
            self.hidden = false;
            Ok(())
        }
        fn focus(&mut self) -> Result<(), String> {
            self.steps.push("focus");
            if self.restore_fails {
                return Err("Focus failed".into());
            }
            self.focused = true;
            Ok(())
        }
        fn hide(&mut self) -> Result<(), String> {
            // Even a partial native failure must trigger window recovery.
            self.hidden = true;
            if self.hide_fails {
                return Err("Hide failed".into());
            }
            Ok(())
        }
    }
    #[test]
    fn repeated_status_sync_keeps_one_icon_and_open_restores_minimized_window() {
        let mut window = Window {
            minimized: true,
            hidden: true,
            ..Default::default()
        };
        for _ in 0..4 {
            window.ensure_tray().unwrap();
        }
        assert_eq!(window.icons_created, 1);
        window.restore().unwrap();
        assert!(!window.hidden && !window.minimized && window.focused);
        assert_eq!(window.steps, ["unminimize", "show", "focus"]);
        window.steps.clear();
        window.restore_fails = true;
        assert!(window.restore().is_err());
        assert_eq!(window.steps, ["unminimize", "show", "focus"]);
        assert!(
            window.tray,
            "Failed Open must retain recovery through the tray"
        );
    }
    #[test]
    fn explicit_close_preference_survives_restart_and_hides_only_with_tray() {
        let root = std::env::temp_dir().join(format!("tray-close-{}", std::process::id()));
        let mut desktop = Desktop::load(&root, true);
        let mut window = Window::default();
        assert!(!desktop.snapshot().preferences.close_to_tray);
        assert_eq!(desktop.close(&mut window, false).unwrap(), Close::Exit);
        desktop.configure(true, &mut window).unwrap();
        let mut restarted = Desktop::load(&root, true);
        assert!(restarted.snapshot().preferences.close_to_tray);
        assert_eq!(restarted.close(&mut window, false).unwrap(), Close::Stay);
        assert!(window.hidden && window.tray);
        window.restore().unwrap();
        window.tray = false;
        window.unavailable = true;
        assert!(restarted.close(&mut window, false).is_err());
        assert!(!window.hidden);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn failed_hide_and_hidden_opt_out_preserve_a_reachable_window_or_tray() {
        let root = std::env::temp_dir().join(format!("tray-recovery-{}", std::process::id()));
        let mut desktop = Desktop::load(&root, true);
        let mut window = Window::default();
        desktop.configure(true, &mut window).unwrap();
        window.hide_fails = true;
        assert!(desktop.close(&mut window, false).is_err());
        assert!(!window.hidden && window.tray);
        assert!(desktop.snapshot().notice.is_some());
        window.hide_fails = false;
        desktop.close(&mut window, false).unwrap();
        window.restore_fails = true;
        assert!(desktop.configure(false, &mut window).is_err());
        assert!(window.tray);
        assert!(
            Desktop::load(&root, true)
                .snapshot()
                .preferences
                .close_to_tray
        );
        window.restore_fails = false;
        desktop.configure(false, &mut window).unwrap();
        assert!(!window.hidden && !window.tray);
        assert!(
            !Desktop::load(&root, true)
                .snapshot()
                .preferences
                .close_to_tray
        );
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn upgrade_and_failed_preference_save_cannot_change_close_to_exit() {
        let root = std::env::temp_dir().join(format!("tray-upgrade-{}", std::process::id()));
        std::fs::create_dir_all(root.join("renewal-host")).unwrap();
        std::fs::write(
            root.join("renewal-host/settings.json"),
            br#"{"pilotVersion":1,"optedIn":true,"closeToTray":true,"startAtLogin":true}"#,
        )
        .unwrap();
        let mut desktop = Desktop::load(&root, true);
        let mut window = Window::default();
        assert_eq!(desktop.close(&mut window, false).unwrap(), Close::Exit);
        std::fs::write(root.join("desktop"), "blocks preference directory").unwrap();
        assert!(desktop.configure(true, &mut window).is_err());
        assert!(!desktop.snapshot().preferences.close_to_tray);
        assert_eq!(desktop.close(&mut window, false).unwrap(), Close::Exit);
        assert!(!window.hidden);
        assert!(
            !Desktop::load(&root, true)
                .snapshot()
                .preferences
                .close_to_tray
        );
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn close_during_quit_never_hides_or_requests_another_exit() {
        let root = std::env::temp_dir().join(format!("tray-exit-{}", std::process::id()));
        let mut desktop = Desktop::load(&root, true);
        let mut window = Window::default();
        desktop.configure(true, &mut window).unwrap();
        desktop.close(&mut window, false).unwrap();
        assert!(window.hidden);
        for _ in 0..3 {
            assert_eq!(desktop.close(&mut window, true).unwrap(), Close::Stay);
            assert!(!window.hidden && window.tray);
        }
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn unavailable_build_keeps_close_to_exit_without_erasing_strict_opt_in() {
        let root = std::env::temp_dir().join(format!("tray-unavailable-{}", std::process::id()));
        let mut window = Window::default();
        Desktop::load(&root, true)
            .configure(true, &mut window)
            .unwrap();
        window.remove_tray();
        let mut default_build = Desktop::load(&root, false);
        assert!(!default_build.snapshot().preferences.close_to_tray);
        assert!(default_build.configure(true, &mut window).is_err());
        assert_eq!(
            default_build.close(&mut window, false).unwrap(),
            Close::Exit
        );
        assert!(!window.tray && !window.hidden);
        assert!(
            Desktop::load(&root, true)
                .snapshot()
                .preferences
                .close_to_tray
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
