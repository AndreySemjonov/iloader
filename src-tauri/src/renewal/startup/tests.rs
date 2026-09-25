use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
static SEQ: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "startup-policy-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        Self(root)
    }
    fn startup(&self) -> Startup {
        Startup::new(
            &self.0,
            true,
            Ok(r#""C:\Stable Folder\iloader.exe" --renewal-startup"#.into()),
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
#[derive(Default)]
struct FakeRegistry {
    value: Option<Value>,
    writes: usize,
    reads: usize,
    fail: bool,
    read_failure: bool,
    block_commit: Option<PathBuf>,
    external_change: bool,
    fail_readback: bool,
}
impl Registry for FakeRegistry {
    fn read(&mut self) -> Result<Option<Value>, String> {
        self.reads += 1;
        if self.read_failure {
            return Err("Registry read denied".into());
        }
        Ok(self.value.clone())
    }
    fn replace(&mut self, expected: Option<&Value>, next: Option<&str>) -> Result<(), String> {
        if self.external_change {
            self.value = Some(Value::Other);
            return Err("Externally changed".into());
        }
        assert_eq!(self.value.as_ref(), expected);
        if self.fail {
            return Err("Registry denied".into());
        }
        self.value = next.map(|s| Value::Command(s.into()));
        self.writes += 1;
        if self.fail_readback {
            self.read_failure = true;
        }
        if let Some(path) = &self.block_commit {
            std::fs::create_dir(path).unwrap();
        }
        Ok(())
    }
}
#[test]
fn explicit_opt_in_registers_only_current_executable_and_survives_restart() {
    let f = Fixture::new();
    let startup = f.startup();
    let mut registry = FakeRegistry::default();
    assert!(!startup.snapshot(&mut registry).enabled);
    startup.configure(&mut registry, true).unwrap();
    assert_eq!(
        registry.value,
        Some(Value::Command(
            r#""C:\Stable Folder\iloader.exe" --renewal-startup"#.into()
        ))
    );
    let status = f.startup().snapshot(&mut registry);
    assert!(status.enabled && status.verified);
    assert_eq!(registry.writes, 1);
    startup.configure(&mut registry, false).unwrap();
    assert_eq!(registry.value, None);
    assert!(!f.startup().snapshot(&mut registry).enabled);
}

#[derive(Default)]
struct FakeSurface {
    tray: bool,
    hidden: bool,
    fail_tray: bool,
    fail_hide: bool,
    fail_show: bool,
    steps: Vec<&'static str>,
}
impl super::super::desktop::lifecycle::Surface for FakeSurface {
    fn tray_present(&self) -> bool {
        self.tray
    }
    fn create_tray(&mut self) -> Result<(), String> {
        self.steps.push("tray");
        if self.fail_tray {
            return Err("Tray unavailable".into());
        }
        self.tray = true;
        Ok(())
    }
    fn update_tray(&mut self) -> Result<(), String> {
        self.create_tray()
    }
    fn remove_tray(&mut self) {
        self.steps.push("remove");
        self.tray = false;
    }
    fn unminimize(&mut self) -> Result<(), String> {
        self.steps.push("unminimize");
        Ok(())
    }
    fn show(&mut self) -> Result<(), String> {
        self.steps.push("show");
        if self.fail_show {
            return Err("Show failed".into());
        }
        self.hidden = false;
        Ok(())
    }
    fn focus(&mut self) -> Result<(), String> {
        self.steps.push("focus");
        Ok(())
    }
    fn hide(&mut self) -> Result<(), String> {
        self.steps.push("hide");
        self.hidden = true;
        if self.fail_hide {
            Err("Hide failed".into())
        } else {
            Ok(())
        }
    }
}
#[test]
fn logon_hides_only_after_verified_consent_and_tray_and_never_rewrites_registration() {
    let f = Fixture::new();
    let startup = f.startup();
    let mut registry = FakeRegistry::default();
    let mut window = FakeSurface::default();
    startup.configure(&mut registry, true).unwrap();
    assert!(
        !startup
            .launch(&mut registry, &[], true, &mut window)
            .unwrap()
    );
    assert!(!window.hidden);
    assert!(
        startup
            .launch(&mut registry, &[ARGUMENT.into()], true, &mut window)
            .unwrap()
    );
    assert!(window.hidden && window.tray);
    assert_eq!(window.steps, vec!["tray", "hide"]);
    assert_eq!(registry.writes, 1);
}

#[test]
fn command_line_is_quoted_bounded_and_rejects_temporary_or_ambiguous_paths() {
    assert_eq!(
        command_for(r"C:\My Apps & tools\iloader.exe", &[]).unwrap(),
        r#""C:\My Apps & tools\iloader.exe" --renewal-startup"#
    );
    for path in [
        r"relative\iloader.exe",
        r"\\server\share\iloader.exe",
        r#"C:\bad"name\iloader.exe"#,
        "C:\\bad\nname\\iloader.exe",
    ] {
        assert!(command_for(path, &[]).is_err());
    }
    assert!(command_for(&format!("C:\\{}\\iloader.exe", "😀".repeat(130)), &[]).is_err());
    assert!(command_for(r"C:\TEMP\copy\iloader.exe", &[r"c:\temp".into()]).is_err());
    assert!(command_for(r"C:\Tempest\iloader.exe", &[r"c:\temp".into()]).is_ok());
    assert_eq!(
        command_for(r"\\?\C:\Stable\iloader.exe", &[]).unwrap(),
        r#""C:\Stable\iloader.exe" --renewal-startup"#
    );
}
#[test]
fn legacy_preferences_are_not_consent_and_renewal_state_stays_unchanged() {
    let f = Fixture::new();
    std::fs::create_dir(f.0.join("renewal-host")).unwrap();
    std::fs::create_dir(f.0.join("renewal")).unwrap();
    let host = f.0.join("renewal-host/settings.json");
    let job = f.0.join("renewal/untouched.json");
    std::fs::write(
        &host,
        b"{\"startAtLogin\":true,\"optedIn\":false,\"paused\":true}",
    )
    .unwrap();
    std::fs::write(&job, b"existing app schedules and account holds").unwrap();
    let before_host = std::fs::read(&host).unwrap();
    let before_job = std::fs::read(&job).unwrap();
    let mut registry = FakeRegistry::default();
    let startup = f.startup();
    let mut window = FakeSurface::default();
    assert!(!startup.snapshot(&mut registry).enabled);
    assert!(
        startup
            .launch(&mut registry, &[ARGUMENT.into()], true, &mut window)
            .is_err()
    );
    assert!(!window.hidden);
    startup.configure(&mut registry, true).unwrap();
    startup.configure(&mut registry, false).unwrap();
    assert_eq!(std::fs::read(host).unwrap(), before_host);
    assert_eq!(std::fs::read(job).unwrap(), before_job);
}
#[test]
fn foreign_modified_missing_and_moved_registrations_never_hide_or_silently_repair() {
    for foreign in [
        Value::Other,
        Value::Command(r#""C:\Stable Folder\iloader.exe" --renewal-startup"#.into()),
        Value::Command("someone else's command".into()),
    ] {
        let f = Fixture::new();
        let startup = f.startup();
        let mut registry = FakeRegistry {
            value: Some(foreign.clone()),
            ..Default::default()
        };
        for enabled in [true, false] {
            assert!(startup.configure(&mut registry, enabled).is_err());
        }
        assert!(!startup.snapshot(&mut registry).verified);
        assert_eq!(registry.value, Some(foreign));
        assert_eq!(registry.writes, 0);
    }
    let f = Fixture::new();
    let startup = f.startup();
    let mut registry = FakeRegistry::default();
    startup.configure(&mut registry, true).unwrap();
    let bytes = std::fs::read(f.0.join("startup/settings.json")).unwrap();
    registry.value = Some(Value::Other);
    let mut window = FakeSurface::default();
    assert!(
        startup
            .launch(&mut registry, &[ARGUMENT.into()], true, &mut window)
            .is_err()
    );
    assert!(!window.hidden);
    assert!(startup.configure(&mut registry, false).is_err());
    assert_eq!(registry.writes, 1);
    assert_eq!(
        std::fs::read(f.0.join("startup/settings.json")).unwrap(),
        bytes
    );
    registry.value = None;
    assert!(!startup.snapshot(&mut registry).enabled);
    assert!(
        startup
            .launch(&mut registry, &[ARGUMENT.into()], true, &mut window)
            .is_err()
    );
    assert_eq!(registry.writes, 1);
    startup.configure(&mut registry, true).unwrap();
    let moved = Startup::new(
        &f.0,
        true,
        Ok(r#""C:\New Folder\iloader.exe" --renewal-startup"#.into()),
    );
    assert!(!moved.snapshot(&mut registry).verified);
    assert!(moved.configure(&mut registry, true).is_err());
    moved.configure(&mut registry, false).unwrap();
    moved.configure(&mut registry, true).unwrap();
    assert!(moved.snapshot(&mut registry).verified);
    let temporary = Startup::new(&f.0, true, Err("Use stable copy outside Temp".into()));
    assert!(temporary.snapshot(&mut registry).enabled);
    assert!(!temporary.snapshot(&mut registry).verified);
    assert!(temporary.configure(&mut registry, true).is_err());
    temporary.configure(&mut registry, false).unwrap();
    assert_eq!(registry.value, None);
}
#[test]
fn failures_at_each_persistence_boundary_are_truthful_and_recover_only_explicitly() {
    for enabled in [true, false] {
        let f = Fixture::new();
        let startup = f.startup();
        let mut registry = FakeRegistry::default();
        if !enabled {
            startup.configure(&mut registry, true).unwrap();
        }
        let path = f.0.join("startup/settings.pending");
        std::fs::create_dir_all(&path).unwrap();
        let writes = registry.writes;
        assert!(startup.configure(&mut registry, enabled).is_err());
        assert_eq!(registry.writes, writes);
        std::fs::remove_dir(&path).unwrap();
        registry.fail = true;
        assert!(startup.configure(&mut registry, enabled).is_err());
        assert!(!startup.snapshot(&mut registry).verified);
        assert_eq!(registry.writes, writes);
        registry.fail = false;
        registry.block_commit = Some(path.clone());
        assert!(startup.configure(&mut registry, enabled).is_err());
        let state = startup.snapshot(&mut registry);
        assert_eq!(state.enabled, enabled);
        assert!(!state.verified);
        assert!(state.notice.is_some());
        let writes = registry.writes;
        let mut window = FakeSurface::default();
        assert!(
            f.startup()
                .launch(&mut registry, &[ARGUMENT.into()], true, &mut window)
                .is_err()
        );
        assert_eq!(registry.writes, writes);
        assert!(!window.hidden);
        std::fs::remove_dir(path).unwrap();
        registry.block_commit = None;
        startup.configure(&mut registry, enabled).unwrap();
        assert_eq!(registry.writes, writes);
        assert_eq!(startup.snapshot(&mut registry).verified, enabled);
    }
}
#[test]
fn corrupt_read_failed_or_concurrently_changed_state_cannot_be_claimed_or_hidden() {
    let f = Fixture::new();
    let startup = f.startup();
    let mut registry = FakeRegistry {
        read_failure: true,
        ..Default::default()
    };
    assert!(startup.snapshot(&mut registry).notice.is_some());
    assert!(startup.configure(&mut registry, true).is_err());
    registry.read_failure = false;
    registry.external_change = true;
    assert!(startup.configure(&mut registry, true).is_err());
    assert_eq!(registry.writes, 0);
    assert_eq!(registry.value, Some(Value::Other));
    std::fs::write(f.0.join("startup/settings.json"), b"corrupt").unwrap();
    let state = startup.snapshot(&mut registry);
    assert!(!state.can_enable && !state.can_disable && !state.verified);
    assert!(state.notice.is_some());
}
#[test]
fn unsupported_duplicate_bad_arguments_and_tray_failures_restore_visible_route() {
    let f = Fixture::new();
    let startup = f.startup();
    let mut registry = FakeRegistry::default();
    startup.configure(&mut registry, true).unwrap();
    let unsupported = Startup::new(
        &f.0,
        false,
        Ok(r#""C:\Stable Folder\iloader.exe" --renewal-startup"#.into()),
    );
    let reads = registry.reads;
    assert!(!unsupported.snapshot(&mut registry).enabled);
    assert_eq!(registry.reads, reads);
    assert!(unsupported.configure(&mut registry, true).is_err());
    for mode in 0..5 {
        let mut window = FakeSurface {
            hidden: true,
            fail_tray: mode == 3,
            fail_hide: mode == 4,
            ..Default::default()
        };
        let args = if mode == 2 {
            vec![ARGUMENT.into(), "--extra".into()]
        } else {
            vec![ARGUMENT.into()]
        };
        let chosen = if mode == 0 { &unsupported } else { &startup };
        assert!(
            chosen
                .launch(&mut registry, &args, mode != 1, &mut window)
                .is_err()
        );
        assert!(!window.hidden);
        assert!(window.steps.ends_with(&["unminimize", "show", "focus"]));
    }
    assert_eq!(registry.writes, 1);
}
#[test]
fn startup_session_and_close_preference_have_independent_tray_lifetimes() {
    use super::super::desktop::lifecycle::{Desktop, Surface};
    let f = Fixture::new();
    let startup = f.startup();
    let mut registry = FakeRegistry::default();
    let mut window = FakeSurface::default();
    let mut desktop = Desktop::load(&f.0, true);
    desktop
        .configure_startup(&startup, &mut registry, true, &mut window)
        .unwrap();
    assert!(!desktop.snapshot().preferences.close_to_tray);
    assert!(!window.hidden);
    desktop
        .launch_startup(
            &startup,
            &mut registry,
            &[ARGUMENT.into()],
            true,
            &mut window,
        )
        .unwrap();
    assert!(window.hidden && desktop.tray_required());
    desktop.configure(false, &mut window).unwrap();
    assert!(window.tray && !window.hidden && desktop.tray_required());
    window.hide().unwrap();
    window.fail_show = true;
    let writes = registry.writes;
    assert!(
        desktop
            .configure_startup(&startup, &mut registry, false, &mut window)
            .is_err()
    );
    assert_eq!(registry.writes, writes);
    assert!(window.tray);
    window.fail_show = false;
    registry.fail = true;
    assert!(
        desktop
            .configure_startup(&startup, &mut registry, false, &mut window)
            .is_err()
    );
    assert!(!window.hidden && window.tray);
    registry.fail = false;
    desktop
        .configure_startup(&startup, &mut registry, false, &mut window)
        .unwrap();
    assert!(!window.hidden && !window.tray && !desktop.tray_required());
    desktop.configure(true, &mut window).unwrap();
    desktop
        .configure_startup(&startup, &mut registry, true, &mut window)
        .unwrap();
    desktop
        .launch_startup(
            &startup,
            &mut registry,
            &[ARGUMENT.into()],
            true,
            &mut window,
        )
        .unwrap();
    desktop
        .configure_startup(&startup, &mut registry, false, &mut window)
        .unwrap();
    assert!(window.tray && desktop.snapshot().preferences.close_to_tray && !window.hidden);
}

#[test]
fn unverified_registry_reply_never_confirms_consent_and_requires_explicit_retry() {
    let f = Fixture::new();
    let startup = f.startup();
    let mut registry = FakeRegistry {
        fail_readback: true,
        ..Default::default()
    };
    assert!(startup.configure(&mut registry, true).is_err());
    assert!(!startup.snapshot(&mut registry).verified);
    registry.read_failure = false;
    registry.fail_readback = false;
    let status = f.startup().snapshot(&mut registry);
    assert!(status.enabled && !status.verified && status.notice.is_some());
    let writes = registry.writes;
    let mut window = FakeSurface::default();
    assert!(
        startup
            .launch(&mut registry, &[ARGUMENT.into()], true, &mut window)
            .is_err()
    );
    assert_eq!(registry.writes, writes);
    assert!(!window.hidden);
    startup.configure(&mut registry, true).unwrap();
    assert_eq!(registry.writes, writes);
    assert!(startup.snapshot(&mut registry).verified);
}

#[test]
fn failed_disable_after_uncommitted_enable_preserves_ownership_through_restart() {
    let f = Fixture::new();
    let startup = f.startup();
    let staging = f.0.join("startup/settings.pending");
    let mut registry = FakeRegistry {
        block_commit: Some(staging.clone()),
        ..Default::default()
    };
    assert!(startup.configure(&mut registry, true).is_err());
    std::fs::remove_dir(staging).unwrap();
    registry.block_commit = None;
    registry.fail = true;
    assert!(startup.configure(&mut registry, false).is_err());
    let restarted = f.startup();
    let status = restarted.snapshot(&mut registry);
    assert!(status.enabled && status.can_disable && !status.verified);
    registry.fail = false;
    restarted.configure(&mut registry, false).unwrap();
    assert_eq!(registry.value, None);
}
#[test]
fn unavailable_host_keeps_persisted_close_consent_but_extra_window_cannot_hide() {
    use super::super::desktop::lifecycle::{Close, Desktop};
    let f = Fixture::new();
    let mut owner = Desktop::load(&f.0, true);
    let mut window = FakeSurface::default();
    owner.configure(true, &mut window).unwrap();
    let before = std::fs::read(f.0.join("desktop/settings.json")).unwrap();
    let mut extra = Desktop::load(&f.0, false);
    let mut extra_window = FakeSurface::default();
    assert!(!extra.tray_required());
    assert!(matches!(
        extra.close(&mut extra_window, false).unwrap(),
        Close::Exit
    ));
    assert!(!extra_window.hidden && !extra_window.tray);
    assert!(extra.configure(true, &mut extra_window).is_err());
    assert_eq!(
        std::fs::read(f.0.join("desktop/settings.json")).unwrap(),
        before
    );
    assert!(
        Desktop::load(&f.0, true)
            .snapshot()
            .preferences
            .close_to_tray
    );
}
