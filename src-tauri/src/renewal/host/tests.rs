use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
struct FakePort {
    calls: Arc<AtomicUsize>,
    active: Arc<AtomicUsize>,
    release: Arc<Notify>,
    cancelled: Arc<AtomicUsize>,
}
#[tokio::test]
async fn tray_pause_resume_is_durable_requires_opt_in_and_drains_owned_work() {
    let root = std::env::temp_dir().join(format!("tray-host-control-{}", std::process::id()));
    let settings = Settings {
        pilot_version: 1,
        anisette_url: "https://example.invalid".into(),
        ..Default::default()
    };
    let (control, rx) = watch::channel(Control::default());
    let wake = Arc::new(Notify::new());
    let host = Host {
        directory: root.clone(),
        status: Arc::new(Mutex::new(Status {
            available: true,
            settings,
            ..Default::default()
        })),
        control,
        wake: wake.clone(),
        _thread: Mutex::new(None),
    };
    assert!(host.set_paused(false).is_err(), "Tray resume cannot opt in");
    assert!(!root.join("renewal-host/settings.json").exists());
    let mut opted_in = host.snapshot().settings;
    opted_in.opted_in = true;
    host.configure(opted_in).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let active = Arc::new(AtomicUsize::new(0));
    let cancelled = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(Notify::new());
    let mut port = FakePort {
        calls: calls.clone(),
        active: active.clone(),
        cancelled: cancelled.clone(),
        release: release.clone(),
    };
    let task = tokio::spawn(async move { worker(&mut port, rx, wake, true).await });
    tokio::task::yield_now().await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    host.set_paused(true).unwrap();
    assert!(load_settings(&root).unwrap().paused);
    assert!(host.snapshot().settings.opted_in);
    assert!(!host.snapshot().settings.start_at_login);
    tokio::task::yield_now().await;
    assert_eq!(active.load(Ordering::SeqCst), 1);
    release.notify_one();
    tokio::task::yield_now().await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    host.set_paused(false).unwrap();
    assert!(!load_settings(&root).unwrap().paused);
    tokio::task::yield_now().await;
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    host.shutdown();
    assert!(host.set_paused(false).is_err());
    tokio::task::yield_now().await;
    assert_eq!(active.load(Ordering::SeqCst), 1);
    release.notify_one();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(cancelled.load(Ordering::SeqCst), 0);
    std::fs::remove_dir_all(root).unwrap();
}
struct Flight {
    active: Arc<AtomicUsize>,
    cancelled: Arc<AtomicUsize>,
    finished: bool,
}
impl Drop for Flight {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
        if !self.finished {
            self.cancelled.fetch_add(1, Ordering::SeqCst);
        }
    }
}
impl Port for FakePort {
    fn jobs(&mut self) -> Result<Vec<String>, String> {
        Ok(vec!["a".into(), "b".into()])
    }
    async fn attempt(&mut self, _: &str) -> Result<(), String> {
        assert_eq!(
            self.active.fetch_add(1, Ordering::SeqCst),
            0,
            "attempts must be serial"
        );
        let mut flight = Flight {
            active: self.active.clone(),
            cancelled: self.cancelled.clone(),
            finished: false,
        };
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.release.notified().await;
        flight.finished = true;
        Ok(())
    }
    fn running(&mut self, _: bool) {}
}
#[test]
fn host_pause_and_quit_drain_owned_attempt_without_cancelling_or_starting_more() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let calls = Arc::new(AtomicUsize::new(0));
            let active = Arc::new(AtomicUsize::new(0));
            let cancelled = Arc::new(AtomicUsize::new(0));
            let release = Arc::new(Notify::new());
            let wake = Arc::new(Notify::new());
            let mut port = FakePort {
                calls: calls.clone(),
                active: active.clone(),
                release: release.clone(),
                cancelled: cancelled.clone(),
            };
            let (tx, rx) = watch::channel(Control {
                active: true,
                stop: false,
            });
            worker(&mut port, rx.clone(), wake.clone(), false).await;
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            let task = tokio::spawn(async move { worker(&mut port, rx, wake, true).await });
            tokio::task::yield_now().await;
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            tx.send_replace(Control {
                active: false,
                stop: false,
            });
            tokio::task::yield_now().await;
            assert_eq!(
                active.load(Ordering::SeqCst),
                1,
                "pause must retain active operation ownership"
            );
            assert_eq!(cancelled.load(Ordering::SeqCst), 0);
            release.notify_one();
            tokio::task::yield_now().await;
            assert_eq!(active.load(Ordering::SeqCst), 0);
            assert_eq!(
                calls.load(Ordering::SeqCst),
                1,
                "pause prevents next enrollment"
            );
            tx.send_replace(Control {
                active: true,
                stop: false,
            });
            tokio::task::yield_now().await;
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            release.notify_one();
            tokio::task::yield_now().await;
            assert_eq!(calls.load(Ordering::SeqCst), 3);
            tx.send_replace(Control {
                active: false,
                stop: true,
            });
            tokio::task::yield_now().await;
            assert_eq!(
                active.load(Ordering::SeqCst),
                1,
                "quit drains the current attempt"
            );
            assert!(!task.is_finished());
            release.notify_one();
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(active.load(Ordering::SeqCst), 0);
            assert_eq!(cancelled.load(Ordering::SeqCst), 0);
            assert_eq!(calls.load(Ordering::SeqCst), 3);
        });
}
#[test]
fn persisted_notice_keys_suppress_repeats_but_allow_meaningful_changes() {
    let mut notices = BTreeMap::new();
    assert!(new_notice(&mut notices, "a", "action:MfaRequired".into()));
    let mut restarted: Notices =
        serde_json::from_slice(&serde_json::to_vec(&notices).unwrap()).unwrap();
    assert!(!new_notice(
        &mut restarted,
        "a",
        "action:MfaRequired".into()
    ));
    assert!(new_notice(&mut restarted, "a", "installed:123".into()));
    assert!(new_notice(&mut restarted, "a", "action:MfaRequired".into()));
}

#[test]
fn pilot_settings_reject_startup_before_persisting_and_propagate_save_failure() {
    let mut next = Settings {
        opted_in: true,
        start_at_login: true,
        ..Default::default()
    };
    assert!(
        commit_settings(&next, true, |_| panic!(
            "Startup preference must not be saved"
        ))
        .is_err()
    );
    next.start_at_login = false;
    assert!(commit_settings(&next, false, |_| panic!("Unavailable pilot must not save")).is_err());
    assert_eq!(
        commit_settings(&next, true, |_| Err("Disk full".into())),
        Err("Disk full".into())
    );
}

#[test]
fn product_first_use_respects_persisted_off_pause_and_failed_save() {
    for mode in 0..4 {
        let root = std::env::temp_dir().join(format!("product-host-{}-{mode}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let settings = Settings {
            pilot_version: 1,
            opted_in: mode == 2,
            paused: mode == 2,
            anisette_url: "https://example.invalid".into(),
            ..Default::default()
        };
        let (control, _rx) = watch::channel(Control::default());
        let host = Host {
            directory: root.clone(),
            status: Arc::new(Mutex::new(Status {
                available: true,
                settings: settings.clone(),
                ..Default::default()
            })),
            control,
            wake: Arc::new(Notify::new()),
            _thread: Mutex::new(None),
        };
        if mode == 1 || mode == 2 {
            host.configure(settings.clone()).unwrap();
        }
        if mode == 3 {
            std::fs::write(root.join("renewal-host"), b"blocked").unwrap();
        }
        let result = host.authorize_first_use("https://new.invalid");
        if mode == 3 {
            assert!(result.is_err());
            assert_eq!(
                serde_json::to_value(host.snapshot().settings).unwrap(),
                serde_json::to_value(&settings).unwrap()
            );
        } else {
            result.unwrap();
            if mode == 0 {
                assert!(load_settings(&root).unwrap().opted_in);
            } else {
                assert_eq!(
                    serde_json::to_value(load_settings(&root).unwrap()).unwrap(),
                    serde_json::to_value(&settings).unwrap()
                );
            }
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
