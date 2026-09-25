//! Real host loop + catalog + engine + filesystem journals; only time and external work are injected.
use super::*;
use crate::renewal::{self, AttemptStage, Backend, Clock, Failure, Journal, Phase};
use std::{
    io::Write,
    sync::atomic::{AtomicI64, AtomicU64, Ordering},
};
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "recurring-host-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
    fn enrollment(&self, phone: &str, account: &str, expiry: i64) -> String {
        let ipa = self.0.join("original.ipa");
        let mut zip = zip::ZipWriter::new(std::fs::File::create(&ipa).unwrap());
        zip.start_file(
            "Payload/Test.app/Info.plist",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        write!(zip, "<plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>test.app</string></dict></plist>").unwrap();
        zip.finish().unwrap();
        let catalog = Catalog::acquire(&self.0).unwrap();
        let id = catalog
            .prepare(&ipa, phone.into(), "Phone".into(), account.into())
            .unwrap();
        let mut job = catalog.confirm(&id, "TEAM", None).unwrap();
        job.launch_confirmed = true;
        job.enabled = true;
        job.pilot_enabled = true;
        job.iphone = renewal::DeviceEvidence {
            profile_expiry: Some(expiry),
            last_success: Some(0),
            last_attempt: Some(0),
            outcome: renewal::Outcome::Installed,
        };
        catalog.save_job(&id, &job).unwrap();
        id
    }
    fn job(&self, id: &str) -> renewal::Enrollment {
        Catalog::acquire(&self.0).unwrap().job(id).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
struct Time(Arc<AtomicI64>);
impl Clock for Time {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}
struct External {
    calls: Arc<Mutex<Vec<&'static str>>>,
    failure: Arc<Mutex<Option<Failure>>>,
    time: Arc<AtomicI64>,
    observer: Option<renewal::session_diagnostic::Observer>,
}
impl Backend for External {
    type Signed = ();
    fn observe_session(&mut self, observer: renewal::session_diagnostic::Observer) {
        self.observer = Some(observer);
    }
    async fn prepare(&mut self, _: &renewal::Enrollment) -> Result<(), Failure> {
        self.calls.lock().unwrap().push("archive");
        Ok(())
    }
    async fn discover(&mut self, _: &str, _: Option<&str>) -> Result<(), Failure> {
        self.calls.lock().unwrap().push("discover");
        match self.failure.lock().unwrap().clone() {
            Some(f @ (Failure::Offline | Failure::DeviceLocked)) => Err(f),
            _ => Ok(()),
        }
    }
    async fn session(&mut self, _: &str) -> Result<(), Failure> {
        self.calls.lock().unwrap().push("session");
        if let Some(observer) = &mut self.observer {
            observer(renewal::session_diagnostic::Diagnostic {
                stage: renewal::session_diagnostic::Stage::InitialAuthentication,
                cause: Some(renewal::session_diagnostic::Cause::RateLimited),
                credential_read_succeeded: true,
                auth_started: true,
                http_status: Some(429),
            })
            .map_err(|_| Failure::Interrupted)?;
        }
        match self.failure.lock().unwrap().clone() {
            Some(
                f @ (Failure::MfaRequired
                | Failure::RateLimited
                | Failure::MissingCredentials
                | Failure::AccountSessionFailed),
            ) => Err(f),
            _ => Ok(()),
        }
    }
    async fn sign(&mut self, _: &renewal::Enrollment) -> Result<(), Failure> {
        self.calls.lock().unwrap().push("sign");
        Ok(())
    }
    async fn install_iphone(&mut self, _: &()) -> Result<Option<i64>, Failure> {
        self.calls.lock().unwrap().push("install");
        if self.failure.lock().unwrap().as_ref() == Some(&Failure::Installation) {
            return Err(Failure::Installation);
        }
        Ok(Some(self.time.load(Ordering::SeqCst) + 7 * renewal::DAY))
    }
    async fn install_watch(&mut self, _: &()) -> Result<Option<i64>, Failure> {
        panic!("phone-only host must never install Watch")
    }
}
struct RealPort {
    directory: PathBuf,
    external: External,
    checks: tokio::sync::mpsc::UnboundedSender<()>,
}
impl Port for RealPort {
    fn jobs(&mut self) -> Result<Vec<String>, String> {
        let ids = background_jobs(&self.directory, self.external.time.load(Ordering::SeqCst))?;
        self.checks.send(()).unwrap();
        Ok(ids)
    }
    async fn attempt(&mut self, id: &str) -> Result<(), String> {
        let mut journal = renewal::journal::FileJournal::acquire(&self.directory, id)?;
        let time = Time(self.external.time.clone());
        renewal::run_phone_host(
            &mut self.external,
            &mut journal,
            &time,
            renewal::Trigger::Background,
        )
        .await?;
        Ok(())
    }
    fn running(&mut self, _: bool) {}
}
async fn tick(wake: &Notify, checks: &mut tokio::sync::mpsc::UnboundedReceiver<()>) {
    wake.notify_one();
    tokio::time::timeout(Duration::from_secs(1), checks.recv())
        .await
        .unwrap()
        .unwrap();
    tokio::task::yield_now().await;
}
async fn actual_loop_checks_locally_then_boundary_offline_backoff_wakes_and_restart_without_burst()
{
    let fixture = Fixture::new();
    let id = fixture.enrollment("phone", "a@example.invalid", 4 * renewal::DAY);
    let time = Arc::new(AtomicI64::new(0));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let failure = Arc::new(Mutex::new(None));
    let (checks_tx, mut checks) = tokio::sync::mpsc::unbounded_channel();
    let mut port = RealPort {
        directory: fixture.0.clone(),
        external: External {
            calls: calls.clone(),
            failure: failure.clone(),
            time: time.clone(),
            observer: None,
        },
        checks: checks_tx,
    };
    let (control, receiver) = watch::channel(Control {
        active: true,
        stop: false,
    });
    let wake = Arc::new(Notify::new());
    let running_wake = wake.clone();
    let task =
        tokio::task::spawn_local(
            async move { worker(&mut port, receiver, running_wake, true).await },
        );
    checks.recv().await.unwrap();
    tokio::task::yield_now().await;
    assert!(calls.lock().unwrap().is_empty());
    assert_eq!(fixture.job(&id).next_attempt, renewal::DAY);
    for now in [1, renewal::DAY - 1, -100] {
        time.store(now, Ordering::SeqCst);
        tick(&wake, &mut checks).await;
    }
    assert!(
        calls.lock().unwrap().is_empty(),
        "duplicate wakes and backwards clock cannot authenticate"
    );
    *failure.lock().unwrap() = Some(Failure::Offline);
    time.store(renewal::DAY, Ordering::SeqCst);
    tick(&wake, &mut checks).await;
    assert_eq!(*calls.lock().unwrap(), ["archive", "discover"]);
    let mut next = renewal::DAY;
    for delay in [900, 1800, 3600, 7200, 14400, 21600, 21600] {
        assert_eq!(fixture.job(&id).next_attempt, next + delay);
        next += delay;
        calls.lock().unwrap().clear();
        time.store(next - 1, Ordering::SeqCst);
        tick(&wake, &mut checks).await;
        assert!(calls.lock().unwrap().is_empty());
        time.store(next, Ordering::SeqCst);
        tick(&wake, &mut checks).await;
        assert_eq!(*calls.lock().unwrap(), ["archive", "discover"]);
    }
    *failure.lock().unwrap() = None;
    calls.lock().unwrap().clear();
    time.store(20 * renewal::DAY, Ordering::SeqCst);
    tick(&wake, &mut checks).await;
    assert_eq!(
        calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| **c == "install")
            .count(),
        1
    );
    assert!(
        fixture.job(&id).launch_confirmed,
        "automatic success retains initial owner acceptance"
    );
    tick(&wake, &mut checks).await;
    assert_eq!(
        calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| **c == "install")
            .count(),
        1
    );
    control.send_replace(Control {
        active: false,
        stop: true,
    });
    task.await.unwrap();
    let catalog = Catalog::acquire(&fixture.0).unwrap();
    let mut interrupted = catalog.job(&id).unwrap();
    interrupted.phase = Phase::Running;
    interrupted.attempt.as_mut().unwrap().stage = AttemptStage::InstallingPhone;
    catalog.save_job(&id, &interrupted).unwrap();
    assert!(
        catalog
            .background_jobs(30 * renewal::DAY)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        catalog.job(&id).unwrap().phase,
        Phase::NeedsAction(Failure::Interrupted)
    );
}
#[test]
fn open_host_loop_lifecycle_uses_real_state_without_live_services() {
    // Native non-Send account futures use the same current-thread runtime model.
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(tokio::task::LocalSet::new().run_until(actual_loop_body()));
}
async fn actual_loop_body() {
    actual_loop_checks_locally_then_boundary_offline_backoff_wakes_and_restart_without_burst()
        .await;
}

#[test]
fn account_stops_survive_restart_and_cannot_be_bypassed_by_another_enrollment() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            for failure in [
                Failure::RateLimited,
                Failure::MfaRequired,
                Failure::MissingCredentials,
                Failure::AccountSessionFailed,
            ] {
                let fixture = Fixture::new();
                let first = fixture.enrollment("a", "same@example.invalid", renewal::DAY);
                let second = fixture.enrollment("b", "SAME@example.invalid", renewal::DAY);
                let time = Arc::new(AtomicI64::new(100));
                let calls = Arc::new(Mutex::new(Vec::new()));
                let mut external = External {
                    calls: calls.clone(),
                    failure: Arc::new(Mutex::new(Some(failure.clone()))),
                    time: time.clone(),
                    observer: None,
                };
                let mut journal =
                    renewal::journal::FileJournal::acquire(&fixture.0, &first).unwrap();
                renewal::run_phone_host(
                    &mut external,
                    &mut journal,
                    &Time(time.clone()),
                    renewal::Trigger::Background,
                )
                .await
                .unwrap();
                let failed = journal.load().unwrap();
                assert_eq!(failed.last_failure, Some(failure.clone()));
                assert!(failed.attempt.unwrap().session.unwrap().auth_started);
                drop(journal);
                calls.lock().unwrap().clear();
                let catalog = Catalog::acquire(&fixture.0).unwrap();
                assert!(catalog.background_jobs(10000).unwrap().is_empty());
                assert!(catalog.enable_reviewed(&second, 100).is_err());
                // Older accepted success and removal of the failed setup cannot clear the persisted hold.
                catalog.accept_launch(&second, 100).unwrap();
                assert!(catalog.remove(&first).is_err());
                // External loss of the manifest still cannot erase the account stop.
                std::fs::remove_file(fixture.0.join("renewal").join(format!("{first}.json")))
                    .unwrap();
                drop(catalog);
                let mut journal =
                    renewal::journal::FileJournal::acquire(&fixture.0, &second).unwrap();
                assert_eq!(
                    renewal::run_phone_host(
                        &mut external,
                        &mut journal,
                        &Time(time),
                        renewal::Trigger::Background
                    )
                    .await
                    .unwrap(),
                    renewal::Decision::NeedsAction(failure)
                );
                assert!(calls.lock().unwrap().is_empty());
            }
        });
}
#[test]
fn fresh_phone_opt_in_and_proven_connectivity_recovery_use_actual_catalog_boundaries() {
    let fixture = Fixture::new();
    let id = fixture.enrollment("phone", "a@example.invalid", 10 * renewal::DAY);
    let catalog = Catalog::acquire(&fixture.0).unwrap();
    let mut job = catalog.job(&id).unwrap();
    job.pilot_enabled = false;
    catalog.save_job(&id, &job).unwrap();
    assert!(
        catalog.background_jobs(100).unwrap().is_empty(),
        "old enabled flag is insufficient"
    );
    catalog.enable_reviewed(&id, 100).unwrap();
    assert_eq!(catalog.job(&id).unwrap().next_attempt, 100 + renewal::DAY);
    let mut job = catalog.job(&id).unwrap();
    job.attempt = Some(renewal::Attempt {
        number: 1,
        manual: false,
        started_at: 200,
        stage: AttemptStage::Discovering,
        session: None,
    });
    job.fail(Failure::Offline, 200);
    let historical = job.failure_evidence.clone();
    catalog.save_job(&id, &job).unwrap();
    catalog.retry_connectivity(&id, 201).unwrap();
    let recovered = catalog.job(&id).unwrap();
    assert_eq!(recovered.next_attempt, 261);
    assert_eq!(recovered.failure_evidence, historical);
    assert!(recovered.launch_confirmed);
    assert_eq!(recovered.iphone, job.iphone);
    assert!(recovered.last_failure.is_none());
    for stage in [AttemptStage::Authenticating, AttemptStage::InstallingPhone] {
        job.attempt.as_mut().unwrap().stage = stage;
        job.fail(Failure::Offline, 300);
        catalog.save_job(&id, &job).unwrap();
        assert!(catalog.retry_connectivity(&id, 301).is_err());
    }
}

#[test]
fn dormant_host_preferences_cannot_enable_pilot_or_startup() {
    let fixture = Fixture::new();
    let directory = fixture.0.join("renewal-host");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("settings.json"), br#"{"optedIn":true,"paused":false,"startAtLogin":true,"anisetteUrl":"https://example.invalid"}"#).unwrap();
    let legacy = load_settings(&fixture.0).unwrap();
    assert!(!legacy.opted_in && legacy.paused && !legacy.start_at_login);
    let next = Settings {
        pilot_version: 1,
        opted_in: true,
        paused: true,
        start_at_login: false,
        anisette_url: "https://example.invalid".into(),
    };
    validate_settings(&next).unwrap();
    commit_settings(&next, true, |s| {
        write_atomic(&directory, "settings", &serde_json::to_vec(s).unwrap())
    })
    .unwrap();
    let restarted = load_settings(&fixture.0).unwrap();
    assert!(restarted.opted_in && restarted.paused && !restarted.start_at_login);
}
struct Pending {
    stage: AttemptStage,
    calls: Vec<AttemptStage>,
}
impl Pending {
    async fn external(&mut self, stage: AttemptStage) -> Result<(), Failure> {
        self.calls.push(stage);
        if stage == self.stage {
            std::future::pending::<()>().await;
        }
        Ok(())
    }
}
impl Backend for Pending {
    type Signed = ();
    fn operation_timeout(&self, _: AttemptStage) -> Duration {
        Duration::from_millis(2)
    }
    async fn prepare(&mut self, _: &renewal::Enrollment) -> Result<(), Failure> {
        self.external(AttemptStage::Preparing).await
    }
    async fn discover(&mut self, _: &str, _: Option<&str>) -> Result<(), Failure> {
        self.external(AttemptStage::Discovering).await
    }
    async fn session(&mut self, _: &str) -> Result<(), Failure> {
        self.external(AttemptStage::Authenticating).await
    }
    async fn sign(&mut self, _: &renewal::Enrollment) -> Result<(), Failure> {
        self.external(AttemptStage::Signing).await
    }
    async fn install_iphone(&mut self, _: &()) -> Result<Option<i64>, Failure> {
        self.external(AttemptStage::InstallingPhone).await?;
        Ok(Some(10 * renewal::DAY))
    }
    async fn install_watch(&mut self, _: &()) -> Result<Option<i64>, Failure> {
        panic!("Watch not permitted")
    }
}
#[tokio::test]
async fn every_owned_phase_timeout_is_durable_and_never_automatically_replayed() {
    let phases = [
        AttemptStage::Preparing,
        AttemptStage::Discovering,
        AttemptStage::Authenticating,
        AttemptStage::Signing,
        AttemptStage::InstallingPhone,
    ];
    for (index, stage) in phases.into_iter().enumerate() {
        let fixture = Fixture::new();
        let id = fixture.enrollment("phone", "a@example.invalid", renewal::DAY);
        let mut journal = renewal::journal::FileJournal::acquire(&fixture.0, &id).unwrap();
        let mut external = Pending {
            stage,
            calls: Vec::new(),
        };
        let time = Time(Arc::new(AtomicI64::new(100)));
        assert_eq!(
            renewal::run_phone_host(
                &mut external,
                &mut journal,
                &time,
                renewal::Trigger::Background
            )
            .await
            .unwrap(),
            renewal::Decision::NeedsAction(Failure::Interrupted)
        );
        assert_eq!(external.calls, phases[..=index]);
        let result = journal.load().unwrap();
        assert_eq!(result.phase, Phase::NeedsAction(Failure::Interrupted));
        assert_eq!(result.attempt.unwrap().stage, stage);
        external.calls.clear();
        assert!(
            renewal::run_phone_host(
                &mut external,
                &mut journal,
                &time,
                renewal::Trigger::Background
            )
            .await
            .is_ok()
                || !result.launch_confirmed
        );
        assert!(external.calls.is_empty());
    }
}

#[tokio::test]
async fn only_new_successful_manual_recovery_on_failed_app_and_owner_acceptance_lifts_account_stop()
{
    let fixture = Fixture::new();
    let id = fixture.enrollment("phone", "a@example.invalid", renewal::DAY);
    let time = Arc::new(AtomicI64::new(100));
    let mut external = External {
        calls: Arc::new(Mutex::new(Vec::new())),
        failure: Arc::new(Mutex::new(Some(Failure::RateLimited))),
        time: time.clone(),
        observer: None,
    };
    let mut journal = renewal::journal::FileJournal::acquire(&fixture.0, &id).unwrap();
    renewal::run_phone_host(
        &mut external,
        &mut journal,
        &Time(time.clone()),
        renewal::Trigger::Background,
    )
    .await
    .unwrap();
    assert!(
        renewal::journal::account_hold(journal.directory(), "A@example.invalid")
            .unwrap()
            .is_some()
    );
    // Explicit manual recovery uses the existing foreground command's state reset.
    let mut job = journal.load().unwrap();
    job.phase = Phase::Idle;
    job.last_failure = None;
    job.launch_confirmed = false;
    job.enabled = false;
    journal.save(&job).unwrap();
    *external.failure.lock().unwrap() = None;
    renewal::run(
        &mut external,
        &mut journal,
        &Time(time),
        renewal::Trigger::Manual,
    )
    .await
    .unwrap();
    assert!(
        renewal::journal::account_hold(journal.directory(), &job.account)
            .unwrap()
            .is_some()
    );
    drop(journal);
    let catalog = Catalog::acquire(&fixture.0).unwrap();
    catalog.accept_launch(&id, 101).unwrap();
    assert!(
        renewal::journal::account_hold(&fixture.0.join("renewal"), &job.account)
            .unwrap()
            .is_none()
    );
    catalog.enable_reviewed(&id, 101).unwrap();
}

#[test]
fn native_session_report_is_bound_to_current_running_attempt_and_survives_finish() {
    let fixture = Fixture::new();
    let id = fixture.enrollment("phone", "a@example.invalid", renewal::DAY);
    let mut journal = renewal::journal::FileJournal::acquire(&fixture.0, &id).unwrap();
    let mut job = journal.load().unwrap();
    job.phase = Phase::Running;
    job.attempt = Some(renewal::Attempt {
        number: 1,
        manual: false,
        started_at: 100,
        stage: AttemptStage::Authenticating,
        session: None,
    });
    journal.save(&job).unwrap();
    let mut observer = journal
        .session_observer(job.attempt.as_ref().unwrap())
        .unwrap();
    let report = renewal::session_diagnostic::Diagnostic::default();
    observer(report.clone()).unwrap();
    let mut reported = journal.load().unwrap();
    assert_eq!(reported.attempt.as_ref().unwrap().session, Some(report));
    reported.phase = Phase::NeedsAction(Failure::MfaRequired);
    reported.last_failure = Some(Failure::MfaRequired);
    journal.save(&reported).unwrap();
    assert!(observer(renewal::session_diagnostic::Diagnostic::default()).is_err());
    reported.phase = Phase::Running;
    reported.attempt.as_mut().unwrap().number = 2;
    journal.save(&reported).unwrap();
    assert!(observer(renewal::session_diagnostic::Diagnostic::default()).is_err());
}

#[test]
fn interrupted_legacy_auth_or_signing_cannot_authenticate_through_another_app() {
    for stage in [
        None,
        Some(AttemptStage::Authenticating),
        Some(AttemptStage::Signing),
    ] {
        let fixture = Fixture::new();
        let id = fixture.enrollment("a", "same@example.invalid", renewal::DAY);
        let other = fixture.enrollment("b", "same@example.invalid", renewal::DAY);
        let catalog = Catalog::acquire(&fixture.0).unwrap();
        let mut job = catalog.job(&id).unwrap();
        job.phase = Phase::Running;
        job.attempt = stage.map(|stage| renewal::Attempt {
            number: 1,
            manual: false,
            started_at: 1,
            stage,
            session: None,
        });
        catalog.save_job(&id, &job).unwrap();
        catalog.background_jobs(100).unwrap();
        assert!(catalog.enable_reviewed(&other, 100).is_err());
        assert!(catalog.background_jobs(100).unwrap().is_empty());
    }
}

#[test]
fn per_app_pause_persists_during_owned_install_and_drains_without_losing_outcome() {
    struct Installing {
        entered: Arc<Notify>,
        release: Arc<Notify>,
        calls: Arc<AtomicU64>,
    }
    impl Backend for Installing {
        type Signed = ();
        async fn prepare(&mut self, _: &renewal::Enrollment) -> Result<(), Failure> {
            Ok(())
        }
        async fn discover(&mut self, _: &str, _: Option<&str>) -> Result<(), Failure> {
            Ok(())
        }
        async fn session(&mut self, _: &str) -> Result<(), Failure> {
            Ok(())
        }
        async fn sign(&mut self, _: &renewal::Enrollment) -> Result<(), Failure> {
            Ok(())
        }
        async fn install_iphone(&mut self, _: &()) -> Result<Option<i64>, Failure> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.entered.notify_one();
            self.release.notified().await;
            Ok(Some(7 * renewal::DAY))
        }
        async fn install_watch(&mut self, _: &()) -> Result<Option<i64>, Failure> {
            panic!("phone only")
        }
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(tokio::task::LocalSet::new().run_until(async {
            let fixture = Fixture::new();
            let id = fixture.enrollment("phone", "a@example.invalid", renewal::DAY);
            let entered = Arc::new(Notify::new());
            let release = Arc::new(Notify::new());
            let calls = Arc::new(AtomicU64::new(0));
            let mut external = Installing {
                entered: entered.clone(),
                release: release.clone(),
                calls: calls.clone(),
            };
            let mut journal = renewal::journal::FileJournal::acquire(&fixture.0, &id).unwrap();
            let task = tokio::task::spawn_local(async move {
                renewal::run_phone_host(
                    &mut external,
                    &mut journal,
                    &Time(Arc::new(AtomicI64::new(100))),
                    renewal::Trigger::Background,
                )
                .await
            });
            entered.notified().await;
            let pause_result = renewal::management::pause_setup(&fixture.0, &id);
            let during =
                renewal::journal::read_enrollment(&fixture.0.join("renewal"), &id).unwrap();
            let still_owned = crate::install_lock::InstallLease::acquire(&fixture.0).is_err();
            release.notify_one();
            let completed = tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            // Settle the real operation even on RED, then assert the command result.
            assert!(
                pause_result.is_ok(),
                "Pause must persist while this installer owns the lease: {pause_result:?}"
            );
            assert!(still_owned && !during.enabled && during.phase == Phase::Running);
            assert_eq!(during.attempt.unwrap().stage, AttemptStage::InstallingPhone);
            assert_eq!(completed, renewal::Decision::Paused);
            let reloaded = fixture.job(&id);
            assert!(!reloaded.enabled && reloaded.launch_confirmed);
            assert_eq!(reloaded.iphone.outcome, renewal::Outcome::Installed);
            assert_eq!(reloaded.iphone.last_success, Some(100));
            assert_eq!(reloaded.attempt.unwrap().stage, AttemptStage::Complete);
            assert!(
                Catalog::acquire(&fixture.0)
                    .unwrap()
                    .background_jobs(10 * renewal::DAY)
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(calls.load(Ordering::Relaxed), 1);
        }));
}

#[test]
fn pause_remains_authoritative_after_stale_write_or_failed_resume_until_explicit_enable() {
    let fixture = Fixture::new();
    let id = fixture.enrollment("phone", "a@example.invalid", 10 * renewal::DAY);
    let catalog = Catalog::acquire(&fixture.0).unwrap();
    let stale = catalog.job(&id).unwrap();
    renewal::management::pause_setup(&fixture.0, &id).unwrap();
    // A pre-pause journal snapshot cannot undo independently persisted admission.
    catalog.save_job(&id, &stale).unwrap();
    assert!(!catalog.job(&id).unwrap().enabled);
    let directory = fixture.0.join("renewal");
    assert!(renewal::admission::resume(&directory, &id, || Err("Disk full".into())).is_err());
    assert!(renewal::admission::paused(&directory, &id).unwrap());
    assert!(catalog.background_jobs(100).unwrap().is_empty());
    catalog.enable_reviewed(&id, 100).unwrap();
    assert!(!renewal::admission::paused(&directory, &id).unwrap());
    let resumed = catalog.job(&id).unwrap();
    assert!(resumed.enabled);
    assert_eq!(resumed.iphone, stale.iphone);
    assert_eq!(resumed.next_attempt, 100 + renewal::DAY);
}

#[tokio::test]
async fn per_app_pause_after_selection_is_a_quiet_admission_stop() {
    let fixture = Fixture::new();
    let id = fixture.enrollment("phone", "a@example.invalid", renewal::DAY);
    assert_eq!(
        Catalog::acquire(&fixture.0)
            .unwrap()
            .background_jobs(100)
            .unwrap(),
        vec![id.clone()]
    );
    renewal::management::pause_setup(&fixture.0, &id).unwrap();
    let mut journal = renewal::journal::FileJournal::acquire(&fixture.0, &id).unwrap();
    let mut external = Pending {
        stage: AttemptStage::Preparing,
        calls: vec![],
    };
    assert_eq!(
        renewal::run_phone_host(
            &mut external,
            &mut journal,
            &Time(Arc::new(AtomicI64::new(100))),
            renewal::Trigger::Background
        )
        .await
        .unwrap(),
        renewal::Decision::Paused
    );
    assert!(external.calls.is_empty());
}

#[test]
fn locked_discovery_retries_across_host_restart_then_unlocks_once_without_auth_while_locked() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let fixture = Fixture::new();
            let id = fixture.enrollment("phone", "a@example.invalid", 3 * renewal::DAY);
            let time = Arc::new(AtomicI64::new(100));
            let calls = Arc::new(Mutex::new(Vec::new()));
            let failure = Arc::new(Mutex::new(Some(Failure::DeviceLocked)));
            for delay in [900, 1800, 3600, 7200, 14400, 21600, 21600] {
                // Recreate the host port, catalog and journal from disk on every wake.
                let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
                let mut port = RealPort {
                    directory: fixture.0.clone(),
                    external: External {
                        calls: calls.clone(),
                        failure: failure.clone(),
                        time: time.clone(),
                        observer: None,
                    },
                    checks: tx,
                };
                assert_eq!(port.jobs().unwrap(), vec![id.clone()]);
                port.attempt(&id).await.unwrap();
                let job = fixture.job(&id);
                assert_eq!(
                    job.phase,
                    Phase::Idle,
                    "locked discovery must wait rather than require owner recovery"
                );
                assert_eq!(job.next_attempt, time.load(Ordering::SeqCst) + delay);
                assert!(job.enabled && job.launch_confirmed);
                let view = Catalog::acquire(&fixture.0)
                    .unwrap()
                    .snapshot()
                    .unwrap()
                    .setups
                    .remove(0);
                assert!(view.can_retry_connectivity);
                assert_eq!(
                    view.next_attempt,
                    renewal::management::execution_available().then_some(job.next_attempt)
                );
                assert_eq!(view.paused, !renewal::management::execution_available());
                assert!(notice_key(&view).is_none());
                assert_eq!(*calls.lock().unwrap(), ["archive", "discover"]);
                calls.lock().unwrap().clear();
                assert!(
                    Catalog::acquire(&fixture.0)
                        .unwrap()
                        .background_jobs(job.next_attempt - 1)
                        .unwrap()
                        .is_empty()
                );
                time.store(job.next_attempt, Ordering::SeqCst);
            }
            renewal::management::pause_setup(&fixture.0, &id).unwrap();
            assert!(
                Catalog::acquire(&fixture.0)
                    .unwrap()
                    .background_jobs(time.load(Ordering::SeqCst))
                    .unwrap()
                    .is_empty()
            );
            assert!(!fixture.job(&id).enabled);
            assert!(calls.lock().unwrap().is_empty());
            let now = time.load(Ordering::SeqCst);
            Catalog::acquire(&fixture.0)
                .unwrap()
                .enable_reviewed(&id, now)
                .unwrap();
            time.store(fixture.job(&id).next_attempt, Ordering::SeqCst);
            *failure.lock().unwrap() = None;
            let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
            let mut port = RealPort {
                directory: fixture.0.clone(),
                external: External {
                    calls: calls.clone(),
                    failure: failure.clone(),
                    time: time.clone(),
                    observer: None,
                },
                checks: tx,
            };
            for job in port.jobs().unwrap() {
                port.attempt(&job).await.unwrap();
            }
            assert_eq!(
                *calls.lock().unwrap(),
                ["archive", "discover", "session", "sign", "install"]
            );
            assert!(port.jobs().unwrap().is_empty());
            assert_eq!(fixture.job(&id).last_failure, None);
            assert_eq!(fixture.job(&id).retry_count, 0);
        });
}

struct FailureAt {
    stage: AttemptStage,
    failure: Failure,
    calls: Vec<AttemptStage>,
}
impl FailureAt {
    fn call(&mut self, stage: AttemptStage) -> Result<(), Failure> {
        self.calls.push(stage);
        if self.stage == stage {
            Err(self.failure.clone())
        } else {
            Ok(())
        }
    }
}
impl Backend for FailureAt {
    type Signed = ();
    async fn prepare(&mut self, _: &renewal::Enrollment) -> Result<(), Failure> {
        self.call(AttemptStage::Preparing)
    }
    async fn discover(&mut self, _: &str, _: Option<&str>) -> Result<(), Failure> {
        self.call(AttemptStage::Discovering)
    }
    async fn session(&mut self, _: &str) -> Result<(), Failure> {
        self.call(AttemptStage::Authenticating)
    }
    async fn sign(&mut self, _: &renewal::Enrollment) -> Result<(), Failure> {
        self.call(AttemptStage::Signing)
    }
    async fn install_iphone(&mut self, _: &()) -> Result<Option<i64>, Failure> {
        self.call(AttemptStage::InstallingPhone)?;
        Ok(Some(10 * renewal::DAY))
    }
    async fn install_watch(&mut self, _: &()) -> Result<Option<i64>, Failure> {
        panic!("No Watch work")
    }
}
#[tokio::test]
async fn connectivity_failures_after_discovery_require_attention_and_never_replay() {
    for failure in [Failure::DeviceLocked, Failure::Offline] {
        for stage in [
            AttemptStage::Authenticating,
            AttemptStage::Signing,
            AttemptStage::InstallingPhone,
        ] {
            let fixture = Fixture::new();
            let id = fixture.enrollment("phone", "a@example.invalid", renewal::DAY);
            let mut external = FailureAt {
                stage,
                failure: failure.clone(),
                calls: vec![],
            };
            let mut journal = renewal::journal::FileJournal::acquire(&fixture.0, &id).unwrap();
            let decision = renewal::run_phone_host(
                &mut external,
                &mut journal,
                &Time(Arc::new(AtomicI64::new(100))),
                renewal::Trigger::Background,
            )
            .await
            .unwrap();
            assert_eq!(decision, renewal::Decision::NeedsAction(failure.clone()));
            drop(journal);
            let saved = fixture.job(&id);
            assert_eq!(saved.phase, Phase::NeedsAction(failure.clone()));
            assert_eq!(saved.attempt.unwrap().stage, stage);
            if stage == AttemptStage::InstallingPhone {
                assert!(!saved.launch_confirmed);
            }
            let catalog = Catalog::acquire(&fixture.0).unwrap();
            assert!(
                catalog
                    .background_jobs(100 * renewal::DAY)
                    .unwrap()
                    .is_empty()
            );
            let view = catalog.snapshot().unwrap().setups.remove(0);
            assert!(!view.can_retry_connectivity);
            assert!(view.next_attempt.is_none());
            assert_eq!(notice_key(&view).unwrap().0, format!("action:{failure:?}"));
            assert!(catalog.retry_connectivity(&id, 101).is_err());
            assert_eq!(external.calls.last(), Some(&stage));
        }
    }
}
#[test]
fn existing_locked_attention_records_are_not_migrated_or_admitted() {
    for stage in [
        None,
        Some(AttemptStage::Discovering),
        Some(AttemptStage::InstallingPhone),
    ] {
        let fixture = Fixture::new();
        let id = fixture.enrollment("phone", "a@example.invalid", renewal::DAY);
        let catalog = Catalog::acquire(&fixture.0).unwrap();
        let mut job = catalog.job(&id).unwrap();
        job.attempt = stage.map(|stage| renewal::Attempt {
            number: 1,
            manual: false,
            started_at: 100,
            stage,
            session: None,
        });
        job.fail(Failure::DeviceLocked, 100);
        // Reproduce the old persisted policy, including plausible discovery evidence.
        job.phase = Phase::NeedsAction(Failure::DeviceLocked);
        catalog.save_job(&id, &job).unwrap();
        drop(catalog);
        let before = std::fs::read(fixture.0.join("renewal").join(format!("{id}.json"))).unwrap();
        let catalog = Catalog::acquire(&fixture.0).unwrap();
        assert!(
            catalog
                .background_jobs(100 * renewal::DAY)
                .unwrap()
                .is_empty()
        );
        let view = catalog.snapshot().unwrap().setups.remove(0);
        assert!(!view.can_retry_connectivity);
        assert_eq!(notice_key(&view).unwrap().0, "action:DeviceLocked");
        assert!(catalog.retry_connectivity(&id, 200).is_err());
        assert_eq!(
            before,
            std::fs::read(fixture.0.join("renewal").join(format!("{id}.json"))).unwrap()
        );
    }
}

#[tokio::test]
async fn obsolete_pilot_state_cannot_block_or_replay_production_jobs() {
    for contents in [
        b"malformed historical pilot state".as_slice(),
        br#"{"version":3,"state":"Scheduled","dueAt":0,"mode":"Host"}"#.as_slice(),
    ] {
        let fixture = Fixture::new();
        let id = fixture.enrollment("phone", "a@example.invalid", renewal::DAY);
        let legacy = fixture.0.join("renewal-one-shot");
        std::fs::create_dir_all(&legacy).unwrap();
        let request = legacy.join("request.json");
        std::fs::write(&request, contents).unwrap();
        // A stale pilot owner must not be part of production job admission.
        let _old_owner = crate::install_lock::InstallLease::acquire_service(&legacy).unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let time = Arc::new(AtomicI64::new(100));
        let (checks, _receiver) = tokio::sync::mpsc::unbounded_channel();
        let mut port = RealPort {
            directory: fixture.0.clone(),
            external: External {
                calls: calls.clone(),
                failure: Arc::new(Mutex::new(None)),
                time,
                observer: None,
            },
            checks,
        };
        assert_eq!(port.jobs().unwrap(), vec![id.clone()]);
        port.attempt(&id).await.unwrap();
        assert_eq!(
            *calls.lock().unwrap(),
            ["archive", "discover", "session", "sign", "install"]
        );
        assert!(fixture.job(&id).next_attempt > 100);
        assert!(port.jobs().unwrap().is_empty());
        assert_eq!(std::fs::read(&request).unwrap(), contents);
    }
}
