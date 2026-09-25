use super::*;

fn job() -> Enrollment {
    let evidence = DeviceEvidence {
        profile_expiry: Some(2 * DAY),
        last_success: Some(0),
        last_attempt: Some(0),
        outcome: Outcome::Installed,
    };
    Enrollment {
        product: Default::default(),
        pilot_enabled: false,
        attempt: None,
        failure_evidence: None,
        version: 1,
        archive: archive::ArchiveIdentity {
            sha256: "a".repeat(64),
            bundles: vec![("Payload/Test.app/Info.plist".into(), "test.app".into())],
            has_watch: true,
        },
        account: "test@example.invalid".into(),
        team_id: "test-team".into(),
        phone_id: "test-phone".into(),
        watch_id: Some("test-watch".into()),
        enabled: true,
        launch_confirmed: true,
        iphone: evidence.clone(),
        watch: Some(evidence),
        phase: Phase::Idle,
        next_attempt: 0,
        retry_count: 0,
        last_checked: None,
        last_failure: None,
    }
}

#[test]
fn persisted_enable_flag_requires_explicit_launch_confirmation() {
    let mut job = job();
    job.launch_confirmed = false;
    assert_eq!(
        job.decision(0, Trigger::Background),
        Decision::NeedsAction(Failure::LaunchConfirmationRequired)
    );
    assert!(matches!(
        job.decision(0, Trigger::Manual),
        Decision::Renew { .. }
    ));
}

struct TestClock(i64);
impl Clock for TestClock {
    fn now(&self) -> i64 {
        self.0
    }
}

struct MemoryJournal {
    job: Enrollment,
    saves: usize,
    fail_at: Option<usize>,
    fail_stage: Option<AttemptStage>,
}
impl MemoryJournal {
    fn new(job: Enrollment) -> Self {
        Self {
            job,
            saves: 0,
            fail_at: None,
            fail_stage: None,
        }
    }
}
impl Journal for MemoryJournal {
    fn load(&mut self) -> Result<Enrollment, String> {
        Ok(self.job.clone())
    }
    fn save(&mut self, job: &Enrollment) -> Result<(), String> {
        self.saves += 1;
        if self.fail_at == Some(self.saves)
            || self
                .fail_stage
                .is_some_and(|stage| job.attempt.as_ref().is_some_and(|a| a.stage == stage))
        {
            return Err("Disk unavailable".into());
        }
        self.job = job.clone();
        Ok(())
    }
}

#[derive(Default)]
struct MockBackend {
    failure: Option<Failure>,
    watch_failure: bool,
    calls: Vec<&'static str>,
}
impl Backend for MockBackend {
    type Signed = ();
    async fn prepare(&mut self, _: &Enrollment) -> Result<(), Failure> {
        self.calls.push("archive");
        match &self.failure {
            Some(Failure::ArchiveMissing | Failure::ArchiveChanged) => {
                Err(self.failure.clone().unwrap())
            }
            _ => Ok(()),
        }
    }
    async fn discover(&mut self, _: &str, _: Option<&str>) -> Result<(), Failure> {
        self.calls.push("discover");
        match &self.failure {
            Some(Failure::Offline | Failure::WrongDevice) => Err(self.failure.clone().unwrap()),
            _ => Ok(()),
        }
    }
    async fn session(&mut self, _: &str) -> Result<(), Failure> {
        self.calls.push("session");
        match &self.failure {
            Some(Failure::MissingCredentials | Failure::MfaRequired | Failure::RateLimited) => {
                Err(self.failure.clone().unwrap())
            }
            _ => Ok(()),
        }
    }
    async fn sign(&mut self, _: &Enrollment) -> Result<(), Failure> {
        self.calls.push("sign");
        Ok(())
    }
    async fn install_iphone(&mut self, _: &()) -> Result<Option<i64>, Failure> {
        self.calls.push("iphone");
        Ok(Some(7 * DAY))
    }
    async fn install_watch(&mut self, _: &()) -> Result<Option<i64>, Failure> {
        self.calls.push("watch");
        if self.watch_failure {
            Err(Failure::Installation)
        } else {
            Ok(Some(6 * DAY))
        }
    }
}

#[test]
fn policy_uses_each_actual_expiry_and_requires_complete_evidence() {
    let mut job = job();
    job.iphone.profile_expiry = Some(7 * DAY);
    assert_eq!(
        job.decision(0, Trigger::Background),
        Decision::Renew {
            iphone: false,
            watch: true
        }
    );
    job.watch.as_mut().unwrap().profile_expiry = Some(6 * DAY);
    assert_eq!(
        job.decision(0, Trigger::Background),
        Decision::WaitUntil(DAY)
    );
    assert_eq!(
        job.decision(3 * DAY, Trigger::Background),
        Decision::Renew {
            iphone: false,
            watch: true
        }
    );
    job.watch.as_mut().unwrap().profile_expiry = None;
    assert_eq!(
        job.decision(0, Trigger::Background),
        Decision::NeedsAction(Failure::UnknownExpiry)
    );
    assert_eq!(
        job.decision(0, Trigger::Manual),
        Decision::Renew {
            iphone: true,
            watch: true
        }
    );
}

#[tokio::test]
async fn paused_or_not_yet_due_jobs_do_not_touch_account_or_devices() {
    let mut backend = MockBackend::default();
    let mut state = job();
    state.enabled = false;
    let mut store = MemoryJournal::new(state);
    assert_eq!(
        run(&mut backend, &mut store, &TestClock(0), Trigger::Background)
            .await
            .unwrap(),
        Decision::Paused
    );
    store.job.enabled = true;
    store.job.next_attempt = DAY;
    assert_eq!(
        run(&mut backend, &mut store, &TestClock(0), Trigger::Background)
            .await
            .unwrap(),
        Decision::WaitUntil(DAY)
    );
    assert!(backend.calls.is_empty());
}

#[tokio::test]
async fn wrong_device_never_reaches_authentication_or_installation() {
    let mut backend = MockBackend {
        failure: Some(Failure::WrongDevice),
        ..Default::default()
    };
    let mut store = MemoryJournal::new(job());
    assert_eq!(
        run(&mut backend, &mut store, &TestClock(0), Trigger::Background)
            .await
            .unwrap(),
        Decision::NeedsAction(Failure::WrongDevice)
    );
    assert_eq!(backend.calls, vec!["archive", "discover"]);
}

#[tokio::test]
async fn submitted_install_failure_preserves_success_and_requires_review_without_retry() {
    let mut backend = MockBackend {
        watch_failure: true,
        ..Default::default()
    };
    let mut store = MemoryJournal::new(job());
    let result = run(&mut backend, &mut store, &TestClock(0), Trigger::Background)
        .await
        .unwrap();
    assert_eq!(result, Decision::NeedsAction(Failure::Installation));
    assert_eq!(store.job.iphone.profile_expiry, Some(7 * DAY));
    assert_eq!(
        store.job.watch.as_ref().unwrap().profile_expiry,
        Some(2 * DAY)
    );
    assert_eq!(
        store.job.watch.as_ref().unwrap().outcome,
        Outcome::Failed(Failure::Installation)
    );
    backend.calls.clear();
    backend.watch_failure = false;
    run(
        &mut backend,
        &mut store,
        &TestClock(900),
        Trigger::Background,
    )
    .await
    .unwrap();
    assert!(!backend.calls.contains(&"iphone"));
    assert!(
        backend.calls.is_empty(),
        "a submitted install must not retry automatically"
    );
    assert_eq!(
        store.job.watch.as_ref().unwrap().profile_expiry,
        Some(2 * DAY)
    );
    assert_eq!(store.job.iphone.last_success, Some(0));
}

#[tokio::test]
async fn auth_and_archive_failures_stop_until_foreground_action() {
    for failure in [
        Failure::MissingCredentials,
        Failure::MfaRequired,
        Failure::RateLimited,
        Failure::ArchiveMissing,
        Failure::ArchiveChanged,
    ] {
        let mut backend = MockBackend {
            failure: Some(failure.clone()),
            ..Default::default()
        };
        let mut store = MemoryJournal::new(job());
        assert_eq!(
            run(&mut backend, &mut store, &TestClock(0), Trigger::Background)
                .await
                .unwrap(),
            Decision::NeedsAction(failure)
        );
        backend.calls.clear();
        run(
            &mut backend,
            &mut store,
            &TestClock(10 * DAY),
            Trigger::Manual,
        )
        .await
        .unwrap();
        assert!(backend.calls.is_empty());
        assert_eq!(store.job.iphone.last_success, Some(0));
    }
}

#[tokio::test]
async fn offline_backoff_is_bounded_and_sleep_catches_up_without_burst() {
    let mut backend = MockBackend {
        failure: Some(Failure::Offline),
        ..Default::default()
    };
    let mut store = MemoryJournal::new(job());
    let mut clock = TestClock(0);
    for _ in 0..12 {
        run(&mut backend, &mut store, &clock, Trigger::Background)
            .await
            .unwrap();
        let delay = store.job.next_attempt - clock.0;
        assert!((900..=21600).contains(&delay));
        assert!(!backend.calls.contains(&"session"));
        clock.0 = store.job.next_attempt;
    }
    clock.0 += 10 * DAY;
    backend.calls.clear();
    backend.failure = None;
    run(&mut backend, &mut store, &clock, Trigger::Background)
        .await
        .unwrap();
    assert_eq!(
        backend
            .calls
            .iter()
            .filter(|call| **call == "iphone")
            .count(),
        1
    );
}

#[tokio::test]
async fn restart_with_running_journal_requires_reconciliation_not_replay() {
    let mut state = job();
    state.phase = Phase::Running;
    let mut store = MemoryJournal::new(state);
    let mut backend = MockBackend::default();
    assert_eq!(
        run(&mut backend, &mut store, &TestClock(0), Trigger::Background)
            .await
            .unwrap(),
        Decision::NeedsAction(Failure::Interrupted)
    );
    assert_eq!(store.job.phase, Phase::NeedsAction(Failure::Interrupted));
    assert!(backend.calls.is_empty());
}

#[tokio::test]
async fn failed_durable_checkpoint_prevents_next_install() {
    let mut store = MemoryJournal::new(job());
    store.fail_stage = Some(AttemptStage::InstallingWatch);
    let mut backend = MockBackend::default();
    assert!(
        run(&mut backend, &mut store, &TestClock(0), Trigger::Background)
            .await
            .is_err()
    );
    assert!(backend.calls.contains(&"iphone"));
    assert!(!backend.calls.contains(&"watch"));
    assert_eq!(store.job.phase, Phase::Running);
}

#[test]
fn file_journal_replaces_atomically_and_excludes_manual_install() {
    let root = std::env::temp_dir().join(format!("iloader-journal-test-{}", std::process::id()));
    let mut journal = journal::FileJournal::acquire(&root, "test").unwrap();
    assert!(crate::install_lock::InstallLease::acquire(&root).is_err());
    journal.save(&job()).unwrap();
    let mut changed = job();
    changed.phase = Phase::Running;
    journal.save(&changed).unwrap();
    assert_eq!(journal.load().unwrap(), changed);
    drop(journal);
    let mut journal = journal::FileJournal::acquire(&root, "test").unwrap();
    assert_eq!(journal.load().unwrap().phase, Phase::Running);
    drop(journal);
    std::fs::remove_file(root.join("renewal/test.json")).unwrap();
    std::fs::remove_dir(root.join("renewal")).unwrap();
    std::fs::remove_file(root.join("install.lock")).unwrap();
    std::fs::remove_dir(root).unwrap();
}

#[test]
fn explicit_automatic_authorization_never_forges_human_launch_acceptance() {
    let mut job = job();
    job.launch_confirmed = false;
    job.product.authorization = Some(product::Authorization {
        consent_at: 0,
        archive_sha256: job.archive.sha256.clone(),
        validated_attempt: Some(1),
    });
    assert!(product::authorized(&job));
    assert!(!job.launch_confirmed);
    job.product
        .authorization
        .as_mut()
        .unwrap()
        .validated_attempt = None;
    assert!(!product::authorized(&job));
    job.product
        .authorization
        .as_mut()
        .unwrap()
        .validated_attempt = Some(1);
    job.archive.sha256 = "b".repeat(64);
    assert!(!product::authorized(&job));
}
