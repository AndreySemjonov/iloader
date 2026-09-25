use super::super::{
    DAY, Outcome,
    session_diagnostic::{Diagnostic, Observer, Stage},
};
use super::*;
use std::{
    io::Write,
    sync::{
        Arc, Mutex,
        atomic::{AtomicI64, AtomicU64, Ordering},
    },
};
static SEQ: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "product-renewal-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
    fn ipa(&self, bundle: &str, revision: u32) -> PathBuf {
        let p = self.0.join(format!("{bundle}-{revision}.ipa"));
        let mut zip = zip::ZipWriter::new(std::fs::File::create(&p).unwrap());
        zip.start_file(
            "Payload/Test.app/Info.plist",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        write!(zip, "<plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>{bundle}</string><key>CFBundleDisplayName</key><string>App {bundle}</string><key>CFBundleVersion</key><string>{revision}</string></dict></plist>").unwrap();
        zip.finish().unwrap();
        p
    }
    fn job(&self, id: &str) -> Enrollment {
        Catalog::acquire(&self.0).unwrap().job(id).unwrap()
    }
    fn bytes(&self, id: &str) -> Vec<u8> {
        std::fs::read(self.0.join("renewal").join(format!("{id}.json"))).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
#[derive(Clone)]
struct Time(Arc<AtomicI64>);
impl Clock for Time {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}
struct External {
    root: PathBuf,
    time: Time,
    calls: Arc<Mutex<Vec<String>>>,
    observer: Option<Observer>,
    bundle: String,
    failure: Option<Failure>,
    ready: bool,
    unknown_expiry: bool,
    block_after_reply: bool,
}
impl Backend for External {
    type Signed = ();
    fn observe_session(&mut self, observer: Observer) {
        self.observer = Some(observer);
    }
    async fn prepare(&mut self, job: &Enrollment) -> Result<(), Failure> {
        assert!(
            Catalog::acquire(&self.root).is_err(),
            "Command and engine must keep the install lease"
        );
        job.archive.verify(&self.root.join("renewal"))?;
        self.bundle = management::main_bundle(&job.archive).unwrap().into();
        Ok(())
    }
    async fn discover(&mut self, _: &str, _: Option<&str>) -> Result<(), Failure> {
        if let Some(f @ (Failure::Offline | Failure::DeviceLocked)) = &self.failure {
            return Err(f.clone());
        }
        Ok(())
    }
    async fn session(&mut self, _: &str) -> Result<(), Failure> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("auth:{}", self.bundle));
        if let Some(
            f @ (Failure::MfaRequired | Failure::RateLimited | Failure::AccountSessionFailed),
        ) = &self.failure
        {
            return Err(f.clone());
        }
        self.observer.as_mut().unwrap()(Diagnostic {
            stage: Stage::Ready,
            cause: None,
            credential_read_succeeded: self.ready,
            auth_started: true,
            http_status: None,
        })
        .map_err(|_| Failure::Interrupted)?;
        Ok(())
    }
    async fn sign(&mut self, _: &Enrollment) -> Result<(), Failure> {
        Ok(())
    }
    async fn install_iphone(&mut self, _: &()) -> Result<Option<i64>, Failure> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("install:{}", self.bundle));
        if self.failure == Some(Failure::Installation) {
            return Err(Failure::Installation);
        }
        if self.block_after_reply {
            std::fs::create_dir(self.root.join("renewal").join(format!(
                "{}.pending",
                management::identity("same-phone", &self.bundle)
            )))
            .unwrap();
        }
        Ok((!self.unknown_expiry).then(|| self.time.now() + 7 * DAY))
    }
    async fn install_watch(&mut self, _: &()) -> Result<Option<i64>, Failure> {
        panic!("No Watch work")
    }
}
struct Runtime {
    engine: External,
    team_failure: Option<Failure>,
    team_calls: usize,
    host_failure: bool,
    block_commit: bool,
}
impl Services for Runtime {
    type Engine = External;
    fn engine(&mut self) -> &mut External {
        &mut self.engine
    }
    async fn selected_team(&mut self, _: &str) -> Result<String, Failure> {
        self.team_calls += 1;
        match &self.team_failure {
            Some(f) => Err(f.clone()),
            None => Ok("TEAM".into()),
        }
    }
    fn authorize_host_first_use(&mut self) -> Result<(), String> {
        if self.block_commit {
            std::fs::create_dir(self.engine.root.join("renewal").join(format!(
                "{}.pending",
                management::identity("same-phone", &self.engine.bundle)
            )))
            .unwrap();
        }
        if self.host_failure {
            Err("Disk full".into())
        } else {
            Ok(())
        }
    }
}
fn runtime(f: &Fixture) -> (Runtime, Time) {
    let time = Time(Arc::new(AtomicI64::new(100)));
    (
        Runtime {
            engine: External {
                root: f.0.clone(),
                time: time.clone(),
                calls: Default::default(),
                observer: None,
                bundle: String::new(),
                failure: None,
                ready: true,
                unknown_expiry: false,
                block_after_reply: false,
            },
            team_failure: None,
            team_calls: 0,
            host_failure: false,
            block_commit: false,
        },
        time,
    )
}
fn install(source: PathBuf) -> Action {
    Action::Install {
        source,
        phone: "same-phone".into(),
        name: "Phone".into(),
        account: "same@example.invalid".into(),
    }
}

#[tokio::test]
async fn two_different_apps_same_phone_account_install_and_repeat_due_serially_without_human_flags()
{
    let f = Fixture::new();
    let (mut rt, time) = runtime(&f);
    let a = execute(&f.0, &mut rt, &time, install(f.ipa("app.a", 1)))
        .await
        .unwrap();
    let b = execute(&f.0, &mut rt, &time, install(f.ipa("app.b", 1)))
        .await
        .unwrap();
    assert_ne!(a.id, b.id);
    assert!(a.enabled && b.enabled);
    for id in [&a.id, &b.id] {
        let j = f.job(id);
        assert!(!j.launch_confirmed);
        assert!(authorized(&j));
    }
    for days in [4, 8] {
        time.0.store(100 + days * DAY, Ordering::SeqCst);
        let ids = Catalog::acquire(&f.0)
            .unwrap()
            .background_jobs(time.now())
            .unwrap();
        assert_eq!(ids.len(), 2);
        for id in ids {
            let mut owned = FileJournal::acquire(&f.0, &id).unwrap();
            super::super::run_phone_host(&mut rt.engine, &mut owned, &time, Trigger::Background)
                .await
                .unwrap();
        }
    }
    let calls = rt.engine.calls.lock().unwrap();
    assert_eq!(
        calls.iter().filter(|x| x.starts_with("install:")).count(),
        6
    );
    assert!(
        calls
            .chunks(2)
            .all(|pair| pair[0].strip_prefix("auth:") == pair[1].strip_prefix("install:"))
    );
    for id in [&a.id, &b.id] {
        let j = f.job(id);
        assert!(j.enabled && authorized(&j));
        assert!(!j.launch_confirmed);
    }
}

#[tokio::test]
async fn identical_reselect_and_other_app_pause_replace_remove_preserve_independent_state() {
    let f = Fixture::new();
    let (mut rt, time) = runtime(&f);
    let source_a = f.ipa("app.a", 1);
    let source_b = f.ipa("app.b", 1);
    let a = execute(&f.0, &mut rt, &time, install(source_a.clone()))
        .await
        .unwrap();
    let b = execute(&f.0, &mut rt, &time, install(source_b.clone()))
        .await
        .unwrap();
    management::pause_setup(&f.0, &a.id).unwrap();
    let before_a = f.bytes(&a.id);
    let before_b = f.bytes(&b.id);
    let calls = rt.engine.calls.lock().unwrap().len();
    assert!(
        execute(&f.0, &mut rt, &time, install(source_a.clone()))
            .await
            .unwrap()
            .reused
    );
    assert_eq!(f.bytes(&a.id), before_a);
    assert_eq!(rt.engine.calls.lock().unwrap().len(), calls);
    let update = f.ipa("app.a", 2);
    assert!(
        execute(&f.0, &mut rt, &time, install(update.clone()))
            .await
            .unwrap_err()
            .contains("Replace IPA")
    );
    let old = f.job(&a.id).archive;
    let result = execute(
        &f.0,
        &mut rt,
        &time,
        Action::Replace {
            id: a.id.clone(),
            source: update,
        },
    )
    .await
    .unwrap();
    assert!(!result.enabled);
    assert_ne!(f.job(&a.id).archive, old);
    assert!(old.verify(&f.0.join("renewal")).is_ok());
    assert_eq!(f.bytes(&b.id), before_b);
    Catalog::acquire(&f.0).unwrap().remove(&a.id).unwrap();
    assert!(source_a.exists() && source_b.exists());
    assert_eq!(f.bytes(&b.id), before_b);
}

#[tokio::test]
async fn completed_pending_install_survives_host_scan_and_resume_without_install_replay() {
    let f = Fixture::new();
    let (mut rt, time) = runtime(&f);
    rt.host_failure = true;
    let source = f.ipa("app.a", 1);
    assert!(
        execute(&f.0, &mut rt, &time, install(source))
            .await
            .is_err()
    );
    let id = management::identity("same-phone", "app.a");
    let pending = f.job(&id);
    assert!(!pending.enabled);
    assert_eq!(
        pending
            .product
            .pending
            .as_ref()
            .unwrap()
            .candidate
            .attempt
            .as_ref()
            .unwrap()
            .stage,
        AttemptStage::Complete
    );
    let bytes = f.bytes(&id);
    for now in [101, 102, 103] {
        assert!(
            Catalog::acquire(&f.0)
                .unwrap()
                .background_jobs(now)
                .unwrap()
                .is_empty()
        );
        assert_eq!(f.bytes(&id), bytes);
    }
    let calls = rt.engine.calls.lock().unwrap().len();
    rt.host_failure = false;
    assert!(
        execute(&f.0, &mut rt, &time, Action::Resume { id: id.clone() })
            .await
            .unwrap()
            .enabled
    );
    assert_eq!(rt.engine.calls.lock().unwrap().len(), calls);
    assert!(f.job(&id).product.pending.is_none());
    assert!(!f.job(&id).launch_confirmed);
}

#[tokio::test]
async fn failed_replacement_keeps_old_archive_history_and_blocks_automatic_replay() {
    let f = Fixture::new();
    let (mut rt, time) = runtime(&f);
    let a = execute(&f.0, &mut rt, &time, install(f.ipa("app.a", 1)))
        .await
        .unwrap();
    let old = f.job(&a.id);
    rt.engine.failure = Some(Failure::Installation);
    assert!(
        execute(
            &f.0,
            &mut rt,
            &time,
            Action::Replace {
                id: a.id.clone(),
                source: f.ipa("app.a", 2)
            }
        )
        .await
        .is_err()
    );
    let failed = f.job(&a.id);
    assert_eq!(failed.archive, old.archive);
    assert_eq!(failed.iphone, old.iphone);
    assert_eq!(failed.last_failure, Some(Failure::Installation));
    assert!(matches!(
        failed
            .product
            .pending
            .as_ref()
            .unwrap()
            .candidate
            .iphone
            .outcome,
        Outcome::Failed(_)
    ));
    let bytes = f.bytes(&a.id);
    assert!(
        Catalog::acquire(&f.0)
            .unwrap()
            .background_jobs(20 * DAY)
            .unwrap()
            .is_empty()
    );
    assert_eq!(f.bytes(&a.id), bytes);
    assert!(old.archive.verify(&f.0.join("renewal")).is_ok());
}

#[tokio::test]
async fn team_lookup_account_stop_blocks_a_second_app_before_any_account_request() {
    for failure in [
        Failure::RateLimited,
        Failure::AccountSessionFailed,
        Failure::Interrupted,
    ] {
        let f = Fixture::new();
        let (mut rt, time) = runtime(&f);
        rt.team_failure = Some(failure.clone());
        assert!(
            execute(&f.0, &mut rt, &time, install(f.ipa("app.a", 1)))
                .await
                .is_err()
        );
        assert_eq!(
            journal::account_hold(&f.0.join("renewal"), "same@example.invalid")
                .unwrap()
                .unwrap()
                .failure,
            failure
        );
        assert!(
            execute(&f.0, &mut rt, &time, install(f.ipa("app.b", 1)))
                .await
                .is_err()
        );
        assert_eq!(rt.team_calls, 1);
        assert!(rt.engine.calls.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn only_failing_app_explicit_recovery_can_clear_shared_account_stop() {
    for failure in [
        Failure::MfaRequired,
        Failure::RateLimited,
        Failure::AccountSessionFailed,
    ] {
        let f = Fixture::new();
        let (mut rt, time) = runtime(&f);
        let a = execute(&f.0, &mut rt, &time, install(f.ipa("app.a", 1)))
            .await
            .unwrap();
        let b = execute(&f.0, &mut rt, &time, install(f.ipa("app.b", 1)))
            .await
            .unwrap();
        rt.engine.failure = Some(failure);
        assert!(
            execute(&f.0, &mut rt, &time, Action::Renew { id: a.id.clone() })
                .await
                .is_err()
        );
        let calls = rt.engine.calls.lock().unwrap().len();
        for action in [
            Action::Resume { id: b.id.clone() },
            Action::Recover { id: b.id.clone() },
            Action::Replace {
                id: a.id.clone(),
                source: f.ipa("app.a", 2),
            },
        ] {
            assert!(execute(&f.0, &mut rt, &time, action).await.is_err());
        }
        assert_eq!(rt.engine.calls.lock().unwrap().len(), calls);
        assert!(
            Catalog::acquire(&f.0)
                .unwrap()
                .remove(&a.id)
                .unwrap_err()
                .contains("Recover")
        );
        assert!(
            execute(&f.0, &mut rt, &time, Action::Recover { id: a.id.clone() })
                .await
                .is_err()
        );
        assert!(
            journal::account_hold(&f.0.join("renewal"), "same@example.invalid")
                .unwrap()
                .is_some()
        );
        rt.engine.failure = None;
        assert!(
            execute(&f.0, &mut rt, &time, Action::Recover { id: a.id.clone() })
                .await
                .unwrap()
                .enabled
        );
        assert!(
            journal::account_hold(&f.0.join("renewal"), "same@example.invalid")
                .unwrap()
                .is_none()
        );
        assert!(f.job(&b.id).enabled);
        Catalog::acquire(&f.0).unwrap().remove(&a.id).unwrap();
    }
}
#[tokio::test]
async fn unconfirmed_team_recovery_enables_new_app_and_preserves_other_app_removal() {
    let f = Fixture::new();
    let (mut rt, time) = runtime(&f);
    let b = execute(&f.0, &mut rt, &time, install(f.ipa("app.b", 1)))
        .await
        .unwrap();
    rt.team_failure = Some(Failure::RateLimited);
    assert!(
        execute(&f.0, &mut rt, &time, install(f.ipa("app.a", 1)))
            .await
            .is_err()
    );
    let id = management::identity("same-phone", "app.a");
    assert!(Catalog::acquire(&f.0).unwrap().remove(&id).is_err());
    Catalog::acquire(&f.0).unwrap().remove(&b.id).unwrap();
    rt.team_failure = None;
    assert!(
        execute(&f.0, &mut rt, &time, Action::Recover { id: id.clone() })
            .await
            .unwrap()
            .enabled
    );
    assert!(authorized(&f.job(&id)));
    assert!(!f.job(&id).launch_confirmed);
}
#[tokio::test]
async fn incomplete_session_unknown_expiry_or_install_failure_never_authorizes() {
    for mode in 0..3 {
        let f = Fixture::new();
        let (mut rt, time) = runtime(&f);
        rt.engine.ready = mode != 0;
        rt.engine.unknown_expiry = mode == 1;
        if mode == 2 {
            rt.engine.failure = Some(Failure::Installation);
        }
        assert!(
            execute(&f.0, &mut rt, &time, install(f.ipa("app.a", 1)))
                .await
                .is_err()
        );
        let id = management::identity("same-phone", "app.a");
        let job = f.job(&id);
        assert!(!job.enabled && !authorized(&job) && !job.launch_confirmed);
        let calls = rt.engine.calls.lock().unwrap().len();
        assert!(
            execute(&f.0, &mut rt, &time, Action::Resume { id })
                .await
                .is_err()
        );
        assert_eq!(rt.engine.calls.lock().unwrap().len(), calls);
    }
}
#[tokio::test]
async fn lost_install_reply_persistence_reconciles_once_and_never_replays() {
    let f = Fixture::new();
    let (mut rt, time) = runtime(&f);
    rt.engine.block_after_reply = true;
    assert!(
        execute(&f.0, &mut rt, &time, install(f.ipa("app.a", 1)))
            .await
            .is_err()
    );
    let id = management::identity("same-phone", "app.a");
    std::fs::remove_dir(f.0.join("renewal").join(format!("{id}.pending"))).unwrap();
    assert_eq!(f.job(&id).phase, Phase::Running);
    assert!(
        Catalog::acquire(&f.0)
            .unwrap()
            .background_jobs(101)
            .unwrap()
            .is_empty()
    );
    assert_eq!(f.job(&id).last_failure, Some(Failure::Interrupted));
    let bytes = f.bytes(&id);
    for now in [102, 103] {
        assert!(
            Catalog::acquire(&f.0)
                .unwrap()
                .background_jobs(now)
                .unwrap()
                .is_empty()
        );
        assert_eq!(f.bytes(&id), bytes);
    }
    assert_eq!(
        rt.engine
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.starts_with("install:"))
            .count(),
        1
    );
    assert!(
        execute(&f.0, &mut rt, &time, Action::Resume { id })
            .await
            .is_err()
    );
}
#[tokio::test]
async fn removing_then_explicitly_readding_clears_old_pause_and_legacy_metadata_is_optional() {
    let f = Fixture::new();
    let (mut rt, time) = runtime(&f);
    let source = f.ipa("app.a", 1);
    let a = execute(&f.0, &mut rt, &time, install(source.clone()))
        .await
        .unwrap();
    management::pause_setup(&f.0, &a.id).unwrap();
    Catalog::acquire(&f.0).unwrap().remove(&a.id).unwrap();
    assert!(
        execute(&f.0, &mut rt, &time, install(source))
            .await
            .unwrap()
            .enabled
    );
    let mut legacy = f.job(&a.id);
    legacy.launch_confirmed = true;
    let mut value = serde_json::to_value(&legacy).unwrap();
    value.as_object_mut().unwrap().remove("product");
    std::fs::write(
        f.0.join("renewal").join(format!("{}.json", a.id)),
        serde_json::to_vec(&value).unwrap(),
    )
    .unwrap();
    let loaded = f.job(&a.id);
    assert_eq!(loaded.archive, legacy.archive);
    assert_eq!(loaded.next_attempt, legacy.next_attempt);
    assert!(authorized(&loaded));
    assert!(loaded.archive.verify(&f.0.join("renewal")).is_ok());
}

#[tokio::test]
async fn final_commit_failure_keeps_validated_completion_for_resume_without_replay() {
    let f = Fixture::new();
    let (mut rt, time) = runtime(&f);
    rt.block_commit = true;
    assert!(
        execute(&f.0, &mut rt, &time, install(f.ipa("app.a", 1)))
            .await
            .is_err()
    );
    let id = management::identity("same-phone", "app.a");
    std::fs::remove_dir(f.0.join("renewal").join(format!("{id}.pending"))).unwrap();
    let pending = f.job(&id);
    assert!(!pending.enabled);
    assert_eq!(
        pending
            .product
            .pending
            .unwrap()
            .candidate
            .attempt
            .unwrap()
            .stage,
        AttemptStage::Complete
    );
    let calls = rt.engine.calls.lock().unwrap().len();
    rt.block_commit = false;
    assert!(
        execute(&f.0, &mut rt, &time, Action::Resume { id: id.clone() })
            .await
            .unwrap()
            .enabled
    );
    assert_eq!(rt.engine.calls.lock().unwrap().len(), calls);
    assert!(authorized(&f.job(&id)));
}

#[tokio::test]
async fn locked_product_commands_fail_once_without_auth_or_automatic_candidate_replay() {
    for mode in ["install", "renew", "replace"] {
        let f = Fixture::new();
        let (mut rt, time) = runtime(&f);
        let source = f.ipa("app.a", 1);
        let id = if mode == "install" {
            management::identity("same-phone", "app.a")
        } else {
            execute(&f.0, &mut rt, &time, install(source.clone()))
                .await
                .unwrap()
                .id
        };
        rt.engine.calls.lock().unwrap().clear();
        rt.engine.failure = Some(Failure::DeviceLocked);
        let action = match mode {
            "renew" => Action::Renew { id: id.clone() },
            "replace" => Action::Replace {
                id: id.clone(),
                source: f.ipa("app.a", 2),
            },
            _ => install(source),
        };
        assert!(execute(&f.0, &mut rt, &time, action).await.is_err());
        assert!(
            rt.engine.calls.lock().unwrap().is_empty(),
            "no auth or installation while discovery is locked"
        );
        let job = f.job(&id);
        assert!(!job.enabled);
        assert!(job.product.pending.is_some());
        assert!(!authorized(&job));
        let catalog = Catalog::acquire(&f.0).unwrap();
        assert!(
            catalog
                .background_jobs(time.now() + 100 * DAY)
                .unwrap()
                .is_empty()
        );
        let view = catalog.snapshot().unwrap().setups.remove(0);
        assert!(view.pending_install);
        assert!(!view.can_retry_connectivity);
    }
}
