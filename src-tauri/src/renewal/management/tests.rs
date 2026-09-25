use super::*;
use crate::renewal::{Journal, Outcome};
use std::{
    io::Write,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[test]
fn saving_watch_archive_is_rejected_before_managed_copy_or_draft() {
    let fixture = Fixture::new();
    let ipa = fixture.watch_ipa();
    let catalog = fixture.catalog();
    assert!(
        catalog
            .prepare(
                &ipa,
                "phone".into(),
                "Phone".into(),
                "a@example.invalid".into()
            )
            .is_err()
    );
    assert!(catalog.snapshot().unwrap().setups.is_empty());
    assert!(
        !archive::inspect(&ipa)
            .unwrap()
            .path(catalog.journal.directory())
            .unwrap()
            .exists()
    );
}

#[test]
fn legacy_watch_draft_cannot_be_confirmed_or_downgraded() {
    let fixture = Fixture::new();
    let ipa = fixture.watch_ipa();
    let catalog = fixture.catalog();
    let archive = archive::retain(&ipa, catalog.journal.directory()).unwrap();
    let id = identity("phone", main_bundle(&archive).unwrap());
    let draft = Draft {
        team_attempt: None,
        version: 1,
        archive,
        phone_id: "phone".into(),
        phone_name: "Phone".into(),
        account: "a@example.invalid".into(),
    };
    let drafts = catalog.journal.directory().join("drafts");
    fs::create_dir_all(&drafts).unwrap();
    write_atomic(&drafts, &id, &serde_json::to_vec(&draft).unwrap()).unwrap();
    assert!(catalog.confirm(&id, "TEAM", Some("watch")).is_err());
    assert!(catalog.confirm(&id, "TEAM", None).is_err());
    assert!(catalog.snapshot().unwrap().setups[0].needs_confirmation);
}

#[test]
fn execution_requires_the_strict_backend() {
    assert!(execution_available());
    assert_eq!(require_execution().is_ok(), execution_available());
}

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "iloader-setup-test-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn ipa(&self) -> PathBuf {
        self.archive(false)
    }
    fn watch_ipa(&self) -> PathBuf {
        self.archive(true)
    }
    fn archive(&self, watch: bool) -> PathBuf {
        let path = self.0.join("original.ipa");
        let mut zip = zip::ZipWriter::new(fs::File::create(&path).unwrap());
        for (path, id) in [
            ("Payload/Test.app/Info.plist", "test.app"),
            (
                "Payload/Test.app/Watch/Watch.app/Info.plist",
                "test.app.watch",
            ),
        ] {
            if !watch && path.contains("/Watch/") {
                continue;
            }
            zip.start_file(path, zip::write::SimpleFileOptions::default())
                .unwrap();
            write!(zip, "<plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>{id}</string></dict></plist>").unwrap();
        }
        zip.finish().unwrap();
        path
    }
    fn catalog(&self) -> Catalog {
        Catalog::acquire(&self.0).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn save(catalog: &Catalog, ipa: &Path, phone: &str) -> String {
    catalog
        .prepare(
            ipa,
            phone.into(),
            "Test phone".into(),
            "test@example.invalid".into(),
        )
        .unwrap()
}

#[test]
fn foreground_confirmation_is_paused_and_recovers_interrupted_promotion() {
    let fixture = Fixture::new();
    let ipa = fixture.ipa();
    let catalog = fixture.catalog();
    let id = save(&catalog, &ipa, "phone-a");
    let draft_path = catalog
        .journal
        .directory()
        .join("drafts")
        .join(format!("{id}.json"));
    let draft = fs::read(&draft_path).unwrap();
    assert!(catalog.confirm(&id, "TEAM", Some("watch-a")).is_err());
    let mut job = catalog.confirm(&id, "TEAM", None).unwrap();
    assert!(!job.enabled && !job.launch_confirmed);
    assert!(catalog.accept_launch(&id, 1).is_err());
    // Simulate a crash after durable enrollment, before removing draft.
    fs::write(&draft_path, &draft).unwrap();
    assert_eq!(catalog.snapshot().unwrap().setups.len(), 1);
    assert!(!catalog.snapshot().unwrap().setups[0].needs_confirmation);
    assert!(catalog.enable(&id, 1).is_err());
    job.iphone = DeviceEvidence {
        profile_expiry: Some(500),
        last_success: Some(20),
        last_attempt: Some(10),
        outcome: Outcome::Installed,
    };

    catalog.save_job(&id, &job).unwrap();
    catalog.accept_launch(&id, 30).unwrap();
    assert!(catalog.job(&id).unwrap().launch_confirmed);
    assert!(catalog.accept_launch(&id, 500).is_err());
    assert_eq!(
        catalog.enable(&id, 30).is_ok(),
        execution_available(),
        "build gate controls reviewed opt-in"
    );
    catalog.remove(&id).unwrap();
    assert!(catalog.snapshot().unwrap().setups.is_empty());
}

#[test]
fn setup_survives_restart_and_source_removal_without_becoming_executable() {
    let fixture = Fixture::new();
    let ipa = fixture.ipa();
    let id = save(&fixture.catalog(), &ipa, "phone-a");
    fs::remove_file(ipa).unwrap();
    let catalog = fixture.catalog();
    let snapshot = catalog.snapshot().unwrap();
    assert_eq!(snapshot.execution_available, execution_available());
    assert_eq!(require_execution().is_ok(), execution_available());
    assert_eq!(snapshot.setups.len(), 1);
    let setup = &snapshot.setups[0];
    assert_eq!(setup.id, id);
    assert!(setup.needs_confirmation && setup.paused);
    assert!(setup.iphone.profile_expiry.is_none());
    assert_eq!(setup.iphone.outcome, Outcome::Never);
    assert!(setup.watch.is_none());
    assert!(setup.next_attempt.is_none());
    let records = catalog.records().unwrap();
    records[0]
        .1
        .archive()
        .verify(catalog.journal.directory())
        .unwrap();
    // Drafts are kept out of the engine's executable manifest directory.
    assert!(record_ids(catalog.journal.directory()).unwrap().is_empty());
}

#[test]
fn duplicate_setup_is_idempotent_but_account_replacement_is_explicit() {
    let fixture = Fixture::new();
    let ipa = fixture.ipa();
    let catalog = fixture.catalog();
    let id = save(&catalog, &ipa, "phone-a");
    assert_eq!(save(&catalog, &ipa, "phone-a"), id);
    assert!(
        catalog
            .prepare(
                &ipa,
                "phone-a".into(),
                "Test phone".into(),
                "other@example.invalid".into()
            )
            .is_err()
    );
    let snapshot = catalog.snapshot().unwrap();
    assert_eq!(snapshot.setups.len(), 1);
    assert_eq!(snapshot.setups[0].account, "test@example.invalid");
}

#[test]
fn reselecting_original_repairs_missing_copy_but_rejects_changed_copy() {
    let fixture = Fixture::new();
    let ipa = fixture.ipa();
    let catalog = fixture.catalog();
    let id = save(&catalog, &ipa, "phone-a");
    let records = catalog.records().unwrap();
    let retained = records[0]
        .1
        .archive()
        .path(catalog.journal.directory())
        .unwrap();
    fs::remove_file(&retained).unwrap();
    assert_eq!(save(&catalog, &ipa, "phone-a"), id);
    records[0]
        .1
        .archive()
        .verify(catalog.journal.directory())
        .unwrap();
    fs::write(&retained, b"changed").unwrap();
    assert!(
        catalog
            .prepare(
                &ipa,
                "phone-a".into(),
                "Test phone".into(),
                "test@example.invalid".into()
            )
            .is_err()
    );
    assert_eq!(fs::read(&retained).unwrap(), b"changed");
}

#[test]
fn removing_one_setup_preserves_other_references_and_original() {
    let fixture = Fixture::new();
    let ipa = fixture.ipa();
    let catalog = fixture.catalog();
    let first = save(&catalog, &ipa, "phone-a");
    let second = save(&catalog, &ipa, "phone-b");
    let records = catalog.records().unwrap();
    let retained = records[0]
        .1
        .archive()
        .path(catalog.journal.directory())
        .unwrap();
    catalog.remove(&first).unwrap();
    assert!(retained.exists() && ipa.exists());
    assert_eq!(catalog.snapshot().unwrap().setups.len(), 1);
    assert!(catalog.remove("../../outside").is_err());
    catalog.remove(&second).unwrap();
    assert!(!retained.exists());
    assert!(ipa.exists());
}

#[test]
fn setup_management_excludes_installation_and_preserves_corrupt_metadata() {
    let fixture = Fixture::new();
    let ipa = fixture.ipa();
    let catalog = fixture.catalog();
    let id = save(&catalog, &ipa, "phone-a");
    assert!(FileJournal::acquire(&fixture.0, "other-job").is_err());
    let manifest = catalog
        .journal
        .directory()
        .join("drafts")
        .join(format!("{id}.json"));
    fs::write(&manifest, b"broken state").unwrap();
    assert!(catalog.snapshot().is_err());
    assert!(catalog.remove(&id).is_err());
    assert_eq!(fs::read(&manifest).unwrap(), b"broken state");
}

#[test]
fn paused_and_interrupted_enrollment_keeps_separate_device_evidence() {
    let fixture = Fixture::new();
    let ipa = fixture.watch_ipa();
    let id = "verified-job";
    {
        let mut journal = FileJournal::acquire(&fixture.0, id).unwrap();
        let archive = archive::retain(&ipa, journal.directory()).unwrap();
        journal
            .save(&Enrollment {
                product: Default::default(),
                pilot_enabled: false,
                attempt: None,
                failure_evidence: None,
                version: 1,
                archive,
                account: "test@example.invalid".into(),
                team_id: "team-a".into(),
                phone_id: "phone-a".into(),
                watch_id: Some("watch-a".into()),
                enabled: true,
                launch_confirmed: false,
                iphone: DeviceEvidence {
                    profile_expiry: Some(123),
                    last_success: Some(100),
                    last_attempt: Some(100),
                    outcome: Outcome::Installed,
                },
                watch: Some(DeviceEvidence::unknown()),
                phase: Phase::Running,
                next_attempt: 99,
                retry_count: 0,
                last_checked: Some(98),
                last_failure: None,
            })
            .unwrap();
    }
    let catalog = fixture.catalog();
    let snapshot = catalog.snapshot().unwrap();
    let setup = &snapshot.setups[0];
    assert_eq!(setup.problem, Some(Failure::Interrupted));
    assert!(setup.paused && setup.next_attempt.is_none());
    catalog.pause(id).unwrap();
    drop(catalog);
    let mut journal = FileJournal::acquire(&fixture.0, id).unwrap();
    let job = journal.load().unwrap();
    assert!(!job.enabled);
    assert_eq!(job.phase, Phase::Running);
    assert_eq!(job.iphone.profile_expiry, Some(123));
    assert_eq!(job.watch.unwrap().outcome, Outcome::Never);
}

#[test]
fn proven_preinstall_connectivity_retains_accepted_install_evidence() {
    for failure in [Failure::Offline, Failure::DeviceLocked] {
        let fixture = Fixture::new();
        let ipa = fixture.ipa();
        let catalog = fixture.catalog();
        let id = save(&catalog, &ipa, "phone-a");
        let mut job = catalog.confirm(&id, "TEAM", None).unwrap();
        job.iphone = DeviceEvidence {
            profile_expiry: Some(10000),
            last_success: Some(100),
            last_attempt: Some(100),
            outcome: Outcome::Installed,
        };
        job.launch_confirmed = true;
        job.attempt = Some(crate::renewal::Attempt {
            manual: false,
            number: 2,
            started_at: 200,
            stage: crate::renewal::AttemptStage::Discovering,
            session: None,
        });
        job.fail(failure, 200);
        assert!(
            require_installed(&job, 201).is_ok(),
            "proven discovery-only failure must not demand another install"
        );
        let mut legacy = job.clone();
        legacy.attempt = None;
        assert!(require_installed(&legacy, 201).is_err());
        job.attempt.as_mut().unwrap().stage = crate::renewal::AttemptStage::InstallingPhone;
        assert!(require_installed(&job, 201).is_err());
    }
}

#[test]
fn confirmation_rejects_a_changed_retained_archive() {
    let fixture = Fixture::new();
    let ipa = fixture.ipa();
    let catalog = fixture.catalog();
    let id = save(&catalog, &ipa, "phone-a");
    let identity = archive::inspect(&ipa).unwrap();
    fs::write(
        identity.path(catalog.journal.directory()).unwrap(),
        b"changed",
    )
    .unwrap();
    assert!(catalog.confirm(&id, "TEAM", None).is_err());
    assert!(catalog.snapshot().unwrap().setups[0].needs_confirmation);
}
