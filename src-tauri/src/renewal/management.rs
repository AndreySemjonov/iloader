//! Local-only setup. A draft is deliberately not an executable Enrollment:
//! signing team, companion identity and installed evidence need confirmation.
use std::{fs, path::Path};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    DeviceEvidence, Enrollment, Failure, Phase,
    archive::{self, ArchiveIdentity},
    journal::{FileJournal, read_enrollment, write_atomic},
};

// Automatic renewal is always compiled in; kept as one switch point for callers.
pub fn execution_available() -> bool {
    true
}

pub fn require_execution() -> Result<(), String> {
    if execution_available() {
        Ok(())
    } else {
        Err(
            "Automatic renewal is not available in this build. Use the manual Wi-Fi check first."
                .into(),
        )
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Draft {
    version: u32,
    pub(crate) archive: ArchiveIdentity,
    pub(crate) phone_id: String,
    pub(crate) phone_name: String,
    pub(crate) account: String,
    #[serde(default)]
    team_attempt: Option<TeamAttempt>,
}
#[derive(Clone, Serialize, Deserialize)]
struct TeamAttempt {
    at: i64,
    failure: Option<Failure>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetupView {
    pub display_name: String,
    pub pending_install: bool,
    pub can_recover: bool,
    pub attempt: Option<super::Attempt>,
    pub failure_evidence: Option<super::FailureEvidence>,
    pub account_problem: Option<Failure>,
    pub account_session: Option<super::session_diagnostic::Diagnostic>,
    pub can_retry_connectivity: bool,
    pub id: String,
    pub bundle_id: String,
    pub archive_sha256: String,
    pub phone_only: bool,
    pub phone_id: String,
    pub phone_name: String,
    pub account: String,
    pub needs_confirmation: bool,
    pub launch_confirmed: bool,
    pub team_id: Option<String>,
    pub watch_id: Option<String>,
    pub paused: bool,
    pub iphone: DeviceEvidence,
    pub watch: Option<DeviceEvidence>,
    pub next_attempt: Option<i64>,
    pub last_checked: Option<i64>,
    pub problem: Option<Failure>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub execution_available: bool,
    pub setups: Vec<SetupView>,
}

enum Record {
    Draft(Draft),
    Enrolled(Enrollment),
}

impl Record {
    fn archive(&self) -> &ArchiveIdentity {
        match self {
            Self::Draft(draft) => &draft.archive,
            Self::Enrolled(job) => &job.archive,
        }
    }

    fn account(&self) -> &str {
        match self {
            Self::Draft(draft) => &draft.account,
            Self::Enrolled(job) => &job.account,
        }
    }

    fn phone_id(&self) -> &str {
        match self {
            Self::Draft(draft) => &draft.phone_id,
            Self::Enrolled(job) => &job.phone_id,
        }
    }

    fn view(&self, id: String) -> Result<SetupView, String> {
        let bundle_id = main_bundle(self.archive())?.to_owned();
        Ok(match self {
            Self::Draft(draft) => SetupView {
                display_name: bundle_id.clone(),
                pending_install: false,
                can_recover: true,
                attempt: None,
                failure_evidence: None,
                account_problem: None,
                account_session: None,
                can_retry_connectivity: false,
                id,
                bundle_id,
                archive_sha256: self.archive().sha256.clone(),
                phone_only: !self.archive().has_watch,
                phone_id: draft.phone_id.clone(),
                phone_name: draft.phone_name.clone(),
                account: draft.account.clone(),
                needs_confirmation: true,
                launch_confirmed: false,
                team_id: None,
                watch_id: None,
                paused: true,
                iphone: DeviceEvidence::unknown(),
                watch: draft.archive.has_watch.then(DeviceEvidence::unknown),
                next_attempt: None,
                last_checked: None,
                problem: draft
                    .team_attempt
                    .as_ref()
                    .map(|a| a.failure.clone().unwrap_or(Failure::Interrupted)),
            },
            Self::Enrolled(job) => SetupView {
                display_name: job
                    .product
                    .display_name
                    .clone()
                    .unwrap_or_else(|| bundle_id.clone()),
                pending_install: job.product.pending.is_some(),
                can_recover: job.product.pending.is_some()
                    || job.last_failure.is_some()
                    || !super::product::authorized(job),
                attempt: job.attempt.clone(),
                failure_evidence: job.failure_evidence.clone(),
                account_problem: None,
                account_session: None,
                can_retry_connectivity: safe_connectivity_failure(job),
                id,
                bundle_id,
                archive_sha256: self.archive().sha256.clone(),
                phone_only: !self.archive().has_watch,
                phone_id: job.phone_id.clone(),
                phone_name: job
                    .product
                    .phone_name
                    .clone()
                    .unwrap_or_else(|| "Saved iPhone".into()),
                account: job.account.clone(),
                needs_confirmation: false,
                launch_confirmed: job.launch_confirmed,
                team_id: Some(job.team_id.clone()),
                watch_id: job.watch_id.clone(),
                paused: !execution_available() || !job.enabled || !job.pilot_enabled,
                iphone: job.iphone.clone(),
                watch: job.watch.clone(),
                next_attempt: (execution_available()
                    && job.enabled
                    && job.pilot_enabled
                    && job.phase == Phase::Idle)
                    .then_some(job.next_attempt),
                last_checked: job.last_checked,
                problem: if job.phase == Phase::Running {
                    Some(Failure::Interrupted)
                } else {
                    job.last_failure.clone()
                },
            },
        })
    }
}

pub(crate) fn main_bundle(archive: &ArchiveIdentity) -> Result<&str, String> {
    let mut roots = archive.bundles.iter().filter(|(path, _)| {
        let parts: Vec<_> = path.split('/').collect();
        parts.len() == 3
            && parts[0] == "Payload"
            && parts[1].ends_with(".app")
            && parts[2] == "Info.plist"
    });
    let (_, bundle) = roots.next().ok_or("Original IPA has no app identity")?;
    if bundle.is_empty() || roots.next().is_some() {
        return Err("Original IPA has an ambiguous app identity".into());
    }
    Ok(bundle)
}

pub(crate) fn identity(phone: &str, bundle: &str) -> String {
    let mut hash = Sha256::new();
    for item in [phone, bundle] {
        hash.update((item.len() as u64).to_le_bytes());
        hash.update(item.as_bytes());
    }
    hash.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn record_ids(directory: &Path) -> Result<Vec<String>, String> {
    if !directory.exists() {
        return Ok(Vec::new());
    }
    let mut ids = Vec::new();
    for entry in fs::read_dir(directory).map_err(|_| "Unable to read saved setups")? {
        let entry = entry.map_err(|_| "Unable to read saved setup")?;
        let path = entry.path();
        if path.extension().is_none_or(|ext| ext != "json") {
            continue;
        }
        let id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or("Invalid setup name")?;
        if id.is_empty()
            || id.len() > 64
            || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || entry
                .metadata()
                .map_err(|_| "Unable to inspect saved setup")?
                .len()
                > 1024 * 1024
        {
            return Err("Invalid saved setup; manual recovery required".into());
        }
        ids.push(id.to_owned());
    }
    ids.sort();
    Ok(ids)
}

/// The catalog shares the install lease. Concurrent imports, removal, manual
/// installation and journal changes therefore cannot race one another.
pub struct Catalog {
    journal: FileJournal,
}

impl Catalog {
    pub(crate) fn draft(&self, id: &str) -> Result<Draft, String> {
        self.records()?
            .into_iter()
            .find_map(|(key, record)| {
                if key == id {
                    if let Record::Draft(d) = record {
                        Some(d)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .ok_or("No draft setup".into())
    }
    pub(crate) fn team_started(&self, id: &str, now: i64) -> Result<(), String> {
        let mut draft = self.draft(id)?;
        draft.team_attempt = Some(TeamAttempt {
            at: now,
            failure: None,
        });
        write_atomic(
            &self.journal.directory().join("drafts"),
            id,
            &serde_json::to_vec(&draft).map_err(|_| "Unable to record account preparation")?,
        )
    }
    pub(crate) fn team_finished(&self, id: &str, failure: Option<Failure>) -> Result<(), String> {
        // Own the lease; don't reconcile our in-flight checkpoint as a restart.
        let path = self.journal.directory().join("drafts");
        let mut draft: Draft = serde_json::from_slice(
            &fs::read(path.join(format!("{id}.json"))).map_err(|_| "Unable to read draft")?,
        )
        .map_err(|_| "Invalid draft")?;
        if let Some(failure) = failure {
            let attempt = draft
                .team_attempt
                .as_mut()
                .ok_or("Account preparation checkpoint missing")?;
            attempt.failure = Some(failure.clone());
            super::journal::persist_team_hold(
                self.journal.directory(),
                &draft.account,
                &draft.phone_id,
                &draft.archive,
                failure,
                attempt.at,
            )?;
        } else {
            draft.team_attempt = None;
        }
        write_atomic(
            &path,
            id,
            &serde_json::to_vec(&draft).map_err(|_| "Unable to record account preparation")?,
        )
    }
    pub(crate) fn product_selection(
        &self,
        source: &Path,
        phone: &str,
        name: &str,
        account: &str,
    ) -> Result<(String, bool), String> {
        let archive = archive::inspect(source).map_err(|_| "Choose a readable valid IPA")?;
        require_phone_archive(&archive)?;
        for (id, record) in self.records()? {
            if record.phone_id() == phone
                && main_bundle(record.archive())? == main_bundle(&archive)?
            {
                let owner = match &record {
                    Record::Draft(d) => &d.account,
                    Record::Enrolled(j) => &j.account,
                };
                if !owner.eq_ignore_ascii_case(account) {
                    return Err("This app belongs to a different saved account".into());
                }
                if record.archive() != &archive {
                    return Err("This app is already managed. Choose Replace IPA from its menu to update it.".into());
                }
                if matches!(record, Record::Enrolled(_)) {
                    return Ok((id, true));
                }
            }
        }
        if super::journal::account_hold(self.journal.directory(), account)?.is_some() {
            return Err(
                "This account is stopped. Recover its failing app before adding another app."
                    .into(),
            );
        }
        self.prepare(source, phone.into(), name.into(), account.into())
            .map(|id| (id, false))
    }
    pub(crate) fn into_journal(self, id: &str) -> Result<FileJournal, String> {
        self.job(id)?;
        self.journal.with_id(id)
    }
    pub fn acquire(app_directory: &Path) -> Result<Self, String> {
        Ok(Self {
            journal: FileJournal::acquire(app_directory, "catalog")?,
        })
    }

    fn records(&self) -> Result<Vec<(String, Record)>, String> {
        let directory = self.journal.directory();
        let drafts = directory.join("drafts");
        let mut records = Vec::new();
        for id in record_ids(&drafts)? {
            let data = fs::read(drafts.join(format!("{id}.json")))
                .map_err(|_| "Unable to read saved setup")?;
            let draft: Draft = serde_json::from_slice(&data)
                .map_err(|_| "Invalid saved setup; manual recovery required")?;
            if draft.version != 1
                || draft.phone_id.is_empty()
                || draft.account.is_empty()
                || identity(&draft.phone_id, main_bundle(&draft.archive)?) != id
            {
                return Err("Inconsistent saved setup; manual recovery required".into());
            }
            draft
                .archive
                .path(directory)
                .map_err(|_| "Invalid archive identity")?;
            if let Some(attempt) = &draft.team_attempt {
                super::journal::persist_team_hold(
                    directory,
                    &draft.account,
                    &draft.phone_id,
                    &draft.archive,
                    attempt.failure.clone().unwrap_or(Failure::Interrupted),
                    attempt.at,
                )?;
            }
            records.push((id, Record::Draft(draft)));
        }
        for id in record_ids(directory)? {
            let job = read_enrollment(directory, &id)?;
            // Promotion writes the durable enrollment before removing its draft.
            // A crash between those writes must not lose or duplicate the setup.
            if let Some(index) = records.iter().position(|(key,record)| key == &id && matches!(record,Record::Draft(draft)
                if draft.archive == job.archive && draft.phone_id == job.phone_id && draft.account == job.account)) {
                records.remove(index);
            }
            if records.iter().any(|(other_id, record)| {
                other_id == &id
                    || (record.phone_id() == job.phone_id
                        && main_bundle(record.archive()).ok() == main_bundle(&job.archive).ok())
            }) {
                return Err("Duplicate saved setup; manual recovery required".into());
            }
            records.push((id, Record::Enrolled(job)));
        }
        Ok(records)
    }

    pub fn snapshot(&self) -> Result<Snapshot, String> {
        Ok(Snapshot {
            execution_available: execution_available(),
            setups: self
                .records()?
                .into_iter()
                .map(|(id, record)| {
                    let mut view = record.view(id)?;
                    if view.display_name == view.bundle_id {
                        if let Ok(path) = record.archive().path(self.journal.directory()) {
                            if let Some(name) = archive::display_name(&path) {
                                view.display_name = name;
                            }
                        }
                    }
                    if let Some(hold) =
                        super::journal::account_hold(self.journal.directory(), &view.account)?
                    {
                        view.account_problem = Some(hold.failure);
                        view.can_retry_connectivity = false;
                        view.account_session = hold.session;
                        view.next_attempt = None;
                        view.can_recover = match &record {
                            Record::Draft(d) => super::journal::unconfirmed_recovery_matches(
                                self.journal.directory(),
                                &d.account,
                                &d.phone_id,
                                &d.archive,
                            )?,
                            Record::Enrolled(job) => {
                                super::journal::recovery_matches(self.journal.directory(), job)?
                            }
                        };
                    }
                    Ok::<SetupView, String>(view)
                })
                .collect::<Result<_, _>>()?,
        })
    }

    /// Actual host admission path: only local journals are read here.
    pub(crate) fn background_jobs(&self, now: i64) -> Result<Vec<String>, String> {
        let records = self.records()?;
        // Include legacy failures before considering any other job on the account.
        for (_, record) in &records {
            if let Record::Enrolled(job) = record {
                super::journal::persist_account_hold(self.journal.directory(), job)?;
            }
        }
        let mut due = Vec::new();
        for (id, record) in records {
            let Record::Enrolled(mut job) = record else {
                continue;
            };
            if job.phase == Phase::Running {
                job.fail(Failure::Interrupted, now);
                self.save_job(&id, &job)?;
                continue;
            }
            // Settled pending success/failure is not a fresh interruption. Keep
            // Complete evidence for explicit finalization without another install.
            if job.product.pending.is_some() {
                continue;
            }
            if require_phone_job(&job).is_err()
                || !job.enabled
                || !job.pilot_enabled
                || !super::product::authorized(&job)
                || job.phase != Phase::Idle
                || job.next_attempt > now
            {
                continue;
            }
            if super::journal::account_hold(self.journal.directory(), &job.account)?.is_some() {
                continue;
            }
            due.push(id);
        }
        Ok(due)
    }

    #[cfg(test)]
    pub(crate) fn retry_connectivity(&self, id: &str, now: i64) -> Result<(), String> {
        let mut job = self.job(id)?;
        require_phone_job(&job).map_err(|_| "Recovery is phone-only")?;
        if !safe_connectivity_failure(&job) {
            return Err("This failure requires review before another renewal".into());
        }
        if super::journal::account_hold(self.journal.directory(), &job.account)?.is_some() {
            return Err("Account recovery is required first".into());
        }
        job.archive
            .verify(self.journal.directory())
            .map_err(|_| "Retained IPA is missing or changed")?;
        // Keep failure_evidence and accepted installation; the explicit request only
        // clears the active connectivity error and schedules a future check.
        job.last_failure = None;
        job.retry_count = 0;
        job.next_attempt = now.saturating_add(60);
        self.save_job(id, &job)
    }

    pub fn prepare(
        &self,
        source: &Path,
        phone_id: String,
        phone_name: String,
        account: String,
    ) -> Result<String, String> {
        if [phone_id.as_str(), phone_name.as_str(), account.as_str()]
            .iter()
            .any(|value| value.trim().is_empty() || value.len() > 4096)
        {
            return Err("Select a phone and sign in before saving setup".into());
        }
        let records = self.records()?;
        let directory = self.journal.directory();
        let archive = archive::inspect(source)
            .map_err(|_| "Unable to retain the original IPA. Choose a readable, valid IPA.")?;
        require_phone_archive(&archive)?;
        let bundle = main_bundle(&archive)?;
        for (id, record) in &records {
            if record.phone_id() == phone_id && main_bundle(record.archive())? == bundle {
                if let Record::Draft(draft) = record {
                    if draft.archive == archive && draft.account == account {
                        // Re-selecting the original repairs a missing managed
                        // copy, but must not silently accept a changed copy.
                        retain_expected(source, directory, &archive)?;
                        return Ok(id.clone());
                    }
                }
                return Err("This app and phone already have a saved setup. Use Replace IPA to update it; its phone and account cannot be changed.".into());
            }
        }
        let id = identity(&phone_id, bundle);
        retain_expected(source, directory, &archive)?;
        let draft = Draft {
            team_attempt: None,
            version: 1,
            archive,
            phone_id,
            phone_name,
            account,
        };
        let bytes = serde_json::to_vec_pretty(&draft).map_err(|_| "Unable to save setup")?;
        let drafts = directory.join("drafts");
        fs::create_dir_all(&drafts).map_err(|_| "Unable to create setup directory")?;
        write_atomic(&drafts, &id, &bytes)?;
        Ok(id)
    }

    pub fn pause(&self, id: &str) -> Result<(), String> {
        let (_, record) = self
            .records()?
            .into_iter()
            .find(|(key, _)| key == id)
            .ok_or("Saved setup no longer exists")?;
        if let Record::Enrolled(mut job) = record {
            super::admission::pause(self.journal.directory(), id)?;
            job.enabled = false;
            let bytes = serde_json::to_vec_pretty(&job).map_err(|_| "Unable to pause renewal")?;
            write_atomic(self.journal.directory(), id, &bytes)?;
        }
        Ok(())
    }

    pub fn remove(&self, id: &str) -> Result<(), String> {
        let records = self.records()?;
        let (_, record) = records
            .iter()
            .find(|(key, _)| key == id)
            .ok_or("Saved setup no longer exists")?;
        let directory = self.journal.directory();
        let owns_hold = match record {
            Record::Draft(draft) => super::journal::unconfirmed_recovery_matches(
                directory,
                &draft.account,
                &draft.phone_id,
                &draft.archive,
            )?,
            Record::Enrolled(job) => super::journal::recovery_matches(directory, job)?,
        };
        if owns_hold {
            return Err(
                "Recover this account from View details before removing its failing app".into(),
            );
        }
        let manifest_directory = match record {
            Record::Draft(_) => directory.join("drafts"),
            Record::Enrolled(_) => directory.to_owned(),
        };
        if matches!(record, Record::Enrolled(_)) {
            // Remove a matching promotion remnant before the authoritative job;
            // otherwise removing the job could resurrect its old draft.
            let remnant = directory.join("drafts").join(format!("{id}.json"));
            match fs::remove_file(remnant) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err("Unable to remove setup promotion record".into()),
            }
        }
        fs::remove_file(manifest_directory.join(format!("{id}.json")))
            .map_err(|_| "Unable to remove saved setup")?;
        if !records
            .iter()
            .any(|(key, other)| key != id && other.archive().sha256 == record.archive().sha256)
        {
            let path = record
                .archive()
                .path(directory)
                .map_err(|_| "Invalid archive identity")?;
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => {
                    return Err("Setup removed, but its retained IPA could not be removed".into());
                }
            }
        }
        Ok(())
    }

    /// Before an Apple ID is removed: refuse while it still has saved setups,
    /// otherwise delete its leftover recovery state.
    pub fn forget_account(&self, account: &str) -> Result<(), String> {
        if self
            .records()?
            .iter()
            .any(|(_, record)| record.account().eq_ignore_ascii_case(account))
        {
            return Err(
                "Remove this account's automatic renewal apps before removing the account.".into(),
            );
        }
        super::journal::forget_account(self.journal.directory(), account)
    }

    pub(crate) fn job(&self, id: &str) -> Result<Enrollment, String> {
        self.records()?
            .into_iter()
            .find_map(|(key, record)| {
                if key == id {
                    if let Record::Enrolled(job) = record {
                        Some(job)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .ok_or("Confirm the saved setup first".into())
    }

    /// Bind a verified retained draft to the selected signing team while holding this lease.
    pub(crate) fn confirm(
        &self,
        id: &str,
        team: &str,
        watch: Option<&str>,
    ) -> Result<Enrollment, String> {
        if team.is_empty()
            || team.len() > 128
            || !team.bytes().all(|b| b.is_ascii_alphanumeric())
            || watch.is_some_and(|w| w.is_empty() || w.len() > 256)
        {
            return Err("Enter valid signing team and device identities".into());
        }
        let (_, record) = self
            .records()?
            .into_iter()
            .find(|(key, _)| key == id)
            .ok_or("Saved setup no longer exists")?;
        let draft = match record {
            Record::Draft(draft) => draft,
            Record::Enrolled(_) => {
                return Err("This setup is already confirmed; use Renew now".into());
            }
        };
        require_phone_archive(&draft.archive)?;
        if watch.is_some() {
            return Err("Confirm the Watch included in this IPA".into());
        }
        draft
            .archive
            .verify(self.journal.directory())
            .map_err(|_| "Retained original IPA is missing or changed")?;
        let job = Enrollment {
            product: Default::default(),
            pilot_enabled: false,
            attempt: None,
            failure_evidence: None,
            version: 1,
            archive: draft.archive,
            account: draft.account,
            team_id: team.into(),
            phone_id: draft.phone_id,
            watch_id: watch.map(str::to_owned),
            enabled: false,
            launch_confirmed: false,
            iphone: DeviceEvidence::unknown(),
            watch: watch.map(|_| DeviceEvidence::unknown()),
            phase: Phase::Idle,
            next_attempt: 0,
            retry_count: 0,
            last_checked: None,
            last_failure: None,
        };
        self.save_job(id, &job)?;
        fs::remove_file(
            self.journal
                .directory()
                .join("drafts")
                .join(format!("{id}.json")),
        )
        .map_err(|_| "Setup was confirmed; refresh to finish recovery")?;
        Ok(job)
    }

    pub(crate) fn save_job(&self, id: &str, job: &Enrollment) -> Result<(), String> {
        if identity(&job.phone_id, main_bundle(&job.archive)?) != id {
            return Err("Setup identity changed".into());
        }
        super::journal::persist_account_hold(self.journal.directory(), job)?;
        write_atomic(
            self.journal.directory(),
            id,
            &serde_json::to_vec_pretty(job).map_err(|_| "Unable to save enrollment")?,
        )
    }

    #[cfg(test)]
    pub(crate) fn accept_launch(&self, id: &str, now: i64) -> Result<(), String> {
        let mut job = self.job(id)?;
        require_phone_job(&job).map_err(|_| "Watch saved renewal is unavailable in this build")?;
        require_installed(&job, now)?;
        job.launch_confirmed = true;
        self.save_job(id, &job)?;
        // Only explicit owner acceptance after a successful renewal can lift an
        // account stop. A preserved pre-install success cannot clear an auth hold.
        if job.last_failure.is_none()
            && job
                .attempt
                .as_ref()
                .is_some_and(|a| a.stage == super::AttemptStage::Complete)
        {
            super::journal::acknowledge_account_recovery(self.journal.directory(), &job)?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn enable(&self, id: &str, now: i64) -> Result<(), String> {
        require_execution()?;
        self.enable_reviewed(id, now)
    }
    pub(crate) fn validate_enable(&self, id: &str, now: i64) -> Result<(), String> {
        let job = self.job(id)?;
        require_phone_job(&job).map_err(|_| "Watch saved renewal is unavailable in this build")?;
        require_installed(&job, now)?;
        if super::journal::account_hold(self.journal.directory(), &job.account)?.is_some() {
            return Err("Account recovery is required before enabling another app".into());
        }
        job.archive
            .verify(self.journal.directory())
            .map_err(|_| "Retained IPA is missing or changed")?;
        if !super::product::authorized(&job) {
            return Err("Confirm app launch and retained data first".into());
        }
        Ok(())
    }
    pub(crate) fn enable_reviewed(&self, id: &str, now: i64) -> Result<(), String> {
        self.validate_enable(id, now)?;
        let mut job = self.job(id)?;
        job.enabled = true;
        job.pilot_enabled = true;
        // Explicit opt-in never submits an immediate installation.
        job.next_attempt = now
            .saturating_add(super::DAY)
            .min(
                job.iphone
                    .profile_expiry
                    .unwrap()
                    .saturating_sub(super::RENEWAL_MARGIN),
            )
            .max(now.saturating_add(60));
        super::admission::resume(self.journal.directory(), id, || self.save_job(id, &job))
    }
}

pub(crate) fn require_phone_job(job: &Enrollment) -> Result<(), Failure> {
    if require_phone_archive(&job.archive).is_err() || job.watch_id.is_some() || job.watch.is_some()
    {
        return Err(Failure::WatchNotSupported);
    }
    Ok(())
}
pub(crate) fn require_phone_archive(archive: &ArchiveIdentity) -> Result<(), String> {
    if archive.has_watch
        || archive
            .bundles
            .iter()
            .any(|(path, _)| path.split('/').any(|part| part == "Watch"))
    {
        return Err(
            "Saved renewal currently supports phone-only IPAs. Watch renewal is not enabled."
                .into(),
        );
    }
    Ok(())
}

pub(crate) fn safe_connectivity_failure(job: &Enrollment) -> bool {
    job.phase == Phase::Idle
        && super::product::authorized(job)
        && matches!(
            job.last_failure,
            Some(Failure::Offline | Failure::DeviceLocked)
        )
        && job.attempt.as_ref().is_some_and(|a| {
            a.stage == super::AttemptStage::Discovering
                && a.session.is_none()
                && job.failure_evidence.as_ref().is_some_and(|e| {
                    Some(&e.failure) == job.last_failure.as_ref() && e.attempt.as_ref() == Some(a)
                })
        })
        && job.iphone.outcome == super::Outcome::Installed
        && job
            .iphone
            .last_success
            .zip(job.iphone.last_attempt)
            .is_some_and(|(success, attempt)| success >= attempt)
}

pub(crate) fn require_installed(job: &Enrollment, now: i64) -> Result<(), String> {
    if job.phase != Phase::Idle
        || (job.last_failure.is_some() && !safe_connectivity_failure(job))
        || std::iter::once(&job.iphone)
            .chain(job.watch.iter())
            .any(|e| {
                e.outcome != super::Outcome::Installed
                    || e.last_success
                        .zip(e.last_attempt)
                        .is_none_or(|(success, attempt)| success < attempt)
                    || e.profile_expiry.is_none_or(|expiry| expiry <= now)
            })
    {
        return Err("Complete a successful foreground renewal for every device first".into());
    }
    Ok(())
}

fn retain_expected(
    source: &Path,
    directory: &Path,
    expected: &ArchiveIdentity,
) -> Result<(), String> {
    let retained = archive::retain(source, directory).map_err(
        |_| "Unable to retain the original IPA. Check the file or remove the existing setup first.",
    )?;
    if expected != &retained {
        return Err("The original IPA changed while saving setup. Choose it again.".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests;

/// Filesystem boundary shared by the per-app Pause command and offline tests.
pub(crate) fn pause_setup(directory: &Path, id: &str) -> Result<(), String> {
    super::admission::validate_id(id)?;
    let directory = directory.join("renewal");
    // Atomic journal reads are safe while another owner replaces the file.
    // Never take the install lease or overwrite active attempt evidence here.
    read_enrollment(&directory, id)?;
    super::admission::pause(&directory, id)
}
