use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use super::{Attempt, Enrollment, Failure, Journal, Phase};
use crate::install_lock::InstallLease;
use sha2::{Digest, Sha256};

/// Acquire before reading state and retain until all asynchronous work finishes.
/// One lock covers every enrollment and manual installation in this app directory.
pub struct FileJournal {
    directory: PathBuf,
    id: String,
    candidate: bool,
    _lease: InstallLease,
}

impl FileJournal {
    pub fn acquire(app_directory: &Path, id: &str) -> Result<Self, String> {
        if id.is_empty()
            || id.len() > 64
            || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err("Invalid enrollment id".into());
        }
        let lease = InstallLease::acquire(app_directory)
            .map_err(|_| "Another installation is running or the lock is unavailable")?;
        let directory = app_directory.join("renewal");
        fs::create_dir_all(&directory).map_err(|_| "Unable to create renewal directory")?;
        Ok(Self {
            directory,
            id: id.into(),
            candidate: false,
            _lease: lease,
        })
    }

    pub(super) fn directory(&self) -> &Path {
        &self.directory
    }
    pub(crate) fn with_id(mut self, id: &str) -> Result<Self, String> {
        super::admission::validate_id(id)?;
        self.id = id.into();
        Ok(self)
    }
    pub(crate) fn candidate_mode(&mut self, enabled: bool) {
        self.candidate = enabled;
    }
    pub(crate) fn save_resuming(&mut self, job: &Enrollment) -> Result<(), String> {
        let directory = self.directory.clone();
        let id = self.id.clone();
        super::admission::resume(&directory, &id, || {
            persist_account_hold(&directory, job)?;
            write_atomic(
                &directory,
                &id,
                &serde_json::to_vec(job).map_err(|_| "Unable to save resumed app")?,
            )
        })
    }
}

impl Journal for FileJournal {
    fn load(&mut self) -> Result<Enrollment, String> {
        let root = read_enrollment(&self.directory, &self.id)?;
        if self.candidate {
            root.product
                .pending
                .map(|pending| *pending.candidate)
                .ok_or("No pending installation".into())
        } else {
            Ok(root)
        }
    }

    fn save(&mut self, job: &Enrollment) -> Result<(), String> {
        if self.candidate {
            let mut root = read_enrollment(&self.directory, &self.id)?;
            let pending = root
                .product
                .pending
                .as_mut()
                .ok_or("No pending installation")?;
            if job.product.pending.is_some()
                || job.phone_id != root.phone_id
                || job.account != root.account
                || job.team_id != root.team_id
            {
                return Err("Pending installation identity changed".into());
            }
            pending.candidate = Box::new(job.clone());
            root.phase = job.phase.clone();
            root.attempt = job.attempt.clone();
            root.last_failure = job.last_failure.clone();
            if job.failure_evidence.is_some() {
                root.failure_evidence = job.failure_evidence.clone();
            }
            root.enabled = false;
            persist_account_hold(&self.directory, &root)?;
            return write_atomic(
                &self.directory,
                &self.id,
                &serde_json::to_vec(&root).map_err(|_| "Unable to record installation progress")?,
            );
        }
        // Stop all automatic jobs for this account before committing its failure.
        // A crash between writes is conservative: the hold exists and Running remains.
        persist_account_hold(&self.directory, job)?;
        let mut effective = job.clone();
        if super::admission::paused(&self.directory, &self.id)? {
            effective.enabled = false;
        }
        let bytes =
            serde_json::to_vec_pretty(&effective).map_err(|_| "Unable to encode renewal state")?;
        write_atomic(&self.directory, &self.id, &bytes)
    }
    fn session_observer(&self, attempt: &Attempt) -> Option<super::session_diagnostic::Observer> {
        let directory = self.directory.clone();
        let id = self.id.clone();
        let number = attempt.number;
        let candidate = self.candidate;
        Some(Box::new(move |report| {
            let mut job = read_enrollment(&directory, &id)?;
            if job.phase != Phase::Running
                || job.attempt.as_ref().is_none_or(|a| a.number != number)
            {
                return Err("Saved session report no longer belongs to this attempt".into());
            }
            if candidate {
                let pending = job
                    .product
                    .pending
                    .as_mut()
                    .ok_or("No pending installation")?;
                if pending
                    .candidate
                    .attempt
                    .as_ref()
                    .is_none_or(|a| a.number != number)
                {
                    return Err("Installation report is stale".into());
                }
                pending.candidate.attempt.as_mut().unwrap().session = Some(report.clone());
            }
            job.attempt.as_mut().unwrap().session = Some(report);
            write_atomic(
                &directory,
                &id,
                &serde_json::to_vec(&job).map_err(|_| "Unable to encode saved report")?,
            )
        }))
    }
}

pub(super) fn read_enrollment(directory: &Path, id: &str) -> Result<Enrollment, String> {
    let file =
        File::open(directory.join(format!("{id}.json"))).map_err(|_| "No readable enrollment")?;
    let mut job: Enrollment = serde_json::from_reader(file)
        .map_err(|_| "Invalid enrollment; manual recovery required")?;
    if job.version != 1
        || job.phone_id.is_empty()
        || job.account.is_empty()
        || job.team_id.is_empty()
        || job.watch_id.is_some() != job.watch.is_some()
        || job.archive.has_watch != job.watch.is_some()
    {
        return Err("Unsupported or inconsistent enrollment; manual recovery required".into());
    }
    job.archive
        .path(directory)
        .map_err(|_| "Invalid archive identity")?;
    if let Some(pending) = &job.product.pending {
        let candidate = &pending.candidate;
        if candidate.version != job.version
            || candidate.product.pending.is_some()
            || candidate.phone_id != job.phone_id
            || candidate.account != job.account
            || candidate.team_id != job.team_id
            || super::management::require_phone_job(candidate).is_err()
            || super::management::main_bundle(&candidate.archive)?
                != super::management::main_bundle(&job.archive)?
        {
            return Err("Pending installation is inconsistent; manual recovery required".into());
        }
        candidate
            .archive
            .path(directory)
            .map_err(|_| "Invalid pending archive identity")?;
    }
    if super::admission::paused(directory, id)? {
        job.enabled = false;
    }
    Ok(job)
}

pub(super) fn write_atomic(directory: &Path, id: &str, bytes: &[u8]) -> Result<(), String> {
    let staging = directory.join(format!("{id}.pending"));
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&staging)
        .map_err(|_| "Unable to stage renewal state")?;
    file.write_all(bytes)
        .map_err(|_| "Unable to write renewal state")?;
    file.sync_all()
        .map_err(|_| "Unable to flush renewal state")?;
    drop(file);
    fs::rename(staging, directory.join(format!("{id}.json")))
        .map_err(|_| "Unable to commit renewal state")?;
    #[cfg(unix)]
    File::open(directory)
        .and_then(|dir| dir.sync_all())
        .map_err(|_| "Unable to flush renewal directory")?;
    Ok(())
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct AccountHold {
    #[serde(default)]
    unconfirmed_team: bool,
    pub failure: Failure,
    pub session: Option<super::session_diagnostic::Diagnostic>,
    source: String,
    attempt: u64,
    key: String,
}
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct AccountState {
    hold: Option<AccountHold>,
    acknowledged: Vec<String>,
}
fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn account_key(account: &str) -> String {
    digest(account.to_lowercase().as_bytes())
}
fn source_key(job: &Enrollment) -> String {
    digest(format!("{}:{}:{}", job.phone_id, job.archive.sha256, job.team_id).as_bytes())
}
fn unconfirmed_source(phone: &str, archive: &super::archive::ArchiveIdentity) -> String {
    digest(format!("unconfirmed:{phone}:{}", archive.sha256).as_bytes())
}
pub(crate) fn unconfirmed_recovery_matches(
    directory: &Path,
    account: &str,
    phone: &str,
    archive: &super::archive::ArchiveIdentity,
) -> Result<bool, String> {
    Ok(account_hold(directory, account)?.is_some_and(|hold| {
        hold.unconfirmed_team && hold.source == unconfirmed_source(phone, archive)
    }))
}
pub(crate) fn persist_team_hold(
    directory: &Path,
    account: &str,
    phone: &str,
    archive: &super::archive::ArchiveIdentity,
    failure: Failure,
    at: i64,
) -> Result<(), String> {
    let mut state = read_account(directory, account)?;
    let source = unconfirmed_source(phone, archive);
    let key = digest(format!("{source}:{failure:?}:{at}").as_bytes());
    if state.hold.is_some() || state.acknowledged.contains(&key) {
        return Ok(());
    }
    state.hold = Some(AccountHold {
        unconfirmed_team: true,
        failure,
        session: None,
        source,
        attempt: 0,
        key,
    });
    save_account(directory, account, &state)
}
fn read_account(directory: &Path, account: &str) -> Result<AccountState, String> {
    match fs::read(
        directory
            .join("account-holds")
            .join(format!("{}.json", account_key(account))),
    ) {
        Ok(bytes) => {
            serde_json::from_slice(&bytes).map_err(|_| "Account recovery state is invalid".into())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(AccountState::default()),
        Err(_) => Err("Unable to read account recovery state".into()),
    }
}
fn save_account(directory: &Path, account: &str, state: &AccountState) -> Result<(), String> {
    let directory = directory.join("account-holds");
    fs::create_dir_all(&directory).map_err(|_| "Unable to persist account stop")?;
    write_atomic(
        &directory,
        &account_key(account),
        &serde_json::to_vec(state).map_err(|_| "Unable to encode account stop")?,
    )
}
/// Deletes an account's leftover recovery state. Only for accounts that no
/// longer have any saved setup.
pub(crate) fn forget_account(directory: &Path, account: &str) -> Result<(), String> {
    let path = directory
        .join("account-holds")
        .join(format!("{}.json", account_key(account)));
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("Unable to remove account recovery state".into()),
    }
}
pub(crate) fn account_hold(directory: &Path, account: &str) -> Result<Option<AccountHold>, String> {
    Ok(read_account(directory, account)?.hold)
}
pub(crate) fn recovery_matches(directory: &Path, job: &Enrollment) -> Result<bool, String> {
    Ok(account_hold(directory, &job.account)?.is_some_and(|hold| {
        hold.source
            == if hold.unconfirmed_team {
                unconfirmed_source(&job.phone_id, &job.archive)
            } else {
                source_key(job)
            }
    }))
}
pub(crate) fn persist_account_hold(directory: &Path, job: &Enrollment) -> Result<(), String> {
    let Some(failure) = job.last_failure.as_ref() else {
        return Ok(());
    };
    if !matches!(
        failure,
        Failure::MissingCredentials
            | Failure::MfaRequired
            | Failure::RateLimited
            | Failure::AccountSessionFailed
            | Failure::AccountMismatch
    ) && !(failure == &Failure::Interrupted
        && job.attempt.as_ref().is_none_or(|a| {
            matches!(
                a.stage,
                super::AttemptStage::Authenticating | super::AttemptStage::Signing
            )
        }))
    {
        return Ok(());
    }
    let mut state = read_account(directory, &job.account)?;
    let source = source_key(job);
    let key = digest(
        &serde_json::to_vec(&(
            &source,
            &job.last_failure,
            &job.failure_evidence,
            job.last_checked,
        ))
        .map_err(|_| "Unable to identify account failure")?,
    );
    if state.hold.is_some() || state.acknowledged.contains(&key) {
        return Ok(());
    }
    state.hold = Some(AccountHold {
        unconfirmed_team: false,
        failure: failure.clone(),
        session: job.attempt.as_ref().and_then(|a| a.session.clone()),
        source,
        attempt: job.attempt.as_ref().map_or(0, |a| a.number),
        key,
    });
    save_account(directory, &job.account, &state)
}
pub(crate) fn acknowledge_account_recovery(
    directory: &Path,
    job: &Enrollment,
) -> Result<(), String> {
    let mut state = read_account(directory, &job.account)?;
    let Some(hold) = &state.hold else {
        return Ok(());
    };
    // An older success or a different enrolled app cannot bypass this stop.
    if job.last_failure.is_some()
        || (if hold.unconfirmed_team {
            unconfirmed_source(&job.phone_id, &job.archive)
        } else {
            source_key(job)
        }) != hold.source
        || job.attempt.as_ref().is_none_or(|a| {
            !a.manual || a.stage != super::AttemptStage::Complete || a.number <= hold.attempt
        })
    {
        return Ok(());
    }
    state.acknowledged.push(hold.key.clone());
    state.hold = None;
    save_account(directory, &job.account, &state)
}
