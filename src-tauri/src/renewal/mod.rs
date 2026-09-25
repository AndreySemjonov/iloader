//! Automatic renewal: saved setups, their persisted state, and the policy and
//! orchestration for re-signing them in the background.

mod admission;
pub mod archive;
pub mod desktop;
pub mod host;
pub mod journal;
pub mod live;
pub mod management;
pub mod product;
pub mod session_diagnostic;
pub(crate) mod startup;

use serde::{Deserialize, Serialize};

pub const DAY: i64 = 24 * 60 * 60;
pub const RENEWAL_MARGIN: i64 = 3 * DAY;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Failure {
    Offline,
    MissingCredentials,
    AccountSessionFailed,
    MfaRequired,
    RateLimited,
    ArchiveMissing,
    ArchiveChanged,
    WrongDevice,
    Signing,
    Installation,
    Interrupted,
    UnknownExpiry,
    TrustRequired,
    CertificateActionRequired,
    AccountMismatch,
    LaunchConfirmationRequired,
    WatchNotSupported,
    DeviceLocked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    Never,
    Installed,
    Failed(Failure),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceEvidence {
    /// Expiry from the last successfully installed signed artifact. Not readback.
    pub profile_expiry: Option<i64>,
    pub last_success: Option<i64>,
    pub last_attempt: Option<i64>,
    pub outcome: Outcome,
}

impl DeviceEvidence {
    pub fn unknown() -> Self {
        Self {
            profile_expiry: None,
            last_success: None,
            last_attempt: None,
            outcome: Outcome::Never,
        }
    }
    fn due(&self, now: i64) -> bool {
        self.profile_expiry
            .is_some_and(|expiry| expiry.saturating_sub(now) <= RENEWAL_MARGIN)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    Idle,
    Running,
    NeedsAction(Failure),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttemptStage {
    Preparing,
    Discovering,
    Authenticating,
    Signing,
    InstallingPhone,
    InstallingWatch,
    Complete,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attempt {
    pub number: u64,
    #[serde(default)]
    pub manual: bool,
    pub started_at: i64,
    pub stage: AttemptStage,
    pub session: Option<session_diagnostic::Diagnostic>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureEvidence {
    pub failure: Failure,
    pub at: i64,
    pub attempt: Option<Attempt>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enrollment {
    #[serde(default)]
    pub product: product::ProductState,
    #[serde(default)]
    pub pilot_enabled: bool,
    #[serde(default)]
    pub attempt: Option<Attempt>,
    #[serde(default)]
    pub failure_evidence: Option<FailureEvidence>,
    pub version: u32,
    pub archive: archive::ArchiveIdentity,
    pub account: String,
    pub team_id: String,
    pub phone_id: String,
    pub watch_id: Option<String>,
    pub enabled: bool,
    #[serde(default)]
    pub launch_confirmed: bool,
    pub iphone: DeviceEvidence,
    pub watch: Option<DeviceEvidence>,
    pub phase: Phase,
    pub next_attempt: i64,
    pub retry_count: u32,
    pub last_checked: Option<i64>,
    pub last_failure: Option<Failure>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Paused,
    WaitUntil(i64),
    NeedsAction(Failure),
    Renew { iphone: bool, watch: bool },
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    Background,
    Manual,
}

impl Enrollment {
    pub fn decision(&self, now: i64, trigger: Trigger) -> Decision {
        if self.phase == Phase::Running {
            return Decision::NeedsAction(Failure::Interrupted);
        }
        if let Phase::NeedsAction(reason) = &self.phase {
            return Decision::NeedsAction(reason.clone());
        }
        if trigger == Trigger::Background {
            if !self.enabled {
                return Decision::Paused;
            }
            if !product::authorized(self) {
                return Decision::NeedsAction(Failure::LaunchConfirmationRequired);
            }
            if now < self.next_attempt {
                return Decision::WaitUntil(self.next_attempt);
            }
            if self.iphone.profile_expiry.is_none()
                || self
                    .watch
                    .as_ref()
                    .is_some_and(|w| w.profile_expiry.is_none())
            {
                return Decision::NeedsAction(Failure::UnknownExpiry);
            }
        }
        let iphone = trigger != Trigger::Background || self.iphone.due(now);
        let watch = self
            .watch
            .as_ref()
            .is_some_and(|w| trigger != Trigger::Background || w.due(now));
        if iphone || watch {
            return Decision::Renew { iphone, watch };
        }
        let earliest = std::iter::once(self.iphone.profile_expiry)
            .chain(self.watch.as_ref().map(|w| w.profile_expiry))
            .flatten()
            .min()
            .unwrap_or(now);
        Decision::WaitUntil(
            now.saturating_add(DAY)
                .min(earliest.saturating_sub(RENEWAL_MARGIN)),
        )
    }

    fn fail(&mut self, failure: Failure, now: i64) {
        self.last_failure = Some(failure.clone());
        self.failure_evidence = Some(FailureEvidence {
            failure: failure.clone(),
            at: now,
            attempt: self.attempt.clone(),
        });
        let safe_connectivity = matches!(failure, Failure::Offline | Failure::DeviceLocked)
            && self
                .attempt
                .as_ref()
                .is_some_and(|a| a.stage == AttemptStage::Discovering && a.session.is_none());
        if !safe_connectivity {
            if self.attempt.as_ref().is_some_and(|a| {
                matches!(
                    a.stage,
                    AttemptStage::InstallingPhone | AttemptStage::InstallingWatch
                )
            }) {
                self.launch_confirmed = false;
                if let Some(consent) = &mut self.product.authorization {
                    consent.validated_attempt = None;
                }
            }
            self.phase = Phase::NeedsAction(failure);
        } else {
            self.phase = Phase::Idle;
            self.retry_count = self.retry_count.saturating_add(1);
            let delay = (15 * 60_i64)
                .saturating_mul(1_i64 << self.retry_count.saturating_sub(1).min(5))
                .min(6 * 60 * 60);
            self.next_attempt = now.saturating_add(delay);
        }
    }
}

pub trait Clock {
    fn now(&self) -> i64;
}

/// Implementations must hold the same cross-process install lease as manual
/// installation for this entire call. `save` must commit durably before returning.
pub trait Journal {
    fn load(&mut self) -> Result<Enrollment, String>;
    fn save(&mut self, enrollment: &Enrollment) -> Result<(), String>;
    fn session_observer(&self, _attempt: &Attempt) -> Option<session_diagnostic::Observer> {
        None
    }
}

/// The backend is intentionally injectable. Background account access must use
/// secure storage, never prompt/revoke certificates, and classify MFA/429 as
/// action states. Discovery must verify BOTH enrolled identities on direct Wi-Fi.
/// `prepare` verifies the retained IPA before authentication and checks stable
/// bundle identities; `sign` must not install. Watch-only retries must not install
/// the phone. Signed artifacts must be cleaned up on drop, including error exits.
#[allow(async_fn_in_trait)]
pub trait Backend {
    type Signed;
    fn observe_session(&mut self, _observer: session_diagnostic::Observer) {}
    fn operation_timeout(&self, stage: AttemptStage) -> std::time::Duration {
        std::time::Duration::from_secs(match stage {
            AttemptStage::Preparing => 120,
            AttemptStage::Discovering => 90,
            AttemptStage::Authenticating => 125,
            AttemptStage::Signing => 240,
            AttemptStage::InstallingPhone | AttemptStage::InstallingWatch => 310,
            AttemptStage::Complete => 0,
        })
    }
    async fn prepare(&mut self, enrollment: &Enrollment) -> Result<(), Failure>;
    async fn session(&mut self, account: &str) -> Result<(), Failure>;
    async fn discover(&mut self, phone: &str, watch: Option<&str>) -> Result<(), Failure>;
    async fn sign(&mut self, enrollment: &Enrollment) -> Result<Self::Signed, Failure>;
    async fn install_iphone(&mut self, signed: &Self::Signed) -> Result<Option<i64>, Failure>;
    async fn install_watch(&mut self, signed: &Self::Signed) -> Result<Option<i64>, Failure>;
}

/// Shared native host dispatch: recheck admission under the install lease even
/// when another enrollment's failure changed the account after job selection.
pub(crate) async fn run_phone_host<B: Backend, C: Clock>(
    backend: &mut B,
    journal: &mut journal::FileJournal,
    clock: &C,
    trigger: Trigger,
) -> Result<Decision, String> {
    let job = journal.load()?;
    management::require_phone_job(&job).map_err(|_| "Automatic renewal is phone-only")?;
    if !job.enabled {
        return Ok(Decision::Paused);
    }
    if !job.pilot_enabled || !product::authorized(&job) {
        return Err("Turn on automatic renewal for this app first".into());
    }
    if let Some(hold) = journal::account_hold(journal.directory(), &job.account)? {
        return Ok(Decision::NeedsAction(hold.failure));
    }
    run(backend, journal, clock, trigger).await
}

/// No timer lives here. A single opt-in host invokes this after startup/wake or a
/// scheduled check. Interrupted work requires reconciliation, not blind replay.
pub async fn run<B: Backend, J: Journal, C: Clock>(
    backend: &mut B,
    journal: &mut J,
    clock: &C,
    trigger: Trigger,
) -> Result<Decision, String> {
    let mut job = journal.load()?;
    let decision = job.decision(clock.now(), trigger);
    let (iphone, watch) = match decision {
        Decision::Renew { iphone, watch } => (iphone, watch),
        Decision::NeedsAction(ref reason) => {
            job.phase = Phase::NeedsAction(reason.clone());
            job.last_failure = Some(reason.clone());
            journal.save(&job)?;
            return Ok(decision);
        }
        Decision::WaitUntil(next) => {
            if clock.now() >= job.next_attempt {
                job.last_checked = Some(clock.now());
            }
            job.next_attempt = next;
            journal.save(&job)?;
            return Ok(decision);
        }
        _ => return Ok(decision),
    };
    job.phase = Phase::Running;
    job.last_checked = Some(clock.now());
    job.last_failure = None;
    job.attempt = Some(Attempt {
        manual: trigger == Trigger::Manual,
        number: job
            .attempt
            .as_ref()
            .map_or(1, |a| a.number.saturating_add(1)),
        started_at: clock.now(),
        stage: AttemptStage::Preparing,
        session: None,
    });
    journal.save(&job)?;
    macro_rules! step {
        ($stage:expr, $future:expr) => {{
            job.attempt.as_mut().unwrap().stage = $stage;
            journal.save(&job)?; // durable phase before any possible submission
            let result = tokio::time::timeout(backend.operation_timeout($stage), Box::pin($future))
                .await
                .unwrap_or(Err(Failure::Interrupted));
            // Native session observer persists each stage into this same owned journal.
            job = journal.load()?;
            match result {
                Ok(value) => value,
                Err(failure) => {
                    if $stage == AttemptStage::InstallingPhone {
                        job.iphone.outcome = Outcome::Failed(failure.clone());
                    }
                    if $stage == AttemptStage::InstallingWatch {
                        job.watch.as_mut().unwrap().outcome = Outcome::Failed(failure.clone());
                    }
                    job.fail(failure, clock.now());
                    journal.save(&job)?;
                    return Ok(job.decision(clock.now(), Trigger::Background));
                }
            }
        }};
    }
    step!(AttemptStage::Preparing, backend.prepare(&job));
    step!(
        AttemptStage::Discovering,
        backend.discover(&job.phone_id, job.watch_id.as_deref())
    );
    if let Some(observer) = journal.session_observer(job.attempt.as_ref().unwrap()) {
        backend.observe_session(observer);
    }
    step!(AttemptStage::Authenticating, backend.session(&job.account));
    let signed = step!(AttemptStage::Signing, backend.sign(&job));
    if iphone {
        job.iphone.last_attempt = Some(clock.now());
        let expiry = step!(
            AttemptStage::InstallingPhone,
            backend.install_iphone(&signed)
        );
        job.iphone.profile_expiry = expiry;
        job.iphone.last_success = Some(clock.now());
        job.iphone.outcome = Outcome::Installed;
        journal.save(&job)?;
    }
    if watch {
        job.watch
            .as_mut()
            .ok_or("Missing enrolled Watch evidence")?
            .last_attempt = Some(clock.now());
        let expiry = step!(
            AttemptStage::InstallingWatch,
            backend.install_watch(&signed)
        );
        let evidence = job.watch.as_mut().unwrap();
        evidence.profile_expiry = expiry;
        evidence.last_success = Some(clock.now());
        evidence.outcome = Outcome::Installed;
        journal.save(&job)?;
    }
    job.phase = Phase::Idle;
    job.attempt.as_mut().unwrap().stage = AttemptStage::Complete;
    job.retry_count = 0;
    job.next_attempt = clock.now().saturating_add(DAY);
    if job.iphone.profile_expiry.is_none()
        || job
            .watch
            .as_ref()
            .is_some_and(|w| w.profile_expiry.is_none())
    {
        job.fail(Failure::UnknownExpiry, clock.now());
    } else {
        // Check earlier than a day if the new recorded expiry requires it.
        let earliest = std::iter::once(job.iphone.profile_expiry)
            .chain(job.watch.as_ref().map(|w| w.profile_expiry))
            .flatten()
            .min()
            .unwrap();
        job.next_attempt = job.next_attempt.min(
            earliest
                .saturating_sub(RENEWAL_MARGIN)
                .max(clock.now().saturating_add(60)),
        );
    }
    journal.save(&job)?;
    Ok(job.decision(clock.now(), Trigger::Background))
}

#[cfg(test)]
mod tests;
