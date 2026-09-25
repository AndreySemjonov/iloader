//! Explicit product authorization, separate from historical human launch evidence.
use super::Enrollment;
use super::{
    AttemptStage, Backend, Clock, Failure, Journal, Phase, Trigger, archive,
    journal::{self, FileJournal},
    management::{self, Catalog},
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductState {
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub phone_name: Option<String>,
    #[serde(default)]
    pub authorization: Option<Authorization>,
    #[serde(default)]
    pub pending: Option<Pending>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authorization {
    pub consent_at: i64,
    pub archive_sha256: String,
    pub validated_attempt: Option<u64>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    pub candidate: Box<Enrollment>,
    pub enable_after_success: bool,
    pub recovery: bool,
}

pub fn authorized(job: &Enrollment) -> bool {
    job.product.pending.is_none()
        && (job.launch_confirmed
            || job.product.authorization.as_ref().is_some_and(|consent| {
                consent.archive_sha256 == job.archive.sha256 && consent.validated_attempt.is_some()
            }))
}

pub(crate) trait Services {
    type Engine: Backend;
    fn engine(&mut self) -> &mut Self::Engine;
    async fn selected_team(&mut self, account: &str) -> Result<String, Failure>;
    fn authorize_host_first_use(&mut self) -> Result<(), String>;
}
pub(crate) enum Action {
    Install {
        source: PathBuf,
        phone: String,
        name: String,
        account: String,
    },
    Renew {
        id: String,
    },
    Replace {
        id: String,
        source: PathBuf,
    },
    Recover {
        id: String,
    },
    Resume {
        id: String,
    },
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(Debug)]
pub struct ResultView {
    pub id: String,
    pub reused: bool,
    pub enabled: bool,
}

/// Shared command orchestration: owns the real install lease from local selection
/// through all external phases, host preference persistence, and final commit.
pub(crate) async fn execute<S: Services, C: Clock>(
    directory: &Path,
    services: &mut S,
    clock: &C,
    action: Action,
) -> Result<ResultView, String> {
    let catalog = Catalog::acquire(directory)?;
    let (id, mut job, replacement, enable, recovery, fresh) = match action {
        Action::Install {
            source,
            phone,
            name,
            account,
        } => {
            let (id, existing) = catalog.product_selection(&source, &phone, &name, &account)?;
            if existing {
                let job = catalog.job(&id)?;
                return Ok(ResultView {
                    id,
                    reused: true,
                    enabled: job.enabled,
                });
            }
            let job = resolve_draft(&catalog, &id, directory, services, clock, false).await?;
            (id, job, None, true, false, true)
        }
        Action::Resume { id } => {
            let job = catalog.job(&id)?;
            if job.product.pending.is_some() {
                let mut journal = catalog.into_journal(&id)?;
                return finish(&id, &mut journal, services, clock, true);
            }
            catalog.validate_enable(&id, clock.now())?;
            services.authorize_host_first_use()?;
            catalog.enable_reviewed(&id, clock.now())?;
            return Ok(ResultView {
                id,
                reused: false,
                enabled: true,
            });
        }
        Action::Renew { id } => {
            let job = catalog.job(&id)?;
            let enable = job.enabled;
            (id, job, None, enable, false, false)
        }
        Action::Replace { id, source } => {
            let job = catalog.job(&id)?;
            let enable = job.enabled;
            (id, job, Some(source), enable, false, false)
        }
        Action::Recover { id } => {
            let (job, fresh) = match catalog.job(&id) {
                Ok(job) => (job, false),
                Err(_) => (
                    resolve_draft(&catalog, &id, directory, services, clock, true).await?,
                    true,
                ),
            };
            let enable = fresh
                || job
                    .product
                    .pending
                    .as_ref()
                    .map_or(job.enabled, |p| p.enable_after_success);
            (id, job, None, enable, true, fresh)
        }
    };
    management::require_phone_job(&job)
        .map_err(|_| "Automatic renewal supports phone-only IPAs")?;
    if job.product.pending.is_some() && !recovery {
        return Err("An earlier installation needs review. Use Resume to finish validated setup, or Recover & renew from View details.".into());
    }
    if journal::account_hold(&directory.join("renewal"), &job.account)?.is_some()
        && (!recovery || !journal::recovery_matches(&directory.join("renewal"), &job)?)
    {
        return Err("This account is stopped. Use Recover & renew on its failing app; other apps and IPA replacement cannot bypass the stop.".into());
    }
    job.archive
        .verify(&directory.join("renewal"))
        .map_err(|_| "The retained original IPA is missing or changed")?;
    let mut candidate = job.clone();
    candidate.product.pending = None;
    if let Some(source) = replacement {
        let proposed =
            archive::inspect(&source).map_err(|_| "Choose a readable valid replacement IPA")?;
        management::require_phone_archive(&proposed)?;
        if management::main_bundle(&proposed)? != management::main_bundle(&job.archive)? {
            return Err("Replacement IPA must contain this same app".into());
        }
        let retained = archive::retain(&source, &directory.join("renewal"))
            .map_err(|_| "Unable to retain replacement IPA")?;
        if retained != proposed {
            return Err("Replacement IPA changed while being retained".into());
        }
        candidate.archive = retained;
        candidate.product.display_name = archive::display_name(
            &candidate
                .archive
                .verify(&directory.join("renewal"))
                .map_err(|_| "Replacement IPA is missing or changed")?,
        );
        candidate.launch_confirmed = false;
    }
    candidate.product.authorization = Some(Authorization {
        consent_at: clock.now(),
        archive_sha256: candidate.archive.sha256.clone(),
        validated_attempt: None,
    });
    candidate.enabled = false;
    candidate.phase = Phase::Idle;
    candidate.last_failure = None;
    job.product.pending = Some(Pending {
        candidate: Box::new(candidate),
        enable_after_success: enable,
        recovery,
    });
    job.enabled = false;
    // A pending record is never runnable by the host, including after a crash.
    if fresh {
        // Clear an old removal pause only before this explicit new installation.
        // A Pause arriving during external work remains authoritative.
        super::admission::resume(&directory.join("renewal"), &id, || {
            catalog.save_job(&id, &job)
        })?;
    } else {
        catalog.save_job(&id, &job)?;
    }
    let mut journal = catalog.into_journal(&id)?;
    journal.candidate_mode(true);
    super::run(services.engine(), &mut journal, clock, Trigger::Manual).await?;
    journal.candidate_mode(false);
    finish(&id, &mut journal, services, clock, false)
}

async fn resolve_draft<S: Services, C: Clock>(
    catalog: &Catalog,
    id: &str,
    directory: &Path,
    services: &mut S,
    clock: &C,
    recovery: bool,
) -> Result<Enrollment, String> {
    let draft = catalog.draft(id)?;
    let retained = directory.join("renewal");
    let path = draft
        .archive
        .verify(&retained)
        .map_err(|_| "The retained IPA is missing or changed")?;
    if journal::account_hold(&retained, &draft.account)?.is_some()
        && (!recovery
            || !journal::unconfirmed_recovery_matches(
                &retained,
                &draft.account,
                &draft.phone_id,
                &draft.archive,
            )?)
    {
        return Err("Recover the failing app before preparing another account request".into());
    }
    catalog.team_started(id, clock.now())?;
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        services.selected_team(&draft.account),
    )
    .await
    .unwrap_or(Err(Failure::Interrupted));
    let team = match result {
        Ok(team) => {
            catalog.team_finished(id, None)?;
            team
        }
        Err(failure) => {
            catalog.team_finished(id, Some(failure.clone()))?;
            return Err(format!(
                "Account preparation stopped: {failure:?}. Review this app before using Recover & renew."
            ));
        }
    };
    let mut job = catalog.confirm(id, &team, None)?;
    job.product.phone_name = Some(draft.phone_name);
    job.product.display_name = archive::display_name(&path);
    catalog.save_job(id, &job)?;
    Ok(job)
}

fn validated(candidate: &Enrollment, now: i64) -> Result<(), String> {
    management::require_installed(candidate, now)?;
    let ready = candidate.attempt.as_ref().is_some_and(|a| {
        a.manual
            && a.stage == AttemptStage::Complete
            && a.session.as_ref().is_some_and(|s| {
                s.stage == super::session_diagnostic::Stage::Ready
                    && s.cause.is_none()
                    && s.credential_read_succeeded
                    && s.auth_started
            })
    });
    if !ready {
        return Err("Automatic renewal was not enabled: a complete install and reusable saved-account session are required.".into());
    }
    Ok(())
}
fn finish<S: Services, C: Clock>(
    id: &str,
    journal: &mut FileJournal,
    services: &mut S,
    clock: &C,
    explicit_resume: bool,
) -> Result<ResultView, String> {
    let original = journal.load()?;
    let pending = original
        .product
        .pending
        .as_ref()
        .ok_or("No installation awaits completion")?;
    let mut candidate = (*pending.candidate).clone();
    validated(&candidate, clock.now())?;
    management::require_phone_job(&candidate)
        .map_err(|_| "Automatic renewal supports phone-only IPAs")?;
    if candidate.phone_id != original.phone_id
        || candidate.account != original.account
        || candidate.team_id != original.team_id
        || management::main_bundle(&candidate.archive)?
            != management::main_bundle(&original.archive)?
    {
        return Err("Pending installation no longer matches this app".into());
    }
    candidate
        .archive
        .verify(journal.directory())
        .map_err(|_| "Validated IPA is missing or changed")?;
    if journal::account_hold(journal.directory(), &candidate.account)?.is_some() {
        if !pending.recovery
            || candidate.archive != original.archive
            || !journal::recovery_matches(journal.directory(), &candidate)?
        {
            return Err("Account recovery is required before enabling this app".into());
        }
        journal::acknowledge_account_recovery(journal.directory(), &candidate)?;
        if journal::account_hold(journal.directory(), &candidate.account)?.is_some() {
            return Err("Account recovery did not complete".into());
        }
    }
    services.authorize_host_first_use().map_err(|_| "Installation finished, but automatic-renewal preferences could not be saved. It remains paused; use Resume to finish setup without reinstalling.")?;
    let consent = candidate
        .product
        .authorization
        .as_mut()
        .ok_or("Installation authorization is missing")?;
    if consent.archive_sha256 != candidate.archive.sha256 {
        return Err("Installation authorization does not match this IPA".into());
    }
    consent.validated_attempt = Some(candidate.attempt.as_ref().unwrap().number);
    candidate.pilot_enabled = true;
    candidate.enabled = pending.enable_after_success || explicit_resume;
    candidate.product.pending = None;
    if explicit_resume {
        // Explicit Resume may clear a per-app pause, but never an account stop.
        journal.save_resuming(&candidate)?;
    } else {
        journal.save(&candidate)?;
    }
    let saved = journal.load()?;
    Ok(ResultView {
        id: id.into(),
        reused: false,
        enabled: saved.enabled,
    })
}

#[cfg(test)]
mod tests;
