use std::time::{SystemTime, UNIX_EPOCH};

use apple_codesign::ProvisioningProfile;
use isideload::sideload::bundle::Bundle;
use serde::Serialize;

/// Safe to share: no device identifiers, addresses, account names, paths or
/// upstream errors. Expiry describes the signed artifact, not a device readback.
#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RenewalReport {
    pub(crate) connection: Option<crate::manual_wifi::CheckReport>,
    pub wifi_connected: bool,
    pub signing: StepResult,
    pub(crate) signing_detail: Option<crate::manual_signing::Detail>,
    pub(crate) installation_detail: Option<crate::manual_install::Detail>,
    pub iphone: StepResult,
    pub watch: StepResult,
    pub iphone_profile_expiry: Option<i64>,
    pub watch_profile_expiry: Option<i64>,
    pub completed_at: Option<i64>,
    pub problem: Option<RenewalProblem>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RenewalProblem {
    WifiRequired,
    SignInRequired,
    Busy,
    ConnectionFailed,
    SigningFailed,
    IphoneFailed,
    WatchFailed,
    LocalFiles,
}

#[derive(Default, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum StepResult {
    #[default]
    NotAttempted,
    Failed,
    Installed,
    Signed,
    NotIncluded,
}

impl RenewalReport {
    pub(crate) fn record_error(&mut self, error: crate::error::AppError) {
        use crate::error::AppError;
        self.problem = Some(match error {
            AppError::ManualInstall(detail) => {
                tracing::warn!(stage=?detail.stage,cause=?detail.cause,error_type=detail.error_type,
                    error_name=?detail.error_name,library_code=?detail.library_code,
                    library_subcode=?detail.library_subcode,platform_codes=?detail.platform_codes,
                    domain_codes=?detail.domain_codes,
                    description_context=?detail.description_context,
                    description_unclassified=detail.description_unclassified,
                    outcome_uncertain=detail.outcome_uncertain,"Manual Wi-Fi installation stopped (sanitized)");
                self.installation_detail = Some(detail);
                RenewalProblem::IphoneFailed
            }
            AppError::ManualSigning(detail) => {
                tracing::warn!(stage = ?detail.stage, component = ?detail.component,
                    cause = ?detail.cause, certificate = ?detail.certificate,
                    http_status = ?detail.http_status, service_code = ?detail.service_code,
                    "Manual Wi-Fi signing stopped (sanitized)");
                self.signing_detail = Some(detail);
                RenewalProblem::SigningFailed
            }
            AppError::NotLoggedIn => RenewalProblem::SignInRequired,
            AppError::NoDeviceSelected => RenewalProblem::WifiRequired,
            _ if self.watch == StepResult::Failed => RenewalProblem::WatchFailed,
            _ if self.iphone == StepResult::Failed => RenewalProblem::IphoneFailed,
            _ if self.signing == StepResult::Failed => RenewalProblem::SigningFailed,
            _ if self.problem.is_some() => self.problem.take().unwrap(),
            _ => RenewalProblem::ConnectionFailed,
        });
    }

    pub fn record_profiles(&mut self, bundle: &Bundle) {
        self.iphone_profile_expiry = bundle_expiry(bundle);
        self.watch_profile_expiry =
            earliest_complete(bundle.watch_apps().iter().map(bundle_expiry));
        if bundle.watch_apps().is_empty() {
            self.watch = StepResult::NotIncluded;
        }
    }
}

fn bundle_expiry(bundle: &Bundle) -> Option<i64> {
    let bytes = std::fs::read(bundle.bundle_dir.join("embedded.mobileprovision")).ok()?;
    let profile = ProvisioningProfile::parse(&bytes).ok()?;
    let date = profile.plist().get("ExpirationDate")?.as_date()?;
    let time: SystemTime = date.into();
    let expiry = i64::try_from(time.duration_since(UNIX_EPOCH).ok()?.as_secs()).ok()?;
    earliest_complete(
        std::iter::once(Some(expiry)).chain(bundle.app_extensions().iter().map(bundle_expiry)),
    )
}

fn earliest_complete(values: impl Iterator<Item = Option<i64>>) -> Option<i64> {
    values.collect::<Option<Vec<_>>>()?.into_iter().min()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_signing_failure_preserves_typed_certificate_cause() {
        let mut report = RenewalReport {
            signing: StepResult::Failed,
            ..Default::default()
        };
        let error: rootcause::Report = rootcause::report!(
            isideload::sideload::cert_identity::CertificateReuseError::MissingKey
        )
        .context("Failed to retrieve certificate identity")
        .into();
        let mapped =
            crate::manual_signing::result::<()>(crate::manual_signing::Stage::SignApp, Err(error));
        report.record_error(mapped.unwrap_err());
        let json = serde_json::to_value(report).unwrap();
        assert_eq!(
            json["signingDetail"]["cause"], "savedKeyMissing",
            "manual renewal erased the typed signing cause into generic SigningFailed"
        );
    }

    #[test]
    fn expiry_requires_every_component_and_uses_earliest() {
        assert_eq!(
            earliest_complete([Some(900), Some(300)].into_iter()),
            Some(300)
        );
        assert_eq!(earliest_complete([Some(900), None].into_iter()), None);
        assert_eq!(earliest_complete([].into_iter()), None);
    }

    #[test]
    fn partial_watch_failure_cannot_report_watch_install_success() {
        let report = RenewalReport {
            iphone: StepResult::Installed,
            watch: StepResult::Failed,
            ..Default::default()
        };
        let json = serde_json::to_value(report).unwrap();
        assert_eq!(json["iphone"], "installed");
        assert_eq!(json["watch"], "failed");
        assert!(json["watchProfileExpiry"].is_null());
    }
}
