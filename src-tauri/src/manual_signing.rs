//! Fixed public diagnostics for manual renewal. Never serialize upstream text,
//! attachments, URLs, paths, headers, account identifiers or bundle identifiers.
use isideload::SideloadError;
use rootcause::Report;
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Stage {
    CertificatePolicy,
    TeamLookup,
    DeviceRegistration,
    SignApp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Component {
    Certificate,
    Anisette,
    DeveloperApi,
    ProvisioningProfile,
    Bundle,
    CodeSigning,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Cause {
    PolicyUnavailable,
    SavedKeyMissing,
    SavedKeyUnavailable,
    CertificateLookupFailed,
    CertificateNotMatched,
    CertificateInvalidValidity,
    CertificateInactive,
    Authentication,
    AccountLocked,
    DeveloperRejected,
    AnisetteUnavailable,
    RateLimited,
    HttpRejected,
    RemoteUnavailable,
    NetworkTimeout,
    NetworkConnection,
    InvalidResponse,
    InvalidBundle,
    InvalidExecutable,
    SignatureSpaceUnavailable,
    InvalidProfile,
    CodeSigningFailed,
    LocalFiles,
    SecureStorage,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Detail {
    pub stage: Stage,
    pub component: Component,
    pub cause: Cause,
    pub certificate: Option<Cause>,
    pub http_status: Option<u16>,
    pub service_code: Option<i64>,
}

impl std::fmt::Display for Detail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Manual signing failed: {:?}/{:?}/{:?}",
            self.stage, self.component, self.cause
        )
    }
}

impl Detail {
    pub fn policy_unavailable() -> Self {
        Self {
            stage: Stage::CertificatePolicy,
            component: Component::Certificate,
            cause: Cause::PolicyUnavailable,
            certificate: None,
            http_status: None,
            service_code: None,
        }
    }
}

pub fn classify(stage: Stage, error: &Report) -> Detail {
    let mut detail = Detail {
        stage,
        component: match stage {
            Stage::TeamLookup | Stage::DeviceRegistration => Component::DeveloperApi,
            _ => Component::Unknown,
        },
        cause: Cause::Unknown,
        certificate: None,
        http_status: None,
        service_code: None,
    };
    let mut anisette = false;
    let mut invalid_bundle = false;
    let mut local_files = false;
    let mut secure_storage = false;
    let mut api_cause = None;
    let mut network_cause = None;
    let mut signing_cause = None;
    // Context matching is an exact allowlist from the pinned backend, never a
    // substring of formatted reports or attachments. Unknown wording stays unknown.
    for node in error.iter_reports() {
        let context = node
            .downcast_current_context::<&'static str>()
            .copied()
            .or_else(|| {
                node.downcast_current_context::<String>()
                    .map(String::as_str)
            });
        match context {
            Some(
                "Failed to get anisette headers"
                | "Failed to get anisette data for login"
                | "Failed to get anisette client info",
            ) => anisette = true,
            Some("Failed to retrieve certificate identity") => {
                detail.component = Component::Certificate
            }
            Some("Failed to download provisioning profile") => {
                detail.component = Component::ProvisioningProfile
            }
            Some("Failed to sign app") => detail.component = Component::CodeSigning,
            Some(
                "Failed to open application archive"
                | "Failed to extract application archive"
                | "Failed to read Payload directory"
                | "Failed to get main bundle identifier"
                | "Failed to get main app name"
                | "Failed to modify app bundle",
            ) => detail.component = Component::Bundle,
            _ => {}
        }
        if let Some(certificate) = node
            .downcast_current_context::<isideload::sideload::cert_identity::CertificateReuseError>()
        {
            use isideload::sideload::cert_identity::CertificateReuseError as E;
            detail.certificate = Some(match certificate {
                E::MissingKey => Cause::SavedKeyMissing,
                E::KeyUnavailable => Cause::SavedKeyUnavailable,
                E::LookupFailed => Cause::CertificateLookupFailed,
                E::NoMatch => Cause::CertificateNotMatched,
                E::InvalidValidity => Cause::CertificateInvalidValidity,
                E::Inactive => Cause::CertificateInactive,
            });
        }
        if let Some(cause) = node.downcast_current_context::<SideloadError>() {
            match cause {
                SideloadError::AuthWithMessage(code, _) => {
                    detail.service_code = Some(*code);
                    api_cause = Some(if *code == -20209 {
                        Cause::AccountLocked
                    } else {
                        Cause::Authentication
                    });
                }
                SideloadError::DeveloperError(code, _) => {
                    detail.service_code = Some(*code);
                    api_cause = Some(Cause::DeveloperRejected);
                }
                SideloadError::AnisetteNotProvisioned => anisette = true,
                SideloadError::InvalidBundle(_) => invalid_bundle = true,
                SideloadError::PlistParseError(_) => api_cause = Some(Cause::InvalidResponse),
                _ => {}
            }
        }
        if let Some(http) = node.downcast_current_context::<reqwest::Error>() {
            let (cause, status) = classify_http(http);
            detail.http_status = status;
            network_cause = Some(cause);
        }
        // Middleware and other standard errors can wrap reqwest without adding
        // a rootcause node. Walk typed Error::source without formatting it.
        let mut source = node.current_context_error_source();
        while let Some(inner) = source {
            if let Some(http) = inner.downcast_ref::<reqwest::Error>() {
                let (cause, status) = classify_http(http);
                detail.http_status = status;
                network_cause = Some(cause);
            }
            source = inner.source();
        }
        if let Some(sign) = node.downcast_current_context::<apple_codesign::CodeSignError>() {
            use apple_codesign::CodeSignError as E;
            signing_cause = Some(match sign {
                E::MachO { .. } => Cause::InvalidExecutable,
                E::NeedsCodeSignatureAllocation { .. } => Cause::SignatureSpaceUnavailable,
                E::ProvisioningProfile(_) => Cause::InvalidProfile,
                E::MissingInfoPlist(_)
                | E::MissingInfoString(_)
                | E::InvalidBundlePath(_)
                | E::Plist(_) => Cause::InvalidBundle,
                E::Io { .. } => Cause::LocalFiles,
                _ => Cause::CodeSigningFailed,
            });
            detail.component = if matches!(sign, E::ProvisioningProfile(_)) {
                Component::ProvisioningProfile
            } else {
                Component::CodeSigning
            };
        }
        secure_storage |= node.downcast_current_context::<keyring::Error>().is_some();
        local_files |= node.downcast_current_context::<std::io::Error>().is_some();
        invalid_bundle |= node
            .downcast_current_context::<zip::result::ZipError>()
            .is_some();
    }
    if detail.certificate.is_some() {
        detail.component = Component::Certificate;
    }
    if invalid_bundle {
        detail.component = Component::Bundle;
    }
    if anisette {
        detail.component = Component::Anisette;
    }
    detail.cause = network_cause
        .filter(|cause| *cause != Cause::Unknown)
        .or(api_cause)
        .or(detail.certificate)
        .or(signing_cause)
        .unwrap_or(if anisette {
            Cause::AnisetteUnavailable
        } else if invalid_bundle {
            Cause::InvalidBundle
        } else if secure_storage {
            Cause::SecureStorage
        } else if local_files {
            Cause::LocalFiles
        } else {
            Cause::Unknown
        });
    detail
}

fn classify_http(http: &reqwest::Error) -> (Cause, Option<u16>) {
    let status = http.status().map(|s| s.as_u16());
    let cause = match status {
        Some(429) => Cause::RateLimited,
        Some(401 | 403) => Cause::Authentication,
        Some(500..=599) => Cause::RemoteUnavailable,
        Some(_) => Cause::HttpRejected,
        None if http.is_timeout() => Cause::NetworkTimeout,
        None if http.is_connect() => Cause::NetworkConnection,
        None if http.is_decode() => Cause::InvalidResponse,
        _ => Cause::Unknown,
    };
    (cause, status)
}

/// Called at the real team, registration and sign_app boundaries, before the
/// general AppError conversion can flatten the structured rootcause chain.
pub fn result<T>(stage: Stage, value: Result<T, Report>) -> Result<T, crate::error::AppError> {
    value.map_err(|error| crate::error::AppError::ManualSigning(classify(stage, &error)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::renewal_report::{RenewalReport, StepResult};

    fn final_report(stage: Stage, error: Report) -> serde_json::Value {
        let error = result::<()>(stage, Err(error)).unwrap_err();
        // Exercise the same classifier -> AppError -> final report path as renew_wifi.
        let safe_error = serde_json::to_string(&error).unwrap();
        assert!(!safe_error.contains("SECRET"));
        let mut report = RenewalReport {
            signing: StepResult::Failed,
            ..Default::default()
        };
        report.record_error(error);
        let json = serde_json::to_value(report).unwrap();
        assert_eq!(json["problem"], "signingFailed");
        assert_eq!(json["iphone"], "notAttempted");
        assert_eq!(json["watch"], "notAttempted");
        assert!(json["iphoneProfileExpiry"].is_null());
        assert!(!json.to_string().contains("SECRET"));
        json
    }

    #[test]
    fn manual_boundaries_preserve_stage_api_codes_and_redact_messages() {
        for (stage, label) in [
            (Stage::TeamLookup, "teamLookup"),
            (Stage::DeviceRegistration, "deviceRegistration"),
            (Stage::SignApp, "signApp"),
        ] {
            let error = rootcause::report!(SideloadError::DeveloperError(
                1102,
                "SECRET account URL token".into()
            ))
            .attach("SECRET request body")
            .into();
            let json = final_report(stage, error);
            assert_eq!(json["signingDetail"]["stage"], label);
            assert_eq!(json["signingDetail"]["cause"], "developerRejected");
            assert_eq!(json["signingDetail"]["serviceCode"], 1102);
        }
        let json = final_report(
            Stage::TeamLookup,
            rootcause::report!(SideloadError::AuthWithMessage(
                -20209,
                "SECRET username".into()
            ))
            .into(),
        );
        assert_eq!(json["signingDetail"]["cause"], "accountLocked");
    }

    #[test]
    fn all_certificate_policy_failures_remain_distinct_through_manual_report() {
        use isideload::sideload::cert_identity::CertificateReuseError as E;
        for (error, cause) in [
            (E::MissingKey, "savedKeyMissing"),
            (E::KeyUnavailable, "savedKeyUnavailable"),
            (E::LookupFailed, "certificateLookupFailed"),
            (E::NoMatch, "certificateNotMatched"),
            (E::InvalidValidity, "certificateInvalidValidity"),
            (E::Inactive, "certificateInactive"),
        ] {
            let json = final_report(
                Stage::SignApp,
                rootcause::report!(error)
                    .context("Failed to retrieve certificate identity")
                    .attach("SECRET key path")
                    .into(),
            );
            assert_eq!(json["signingDetail"]["cause"], cause);
            assert_eq!(json["signingDetail"]["certificate"], cause);
            assert_eq!(json["signingDetail"]["component"], "certificate");
        }
    }

    #[test]
    fn unknown_text_cannot_spoof_causes_and_anisette_is_not_a_certificate_diagnosis() {
        let json = final_report(
            Stage::TeamLookup,
            rootcause::report!("Failed to get anisette headers")
                .attach("SECRET server message rate limit password certificate missing")
                .into(),
        );
        assert_eq!(json["signingDetail"]["component"], "anisette");
        assert_eq!(json["signingDetail"]["cause"], "anisetteUnavailable");
        assert!(json["signingDetail"]["certificate"].is_null());
        let unknown = final_report(
            Stage::SignApp,
            rootcause::report!("SECRET Failed to get anisette headers 429 missing key".to_string())
                .into(),
        );
        assert_eq!(unknown["signingDetail"]["cause"], "unknown");
        assert_eq!(unknown["signingDetail"]["component"], "unknown");
    }

    #[test]
    fn unsigned_executable_bundle_and_profile_failures_are_separate() {
        use apple_codesign::CodeSignError as E;
        let json = final_report(
            Stage::SignApp,
            rootcause::report!(E::NeedsCodeSignatureAllocation {
                path: "SECRET original.ipa".into(),
                signature_len: 12345
            })
            .context("Failed to sign app")
            .into(),
        );
        assert_eq!(json["signingDetail"]["cause"], "signatureSpaceUnavailable");
        assert_eq!(json["signingDetail"]["component"], "codeSigning");
        let json = final_report(
            Stage::SignApp,
            rootcause::report!(SideloadError::InvalidBundle("SECRET Info.plist".into())).into(),
        );
        assert_eq!(json["signingDetail"]["cause"], "invalidBundle");
        let json = final_report(
            Stage::SignApp,
            rootcause::report!(E::ProvisioningProfile("SECRET profile".into()))
                .context("Failed to sign app")
                .into(),
        );
        assert_eq!(json["signingDetail"]["cause"], "invalidProfile");
        assert_eq!(json["signingDetail"]["component"], "provisioningProfile");
        let json = final_report(
            Stage::SignApp,
            rootcause::report!(SideloadError::DeveloperError(123, "SECRET".into()))
                .context("Failed to download provisioning profile")
                .into(),
        );
        assert_eq!(json["signingDetail"]["component"], "provisioningProfile");
    }

    // Synthetic loopback HTTP only. Never connects to a phone, account or remote service.
    async fn mock_http_error(status: u16) -> reqwest::Error {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            socket.read(&mut request).await.unwrap();
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 {status} Mock\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        });
        let error = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap()
            .get(format!("http://{addr}/SECRET?token=SECRET"))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap_err();
        server.await.unwrap();
        error
    }

    #[tokio::test]
    async fn typed_http_status_survives_wrappers_and_anisette_context_without_urls() {
        #[derive(Debug, thiserror::Error)]
        #[error("SECRET middleware wrapper")]
        struct Wrapper(#[source] reqwest::Error);
        for (status, cause) in [
            (429, "rateLimited"),
            (401, "authentication"),
            (503, "remoteUnavailable"),
            (400, "httpRejected"),
        ] {
            let json = final_report(
                Stage::TeamLookup,
                rootcause::report!(Wrapper(mock_http_error(status).await))
                    .context("Failed to get anisette headers")
                    .into(),
            );
            assert_eq!(json["signingDetail"]["cause"], cause);
            assert_eq!(json["signingDetail"]["component"], "anisette");
            assert_eq!(json["signingDetail"]["httpStatus"], status);
        }
        {
            let error = rootcause::report!(mock_http_error(429).await)
                .context(isideload::sideload::cert_identity::CertificateReuseError::LookupFailed)
                .into();
            let json = final_report(Stage::SignApp, error);
            assert_eq!(json["signingDetail"]["cause"], "rateLimited");
            assert_eq!(
                json["signingDetail"]["certificate"],
                "certificateLookupFailed"
            );
        }
    }

    #[test]
    fn successful_manual_boundary_has_no_failure_and_policy_failure_is_safe() {
        assert_eq!(result(Stage::TeamLookup, Ok(42)).unwrap(), 42);
        let mut report = RenewalReport::default();
        assert!(serde_json::to_value(&report).unwrap()["signingDetail"].is_null());
        report.record_error(crate::error::AppError::ManualSigning(
            Detail::policy_unavailable(),
        ));
        assert_eq!(
            serde_json::to_value(report).unwrap()["signingDetail"]["cause"],
            "policyUnavailable"
        );
    }
}
