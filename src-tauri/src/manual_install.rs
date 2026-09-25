use crate::error::AppError;
use idevice::IdeviceError;
use serde::Serialize;
use std::{future::Future, sync::Mutex, time::Duration};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Stage {
    Starting,
    AfcConnect,
    LocalPreparation,
    Upload,
    ProxyConnect,
    ProxyInstall,
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Cause {
    DeviceRejected,
    DeviceLocked,
    DeveloperModeDisabled,
    TrustRejected,
    WrongDevice,
    TimedOut,
    Socket,
    Tls,
    Afc,
    LocalFiles,
    Protocol,
    DeviceUnavailable,
    Unknown,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Detail {
    pub stage: Stage,
    pub cause: Cause,
    pub error_type: &'static str,
    pub error_name: Option<&'static str>,
    pub library_code: Option<i32>,
    pub library_subcode: Option<i32>,
    pub platform_codes: Vec<String>,
    pub domain_codes: Vec<String>,
    pub description_context: Vec<&'static str>,
    pub description_present: bool,
    pub description_unclassified: bool,
    pub outcome_uncertain: bool,
}

impl std::fmt::Display for Detail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Phone installation stopped: {:?}/{:?}/{}",
            self.stage, self.cause, self.error_type
        )
    }
}
impl Detail {
    fn new(stage: Stage, cause: Cause, error_type: &'static str) -> Self {
        Self {
            stage,
            cause,
            error_type,
            error_name: None,
            library_code: None,
            library_subcode: None,
            platform_codes: vec![],
            domain_codes: vec![],
            description_context: vec![],
            description_present: false,
            description_unclassified: false,
            outcome_uncertain: false,
        }
    }
}

impl From<isideload::sideload::install::InstallationStage> for Stage {
    fn from(value: isideload::sideload::install::InstallationStage) -> Self {
        use isideload::sideload::install::InstallationStage as S;
        match value {
            S::AfcConnect => Self::AfcConnect,
            S::LocalPreparation => Self::LocalPreparation,
            S::Upload => Self::Upload,
            S::ProxyConnect => Self::ProxyConnect,
            S::ProxyInstall => Self::ProxyInstall,
            S::Complete => Self::Complete,
        }
    }
}

pub async fn install(
    provider: &impl idevice::provider::IdeviceProvider,
    path: &std::path::Path,
) -> Result<(), AppError> {
    let phase = Mutex::new(Stage::Starting);
    let work = isideload::sideload::install::install_app_observed(
        provider,
        path,
        |_| {},
        |stage| *phase.lock().unwrap() = stage.into(),
    );
    await_result(&phase, work, Duration::from_secs(300)).await
}

async fn await_result(
    phase: &Mutex<Stage>,
    work: impl Future<Output = Result<(), rootcause::Report>>,
    limit: Duration,
) -> Result<(), AppError> {
    match tokio::time::timeout(limit, work).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(failure)) => Err(error(failure)),
        Err(_) => {
            let mut detail =
                Detail::new(*phase.lock().unwrap(), Cause::TimedOut, "DeadlineExceeded");
            detail.outcome_uncertain = matches!(
                detail.stage,
                Stage::ProxyInstall | Stage::Complete | Stage::Starting
            );
            Err(AppError::ManualInstall(detail))
        }
    }
}

pub fn error(failure: rootcause::Report) -> AppError {
    AppError::ManualInstall(classify(&failure))
}

fn classify(failure: &rootcause::Report) -> Detail {
    let mut detail = Detail::new(Stage::Starting, Cause::Unknown, "UnclassifiedReport");
    for node in failure.iter_reports() {
        if let Some(stage) =
            node.downcast_current_context::<isideload::sideload::install::InstallationStage>()
        {
            detail.stage = (*stage).into();
        }
        if let Some(isideload::SideloadError::IdeviceError(device)) =
            node.downcast_current_context::<isideload::SideloadError>()
        {
            classify_device(&mut detail, device);
        } else if let Some(device) = node.downcast_current_context::<IdeviceError>() {
            classify_device(&mut detail, device);
        } else if node.downcast_current_context::<std::io::Error>().is_some()
            && detail.cause == Cause::Unknown
        {
            detail.cause = Cause::LocalFiles;
            detail.error_type = "IoError";
        }
    }
    detail.outcome_uncertain = matches!(detail.stage, Stage::ProxyInstall | Stage::Starting)
        && matches!(
            detail.cause,
            Cause::Socket | Cause::TimedOut | Cause::Tls | Cause::Protocol | Cause::Unknown
        );
    detail
}

fn classify_device(detail: &mut Detail, error: &IdeviceError) {
    detail.library_code = Some(error.code());
    detail.library_subcode = Some(error.sub_code());
    let (cause, name) = match error {
        IdeviceError::ApplicationVerificationFailed(description) => {
            detail.error_name = Some("ApplicationVerificationFailed");
            description_details(detail, description);
            (Cause::DeviceRejected, "ApplicationVerificationFailed")
        }
        IdeviceError::InstallationProxy(
            idevice::installation_proxy::InstallationProxyError::OperationFailed(description),
        ) => {
            let token = description
                .split(|c: char| c.is_whitespace() || c == '(')
                .next()
                .unwrap_or("");
            detail.error_name = known_error_name(token);
            description_details(detail, description);
            (Cause::DeviceRejected, "InstallationProxy.OperationFailed")
        }
        IdeviceError::InstallationProxy(_) => (Cause::Protocol, "InstallationProxy"),
        IdeviceError::UnknownErrorType(description) => {
            let token = description
                .split(|c: char| c.is_whitespace() || c == '(')
                .next()
                .unwrap_or("");
            detail.error_name = known_error_name(token);
            description_details(detail, description);
            (Cause::DeviceRejected, "UnknownErrorType")
        }
        IdeviceError::DeveloperModeNotEnabled => {
            (Cause::DeveloperModeDisabled, "DeveloperModeNotEnabled")
        }
        IdeviceError::DeviceLocked => (Cause::DeviceLocked, "DeviceLocked"),
        IdeviceError::PasswordProtected => (Cause::DeviceLocked, "PasswordProtected"),
        IdeviceError::InvalidHostID => (Cause::TrustRejected, "InvalidHostID"),
        IdeviceError::UserDeniedPairing => (Cause::TrustRejected, "UserDeniedPairing"),
        IdeviceError::Timeout => (Cause::TimedOut, "Timeout"),
        IdeviceError::Socket(e)
            if e.get_ref()
                .is_some_and(|e| e.is::<crate::phone_transport::WrongPhone>()) =>
        {
            (Cause::WrongDevice, "WrongPhone")
        }
        IdeviceError::Socket(e) if e.kind() == std::io::ErrorKind::TimedOut => {
            (Cause::TimedOut, "SocketTimeout")
        }
        IdeviceError::Socket(_) => (Cause::Socket, "Socket"),
        IdeviceError::Rustls(_) => (Cause::Tls, "Tls"),
        IdeviceError::Afc(error) => {
            use idevice::afc::errors::AfcError as A;
            detail.error_name = match error {
                A::NoSpaceLeft => Some("NoSpaceLeft"),
                A::PermDenied => Some("PermissionDenied"),
                A::ObjectNotFound => Some("ObjectNotFound"),
                A::OpTimeout => Some("AfcTimeout"),
                _ => None,
            };
            (Cause::Afc, "Afc")
        }
        IdeviceError::NotFound => (Cause::DeviceUnavailable, "NotFound"),
        IdeviceError::DeviceNotFound => (Cause::DeviceUnavailable, "DeviceNotFound"),
        IdeviceError::ServiceNotFound => (Cause::DeviceUnavailable, "ServiceNotFound"),
        IdeviceError::NoEstablishedConnection => (Cause::Socket, "NoEstablishedConnection"),
        IdeviceError::UnexpectedResponse(_) => (Cause::Protocol, "UnexpectedResponse"),
        IdeviceError::Plist(_) => (Cause::Protocol, "Plist"),
        _ => (Cause::Unknown, "UnclassifiedIdeviceError"),
    };
    detail.cause = cause;
    detail.error_type = name;
}

fn known_error_name(token: &str) -> Option<&'static str> {
    // Exact protocol names only, not arbitrary device strings or identifiers.
    const NAMES: &[&str] = &[
        "ApplicationVerificationFailed",
        "BundleVerificationFailed",
        "ApplicationAlreadyInstalled",
        "ApplicationMoveFailed",
        "ApplicationSandboxFailed",
        "APIInternalError",
        "EmbeddedProfileInstallFailed",
        "ExecutableTwiddleFailed",
        "MissingBundleExecutable",
        "MissingBundleIdentifier",
        "MissingBundleVersion",
        "MissingBundlePath",
        "MissingContainer",
        "ContainerCreationFailed",
        "PackageExtractionFailed",
        "PackageInspectionFailed",
        "PackageMoveFailed",
        "PackagePatchFailed",
        "StageCreationFailed",
        "DeviceOSVersionTooLow",
        "DeviceFamilyNotSupported",
        "IncorrectArchitecture",
        "PluginCopyFailed",
        "InstallProhibited",
        "NotEntitled",
        "MissingPackagePath",
        "MissingApplicationIdentifier",
        "ApplicationSignatureInvalid",
        "MaximumNumberOfApplicationsReached",
    ];
    NAMES.iter().copied().find(|name| *name == token)
}

fn description_details(detail: &mut Detail, text: &str) {
    detail.description_present = !text.is_empty();
    // Only platform error-code literals, bounded and token-delimited. No free
    // text survives. Long identifiers sharing a prefix cannot be truncated into codes.
    for token in text.split(|c: char| !c.is_ascii_alphanumeric()) {
        if token.len() == 10
            && token[..6].eq_ignore_ascii_case("0xe800")
            && token[6..].bytes().all(|c| c.is_ascii_hexdigit())
        {
            let code = token.to_ascii_lowercase();
            if !detail.platform_codes.contains(&code) && detail.platform_codes.len() < 4 {
                detail.platform_codes.push(code);
            }
        }
    }
    for domain in [
        "MIInstallerErrorDomain",
        "MIInstallerErrorDomainLegacy",
        "IXUserPresentableErrorDomain",
        "NSOSStatusErrorDomain",
        "NSPOSIXErrorDomain",
        "AMDeviceErrorDomain",
    ] {
        let marker = format!("{domain} Code=");
        if let Some(start) = text.find(&marker) {
            if start > 0 && text.as_bytes()[start - 1].is_ascii_alphanumeric() {
                continue;
            }
            let number = text[start + marker.len()..]
                .split(|c: char| c != '-' && !c.is_ascii_digit())
                .next()
                .unwrap_or("");
            if number.len() <= 12
                && let Ok(code) = number.parse::<i32>()
            {
                detail.domain_codes.push(format!("{domain} Code={code}"));
            }
        }
    }
    // Match complete known diagnostic sentences, or their terminal clause after
    // ': '. Negated/incidental prefixes do not become inferred failure reasons.
    let clauses: Vec<_> = text.split(": ").collect();
    for (sentence, label) in [
        (
            "A valid provisioning profile for this executable was not found.",
            "profileNotFound",
        ),
        (
            "The executable was signed with invalid entitlements.",
            "invalidEntitlements",
        ),
        (
            "The code signature version is no longer supported.",
            "signatureVersionUnsupported",
        ),
        (
            "The identity used to sign the executable is no longer valid.",
            "signingIdentityInvalid",
        ),
        (
            "This device has reached the maximum number of installed apps using a free developer profile.",
            "freeAppLimit",
        ),
        ("Developer mode is not enabled.", "developerModeDisabled"),
        (
            "The executable does not contain an LC_UUID load command.",
            "missingExecutableUuid",
        ),
    ] {
        if clauses.iter().any(|clause| clause.trim() == sentence) {
            detail.description_context.push(label);
        }
    }
    detail.description_unclassified =
        detail.description_present && detail.description_context.is_empty();
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_manual_installer_error_reaches_safe_report() {
        let failure = rootcause::report!(isideload::SideloadError::IdeviceError(
            idevice::IdeviceError::InstallationProxy(
                idevice::installation_proxy::InstallationProxyError::OperationFailed(
                    "ApplicationVerificationFailed SECRET private path".into()
                )
            )
        ));
        let mut report = crate::renewal_report::RenewalReport {
            signing: crate::renewal_report::StepResult::Signed,
            iphone: crate::renewal_report::StepResult::Failed,
            watch: crate::renewal_report::StepResult::NotIncluded,
            iphone_profile_expiry: Some(12345),
            ..Default::default()
        };
        report.record_error(super::error(failure.into()));
        let json = serde_json::to_value(report).unwrap();
        assert_eq!(
            json["installationDetail"]["cause"], "deviceRejected",
            "actual manual installer discarded the installation_proxy failure"
        );
        assert!(!json.to_string().contains("SECRET"));
        assert_eq!(json["signing"], "signed");
        assert_eq!(json["watch"], "notIncluded");
        assert_eq!(json["iphoneProfileExpiry"], 12345);
    }

    #[test]
    fn exact_names_codes_and_sentences_survive_without_private_text_or_false_hints() {
        let error=IdeviceError::UnknownErrorType("BundleVerificationFailed (SECRET profile/path 0xe8008015 MIInstallerErrorDomain Code=13)".into());
        let mut detail = Detail::new(Stage::ProxyInstall, Cause::Unknown, "unknown");
        classify_device(&mut detail, &error);
        assert_eq!(detail.error_name, Some("BundleVerificationFailed"));
        assert_eq!(detail.platform_codes, ["0xe8008015"]);
        assert_eq!(detail.domain_codes, ["MIInstallerErrorDomain Code=13"]);
        assert!(detail.description_unclassified);
        assert!(!serde_json::to_string(&detail).unwrap().contains("SECRET"));
        for text in [
            "Not ApplicationVerificationFailed",
            "ApplicationVerificationFailedSECRET",
            "SECRETBundleVerificationFailed",
        ] {
            let mut detail = Detail::new(Stage::ProxyInstall, Cause::Unknown, "unknown");
            classify_device(&mut detail, &IdeviceError::UnknownErrorType(text.into()));
            assert!(detail.error_name.is_none());
        }
        let mut detail = Detail::new(Stage::ProxyInstall, Cause::Unknown, "unknown");
        description_details(
            &mut detail,
            "not The executable was signed with invalid entitlements. SECRET0xe8008015 0xe8008015SECRET",
        );
        assert!(detail.description_context.is_empty());
        assert!(detail.platform_codes.is_empty());
        description_details(
            &mut detail,
            "SECRET: The executable was signed with invalid entitlements.",
        );
        assert_eq!(detail.description_context, ["invalidEntitlements"]);
    }

    async fn proxy_fixture(response: plist::Dictionary) -> Result<(), rootcause::Report> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (client, mut server) = tokio::io::duplex(16384);
        let task = tokio::spawn(async move {
            let size = server.read_u32().await.unwrap();
            let mut bytes = vec![0; size as usize];
            server.read_exact(&mut bytes).await.unwrap();
            let command: plist::Dictionary = plist::from_bytes(&bytes).unwrap();
            assert_eq!(
                command.get("Command").and_then(|v| v.as_string()),
                Some("Install")
            );
            assert_eq!(
                command.get("PackagePath").and_then(|v| v.as_string()),
                Some("PublicStaging/Synthetic.app")
            );
            let mut encoded = vec![];
            plist::to_writer_xml(&mut encoded, &response).unwrap();
            server.write_u32(encoded.len() as u32).await.unwrap();
            server.write_all(&encoded).await.unwrap();
        });
        let mut proxy = idevice::installation_proxy::InstallationProxyClient::new(
            idevice::Idevice::new(Box::new(client), "synthetic"),
        );
        let result = proxy
            .install("PublicStaging/Synthetic.app", None)
            .await
            .map_err(isideload::SideloadError::IdeviceError)
            .map_err(|e| rootcause::report!(e).into());
        task.await.unwrap();
        result
    }

    #[tokio::test]
    async fn actual_proxy_reader_preserves_rejection_with_or_without_description_and_complete() {
        for description in [None, Some("SECRET /private/staging/app.app: 0xe8008015")] {
            let mut response = plist::Dictionary::new();
            response.insert("Error".into(), "ApplicationVerificationFailed".into());
            if let Some(description) = description {
                response.insert("ErrorDescription".into(), description.into());
            }
            let failure = proxy_fixture(response).await.unwrap_err();
            let AppError::ManualInstall(detail) = error(failure) else {
                panic!("wrong error")
            };
            assert_eq!(detail.error_name, Some("ApplicationVerificationFailed"));
            assert_eq!(detail.cause, Cause::DeviceRejected);
            if description.is_some() {
                assert_eq!(detail.platform_codes, ["0xe8008015"]);
            }
            assert!(!serde_json::to_string(&detail).unwrap().contains("SECRET"));
        }
        let mut response = plist::Dictionary::new();
        response.insert("Error".into(), "BundleVerificationFailed".into());
        let AppError::ManualInstall(detail) = error(proxy_fixture(response).await.unwrap_err())
        else {
            panic!("wrong error")
        };
        assert_eq!(detail.error_type, "UnknownErrorType");
        assert_eq!(detail.error_name, Some("BundleVerificationFailed"));
        let mut response = plist::Dictionary::new();
        response.insert("Status".into(), "Complete".into());
        assert!(proxy_fixture(response).await.is_ok());
    }

    #[test]
    fn backend_phase_contexts_preserve_upload_service_and_install_failures() {
        use isideload::sideload::install::InstallationStage as S;
        for (phase, expected) in [
            (S::AfcConnect, Stage::AfcConnect),
            (S::LocalPreparation, Stage::LocalPreparation),
            (S::Upload, Stage::Upload),
            (S::ProxyConnect, Stage::ProxyConnect),
            (S::ProxyInstall, Stage::ProxyInstall),
        ] {
            let failure = rootcause::report!(isideload::SideloadError::IdeviceError(
                IdeviceError::Socket(std::io::Error::other("SECRET"))
            ))
            .context(phase)
            .into();
            let AppError::ManualInstall(detail) = error(failure) else {
                panic!("wrong error")
            };
            assert_eq!(detail.stage, expected);
            assert_eq!(detail.cause, Cause::Socket);
            assert_eq!(detail.outcome_uncertain, expected == Stage::ProxyInstall);
        }
    }

    #[tokio::test]
    async fn timeout_keeps_last_phase_and_never_claims_installed_or_definite_device_outcome() {
        for phase in [Stage::Upload, Stage::ProxyConnect, Stage::ProxyInstall] {
            let state = Mutex::new(phase);
            let result = await_result(
                &state,
                std::future::pending(),
                Duration::from_millis(1),
            )
            .await;
            let AppError::ManualInstall(detail) = result.unwrap_err() else {
                panic!("wrong error")
            };
            assert_eq!(detail.stage, phase);
            assert_eq!(detail.cause, Cause::TimedOut);
            assert_eq!(detail.outcome_uncertain, phase == Stage::ProxyInstall);
        }
    }

    #[test]
    fn transport_afc_locked_and_developer_mode_are_not_signature_failures() {
        for (error, cause) in [
            (IdeviceError::Timeout, Cause::TimedOut),
            (IdeviceError::DeviceLocked, Cause::DeviceLocked),
            (
                IdeviceError::DeveloperModeNotEnabled,
                Cause::DeveloperModeDisabled,
            ),
            (
                IdeviceError::Afc(idevice::afc::errors::AfcError::NoSpaceLeft),
                Cause::Afc,
            ),
        ] {
            let mut detail = Detail::new(Stage::Upload, Cause::Unknown, "unknown");
            classify_device(&mut detail, &error);
            assert_eq!(detail.cause, cause);
            if cause == Cause::Afc {
                assert_eq!(detail.error_name, Some("NoSpaceLeft"));
            } else {
                assert!(detail.error_name.is_none());
            }
            assert!(detail.library_code.is_some());
        }
    }
}
