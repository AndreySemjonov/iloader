use super::*;
use std::sync::{Arc, Mutex};
#[derive(Default)]
struct External {
    calls: Vec<Stage>,
    stop: Option<(Stage, SessionError)>,
    empty: bool,
    hang: bool,
    wrong_account: bool,
    wrong_team: bool,
}
impl External {
    fn step(&mut self, stage: Stage) -> Result<(), SessionError> {
        self.calls.push(stage);
        if let Some((stop, error)) = &self.stop {
            if *stop == stage {
                return Err(error.clone());
            }
        }
        Ok(())
    }
}
impl Provider for External {
    type Anisette = ();
    type Account = String;
    type Developer = ();
    type Team = String;
    type Output = (String, String);
    fn password(&mut self, account: &str) -> Result<String, SessionError> {
        assert_eq!(account, "a@example.invalid");
        self.step(Stage::CredentialRead)?;
        Ok(if self.empty {
            String::new()
        } else {
            "private-password-sentinel".into()
        })
    }
    fn anisette(&mut self) -> Result<(), SessionError> {
        self.step(Stage::AnisetteInit)
    }
    async fn account(&mut self, email: &str, _: ()) -> Result<String, SessionError> {
        self.step(Stage::AccountBuild)?;
        Ok(if self.wrong_account {
            "other@example.invalid".into()
        } else {
            email.into()
        })
    }
    async fn authenticate(&mut self, _: &mut String, password: &str) -> Result<(), SessionError> {
        assert_eq!(password, "private-password-sentinel");
        self.step(Stage::InitialAuthentication)?;
        if self.hang {
            std::future::pending::<()>().await;
        }
        Ok(())
    }
    fn email(account: &String) -> &str {
        account
    }
    async fn developer(&mut self, _: &mut String) -> Result<(), SessionError> {
        self.step(Stage::DeveloperSession)
    }
    async fn team(&mut self, _: &mut (), team: &str) -> Result<String, SessionError> {
        self.step(Stage::TeamLookup)?;
        Ok(if self.wrong_team {
            "OTHER".into()
        } else {
            team.into()
        })
    }
    fn team_id(team: &String) -> &str {
        team
    }
    fn finish(_: (), email: String, team: String) -> Self::Output {
        (email, team)
    }
}
fn capture() -> (Arc<Mutex<Vec<Diagnostic>>>, Option<Observer>) {
    let reports = Arc::new(Mutex::new(Vec::new()));
    let output = reports.clone();
    (
        reports,
        Some(Box::new(move |r| {
            output.lock().unwrap().push(r);
            Ok(())
        })),
    )
}
fn unknown() -> SessionError {
    SessionError::external(
        &rootcause::report!("private-server-response-token URL credential-target").into(),
    )
}
#[test]
fn unknown_auth_error_is_not_reported_as_missing_password() {
    assert_eq!(unknown().failure, Failure::AccountSessionFailed);
}
#[tokio::test]
async fn each_actual_session_boundary_reports_failure_and_stops_before_next_operation() {
    let stages = [
        Stage::CredentialRead,
        Stage::AnisetteInit,
        Stage::AccountBuild,
        Stage::InitialAuthentication,
        Stage::DeveloperSession,
        Stage::TeamLookup,
    ];
    for (index, stage) in stages.into_iter().enumerate() {
        let error = if stage == Stage::CredentialRead {
            SessionError::keyring(keyring::Error::NoEntry)
        } else {
            unknown()
        };
        let mut external = External {
            stop: Some((stage, error.clone())),
            ..Default::default()
        };
        let (reports, mut observer) = capture();
        assert_eq!(
            recover(
                &mut external,
                "a@example.invalid",
                "TEAM",
                StoragePolicy::Allowed,
                &mut observer,
                Duration::from_secs(1)
            )
            .await,
            Err(error.failure)
        );
        assert_eq!(external.calls, stages[..=index]);
        let reports = reports.lock().unwrap();
        let last = reports.last().unwrap();
        assert_eq!((last.stage, last.cause), (stage, Some(error.cause)));
        assert_eq!(last.credential_read_succeeded, index > 0);
        assert_eq!(last.auth_started, index >= 3);
        let serialized = serde_json::to_string(&*reports).unwrap();
        for forbidden in [
            "private-",
            "example.invalid",
            "credential-target",
            "URL",
            "TEAM",
        ] {
            assert!(!serialized.contains(forbidden));
        }
    }
}
#[tokio::test]
async fn policy_and_keyring_errors_remain_distinct_without_authentication() {
    for (policy, cause) in [
        (StoragePolicy::Disabled, Cause::StorageDisabled),
        (StoragePolicy::Unavailable, Cause::PreferencesUnavailable),
    ] {
        let (reports, mut observer) = capture();
        let mut external = External::default();
        assert_eq!(
            recover(
                &mut external,
                "a@example.invalid",
                "TEAM",
                policy,
                &mut observer,
                Duration::from_secs(1)
            )
            .await,
            Err(Failure::MissingCredentials)
        );
        assert!(external.calls.is_empty());
        assert_eq!(reports.lock().unwrap().last().unwrap().cause, Some(cause));
    }
    for (error, expected) in [
        (keyring::Error::NoEntry, Cause::CredentialNotFound),
        (
            keyring::Error::BadEncoding(b"private-blob".to_vec()),
            Cause::CredentialDecodeFailed,
        ),
        (
            keyring::Error::NoStorageAccess(Box::new(std::io::Error::other("private-access"))),
            Cause::CredentialAccessDenied,
        ),
        (
            keyring::Error::PlatformFailure(Box::new(std::io::Error::other("private-platform"))),
            Cause::CredentialReadFailed,
        ),
    ] {
        let (reports, mut observer) = capture();
        let mut external = External {
            stop: Some((Stage::CredentialRead, SessionError::keyring(error))),
            ..Default::default()
        };
        assert_eq!(
            recover(
                &mut external,
                "a@example.invalid",
                "TEAM",
                StoragePolicy::Allowed,
                &mut observer,
                Duration::from_secs(1)
            )
            .await,
            Err(Failure::MissingCredentials)
        );
        let reports = reports.lock().unwrap();
        assert_eq!(reports.last().unwrap().cause, Some(expected));
        assert_eq!(external.calls, [Stage::CredentialRead]);
        assert!(
            !serde_json::to_string(&*reports)
                .unwrap()
                .contains("private")
        );
    }
}
fn http(status: u16) -> SessionError {
    let response = tauri::http::Response::builder()
        .status(status)
        .body(String::new())
        .unwrap();
    let error = reqwest::Response::from(response)
        .error_for_status()
        .unwrap_err();
    SessionError::external(&rootcause::report!(error).context("private-context").into())
}
#[tokio::test]
async fn typed_mfa_and_http_failures_keep_stage_and_never_reach_signer() {
    let mfa = SessionError::external(
        &rootcause::report!(isideload::auth::apple_account::NoninteractiveLoginError)
            .context("private-context")
            .into(),
    );
    for (error, expected, cause, status) in [
        (mfa, Failure::MfaRequired, Cause::MfaRequired, None),
        (
            http(429),
            Failure::RateLimited,
            Cause::RateLimited,
            Some(429),
        ),
        (
            http(404),
            Failure::AccountSessionFailed,
            Cause::HttpRejected,
            Some(404),
        ),
    ] {
        let (reports, mut observer) = capture();
        let mut external = External {
            stop: Some((Stage::InitialAuthentication, error)),
            ..Default::default()
        };
        assert_eq!(
            recover(
                &mut external,
                "a@example.invalid",
                "TEAM",
                StoragePolicy::Allowed,
                &mut observer,
                Duration::from_secs(1)
            )
            .await,
            Err(expected)
        );
        assert!(!external.calls.contains(&Stage::DeveloperSession));
        let reports = reports.lock().unwrap();
        let last = reports.last().unwrap();
        assert_eq!(
            (last.stage, last.cause, last.http_status),
            (Stage::InitialAuthentication, Some(cause), status)
        );
        assert!(last.credential_read_succeeded && last.auth_started);
    }
}
#[tokio::test]
async fn empty_password_timeout_identity_and_report_write_failure_stop_safely() {
    for scenario in 0..4 {
        let mut external = External {
            empty: scenario == 0,
            hang: scenario == 1,
            wrong_account: scenario == 2,
            wrong_team: scenario == 3,
            ..Default::default()
        };
        let (reports, mut observer) = capture();
        let expected = if scenario == 0 {
            Failure::MissingCredentials
        } else if scenario == 1 {
            Failure::Interrupted
        } else {
            Failure::AccountMismatch
        };
        assert_eq!(
            recover(
                &mut external,
                "a@example.invalid",
                "TEAM",
                StoragePolicy::Allowed,
                &mut observer,
                Duration::from_millis(2)
            )
            .await,
            Err(expected)
        );
        let reports = reports.lock().unwrap();
        let last = reports.last().unwrap();
        assert_eq!(
            last.cause,
            Some(if scenario == 0 {
                Cause::CredentialEmpty
            } else if scenario == 1 {
                Cause::TimedOut
            } else {
                Cause::AccountMismatch
            })
        );
        if scenario == 0 {
            assert!(last.credential_read_succeeded && !last.auth_started);
        }
    }
    let mut external = External::default();
    let mut observer: Option<Observer> = Some(Box::new(|_| Err("private-storage-error".into())));
    assert_eq!(
        recover(
            &mut external,
            "a@example.invalid",
            "TEAM",
            StoragePolicy::Allowed,
            &mut observer,
            Duration::from_secs(1)
        )
        .await,
        Err(Failure::Interrupted)
    );
    assert!(external.calls.is_empty());
    // A failed durable boundary write must also stop a later authentication call.
    let mut external = External::default();
    let mut observer: Option<Observer> = Some(Box::new(|report| {
        if report.stage == Stage::InitialAuthentication {
            Err("private-storage-error".into())
        } else {
            Ok(())
        }
    }));
    assert_eq!(
        recover(
            &mut external,
            "a@example.invalid",
            "TEAM",
            StoragePolicy::Allowed,
            &mut observer,
            Duration::from_secs(1)
        )
        .await,
        Err(Failure::Interrupted)
    );
    assert_eq!(
        external.calls,
        [
            Stage::CredentialRead,
            Stage::AnisetteInit,
            Stage::AccountBuild
        ]
    );
}
#[tokio::test]
async fn successful_session_reports_ready_once_with_exact_identity() {
    let mut external = External::default();
    let (reports, mut observer) = capture();
    assert_eq!(
        recover(
            &mut external,
            "a@example.invalid",
            "TEAM",
            StoragePolicy::Allowed,
            &mut observer,
            Duration::from_secs(1)
        )
        .await,
        Ok(("a@example.invalid".into(), "TEAM".into()))
    );
    let reports = reports.lock().unwrap();
    let last = reports.last().unwrap();
    assert_eq!((last.stage, last.cause), (Stage::Ready, None));
    assert!(last.credential_read_succeeded && last.auth_started);
    assert_eq!(external.calls.len(), 6);
}
