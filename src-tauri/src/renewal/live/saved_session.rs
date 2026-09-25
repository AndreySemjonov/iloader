//! Secure saved-account operations with fixed diagnostics at the actual boundaries.
use super::super::session_diagnostic::{Cause, Diagnostic, Stage};
use super::*;

#[derive(Clone, Debug)]
struct SessionError {
    failure: Failure,
    cause: Cause,
    http_status: Option<u16>,
}
impl SessionError {
    fn new(failure: Failure, cause: Cause) -> Self {
        Self {
            failure,
            cause,
            http_status: None,
        }
    }
    fn keyring(error: keyring::Error) -> Self {
        let cause = match error {
            keyring::Error::NoEntry => Cause::CredentialNotFound,
            keyring::Error::NoStorageAccess(_) => Cause::CredentialAccessDenied,
            keyring::Error::BadEncoding(_) => Cause::CredentialDecodeFailed,
            _ => Cause::CredentialReadFailed,
        };
        Self::new(Failure::MissingCredentials, cause)
    }
    fn external(error: &Report) -> Self {
        for node in error.iter_reports() {
            if node.downcast_current_context::<isideload::auth::apple_account::NoninteractiveLoginError>().is_some() {
                return Self::new(Failure::MfaRequired, Cause::MfaRequired);
            }
            if let Some(error) = node.downcast_current_context::<reqwest::Error>() {
                return Self::http(error);
            }
            let mut source = node.current_context_error_source();
            while let Some(error) = source {
                if let Some(error) = error.downcast_ref::<reqwest::Error>() {
                    return Self::http(error);
                }
                source = error.source();
            }
        }
        Self::new(Failure::AccountSessionFailed, Cause::Unknown)
    }
    fn http(error: &reqwest::Error) -> Self {
        let status = error.status().map(|s| s.as_u16());
        let (failure, cause) = if status == Some(429) {
            (Failure::RateLimited, Cause::RateLimited)
        } else if status.is_some() {
            (Failure::AccountSessionFailed, Cause::HttpRejected)
        } else {
            (Failure::AccountSessionFailed, Cause::NetworkFailure)
        };
        Self {
            failure,
            cause,
            http_status: status,
        }
    }
    fn mismatch() -> Self {
        Self::new(Failure::AccountMismatch, Cause::AccountMismatch)
    }
}

/// Only fixed enums, booleans and HTTP status cross this observer. Raw errors and
/// provider values are discarded before persistence or UI serialization.
struct Trace<'a> {
    report: Diagnostic,
    observer: &'a mut Option<Observer>,
}
impl Trace<'_> {
    fn publish(&mut self) -> Result<(), SessionError> {
        if let Some(observer) = self.observer {
            observer(self.report.clone())
                .map_err(|_| SessionError::new(Failure::Interrupted, Cause::Unknown))?;
        }
        Ok(())
    }
    fn enter(&mut self, stage: Stage) -> Result<(), SessionError> {
        self.report.stage = stage;
        if stage == Stage::InitialAuthentication {
            self.report.auth_started = true;
        }
        self.publish()
    }
    fn failure(&mut self, error: SessionError) -> Failure {
        self.report.cause = Some(error.cause);
        self.report.http_status = error.http_status;
        match self.publish() {
            Ok(()) => error.failure,
            Err(_) => Failure::Interrupted,
        }
    }
}

trait Provider {
    type Anisette;
    type Account;
    type Developer;
    type Team;
    type Output;
    fn password(&mut self, account: &str) -> Result<String, SessionError>;
    fn anisette(&mut self) -> Result<Self::Anisette, SessionError>;
    async fn account(
        &mut self,
        email: &str,
        anisette: Self::Anisette,
    ) -> Result<Self::Account, SessionError>;
    async fn authenticate(
        &mut self,
        account: &mut Self::Account,
        password: &str,
    ) -> Result<(), SessionError>;
    fn email(account: &Self::Account) -> &str;
    async fn developer(
        &mut self,
        account: &mut Self::Account,
    ) -> Result<Self::Developer, SessionError>;
    async fn team(
        &mut self,
        developer: &mut Self::Developer,
        team: &str,
    ) -> Result<Self::Team, SessionError>;
    fn team_id(team: &Self::Team) -> &str;
    fn finish(developer: Self::Developer, email: String, team: Self::Team) -> Self::Output;
}

async fn recover<P: Provider>(
    provider: &mut P,
    account: &str,
    team: &str,
    policy: StoragePolicy,
    observer: &mut Option<Observer>,
    deadline: Duration,
) -> Result<P::Output, Failure> {
    let mut trace = Trace {
        report: Diagnostic::default(),
        observer,
    };
    let result = tokio::time::timeout(
        deadline,
        Box::pin(async {
            trace.enter(Stage::StoragePolicy)?;
            match policy {
                StoragePolicy::Allowed => {}
                StoragePolicy::Disabled => {
                    return Err(SessionError::new(
                        Failure::MissingCredentials,
                        Cause::StorageDisabled,
                    ));
                }
                StoragePolicy::Unavailable => {
                    return Err(SessionError::new(
                        Failure::MissingCredentials,
                        Cause::PreferencesUnavailable,
                    ));
                }
            }
            if account.is_empty() || team.is_empty() {
                return Err(SessionError::mismatch());
            }
            trace.enter(Stage::CredentialRead)?;
            let password = provider.password(account)?;
            trace.report.credential_read_succeeded = true;
            if password.is_empty() {
                return Err(SessionError::new(
                    Failure::MissingCredentials,
                    Cause::CredentialEmpty,
                ));
            }
            trace.enter(Stage::AnisetteInit)?;
            let anisette = provider.anisette()?;
            trace.enter(Stage::AccountBuild)?;
            let mut authenticated = provider.account(account, anisette).await?;
            trace.enter(Stage::InitialAuthentication)?;
            let login = provider.authenticate(&mut authenticated, &password).await;
            drop(password);
            login?;
            if !P::email(&authenticated).eq_ignore_ascii_case(account) {
                return Err(SessionError::mismatch());
            }
            trace.enter(Stage::DeveloperSession)?;
            let mut developer = provider.developer(&mut authenticated).await?;
            trace.enter(Stage::TeamLookup)?;
            let selected = provider.team(&mut developer, team).await?;
            require_session_identity(
                account,
                team,
                P::email(&authenticated),
                P::team_id(&selected),
            )
            .map_err(|_| SessionError::mismatch())?;
            trace.enter(Stage::Ready)?;
            Ok(P::finish(
                developer,
                P::email(&authenticated).into(),
                selected,
            ))
        }),
    )
    .await;
    match result {
        Ok(Ok(ready)) => Ok(ready),
        Ok(Err(error)) => Err(trace.failure(error)),
        Err(_) => Err(trace.failure(SessionError::new(Failure::Interrupted, Cause::TimedOut))),
    }
}

pub(super) async fn recover_native(
    account: &str,
    team: &str,
    url: &str,
    policy: StoragePolicy,
    observer: &mut Option<Observer>,
) -> Result<Session, Failure> {
    recover(
        &mut NativeProvider { anisette_url: url },
        account,
        team,
        policy,
        observer,
        Duration::from_secs(120),
    )
    .await
}
struct NativeProvider<'a> {
    anisette_url: &'a str,
}
impl Provider for NativeProvider<'_> {
    type Anisette = RemoteV3AnisetteProvider;
    type Account = AppleAccount;
    type Developer = DeveloperSession;
    type Team = DeveloperTeam;
    type Output = Session;
    fn password(&mut self, account: &str) -> Result<String, SessionError> {
        keyring::Entry::new(crate::secure_storage::KEYRING_SERVICE, account)
            .and_then(|entry| entry.get_password())
            .map_err(SessionError::keyring)
    }
    fn anisette(&mut self) -> Result<Self::Anisette, SessionError> {
        Ok(RemoteV3AnisetteProvider::default()
            .map_err(|e| SessionError::external(&e))?
            .set_serial_number("0".into())
            .set_storage(Box::new(KeyringStorage::new(crate::secure_storage::KEYRING_SERVICE.into())))
            .set_url(self.anisette_url))
    }
    async fn account(
        &mut self,
        email: &str,
        anisette: Self::Anisette,
    ) -> Result<AppleAccount, SessionError> {
        AppleAccount::builder(email)
            .anisette_provider(anisette)
            .build()
            .await
            .map_err(|e| SessionError::external(&e))
    }
    async fn authenticate(
        &mut self,
        account: &mut AppleAccount,
        password: &str,
    ) -> Result<(), SessionError> {
        account
            .login_noninteractive(password)
            .await
            .map_err(|e| SessionError::external(&e))
    }
    fn email(account: &AppleAccount) -> &str {
        &account.email
    }
    async fn developer(
        &mut self,
        account: &mut AppleAccount,
    ) -> Result<DeveloperSession, SessionError> {
        DeveloperSession::from_account(account)
            .await
            .map_err(|e| SessionError::external(&e))
    }
    async fn team(
        &mut self,
        developer: &mut DeveloperSession,
        team: &str,
    ) -> Result<DeveloperTeam, SessionError> {
        developer
            .list_teams()
            .await
            .map_err(|e| SessionError::external(&e))?
            .into_iter()
            .find(|t| t.team_id == team)
            .ok_or_else(SessionError::mismatch)
    }
    fn team_id(team: &DeveloperTeam) -> &str {
        &team.team_id
    }
    fn finish(developer: DeveloperSession, email: String, team: DeveloperTeam) -> Session {
        let signer = SideloaderBuilder::new(developer, email)
            .machine_name("iloader".into())
            .storage(Box::new(KeyringStorage::new(crate::secure_storage::KEYRING_SERVICE.into())))
            .max_certs_behavior(MaxCertsBehavior::Error)
            .certificate_policy(CertificatePolicy::ReuseExistingOnly)
            .build();
        Session { signer, team }
    }
}

#[cfg(test)]
mod tests;
