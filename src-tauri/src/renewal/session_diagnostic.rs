//! Fixed, secret-free diagnostics for an explicitly requested saved-account attempt.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Stage {
    StoragePolicy,
    CredentialRead,
    AnisetteInit,
    AccountBuild,
    InitialAuthentication,
    DeveloperSession,
    TeamLookup,
    Ready,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Cause {
    StorageDisabled,
    PreferencesUnavailable,
    CredentialNotFound,
    CredentialReadFailed,
    CredentialAccessDenied,
    CredentialDecodeFailed,
    CredentialEmpty,
    NetworkFailure,
    HttpRejected,
    MfaRequired,
    RateLimited,
    AccountMismatch,
    TimedOut,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoragePolicy {
    Allowed,
    Disabled,
    Unavailable,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Diagnostic {
    pub stage: Stage,
    pub cause: Option<Cause>,
    pub credential_read_succeeded: bool,
    pub auth_started: bool,
    pub http_status: Option<u16>,
}
impl Default for Diagnostic {
    fn default() -> Self {
        Self {
            stage: Stage::StoragePolicy,
            cause: None,
            credential_read_succeeded: false,
            auth_started: false,
            http_status: None,
        }
    }
}
pub type Observer = Box<dyn FnMut(Diagnostic) -> Result<(), String>>;
