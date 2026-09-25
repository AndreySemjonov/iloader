//! Policy boundary before verification sends, number lookup, callbacks or retries.
use super::LoginState;
use rootcause::prelude::*;
use std::future::Future;

#[derive(Debug, thiserror::Error)]
#[error("Saved-account authentication requires interactive verification")]
pub struct NoninteractiveLoginError;

pub(super) async fn finish_login<F, Fut>(
    interactive: bool,
    state: LoginState,
    continuation: F,
) -> Result<(), Report>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<(), Report>>,
{
    if !interactive {
        return if matches!(state, LoginState::LoggedIn) {
            Ok(())
        } else {
            Err(report!(NoninteractiveLoginError).into())
        };
    }
    continuation().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[tokio::test]
    async fn strict_challenge_states_never_enter_verification_or_retry_flow() {
        for state in [
            LoginState::NeedsDevice2FA,
            LoginState::NeedsDevice2FAVerification,
            LoginState::NeedsSMS2FA(1),
            LoginState::NeedsSMS2FAVerification(1),
            LoginState::NeedsUnknown2FA,
            LoginState::NeedsLogin,
            LoginState::NeedsExtraStep("private-server-detail".into()),
        ] {
            let verification_flow = Cell::new(0);
            let result = finish_login(false, state, || async {
                verification_flow.set(verification_flow.get() + 1);
                Ok(())
            })
            .await;
            assert_eq!(
                verification_flow.get(),
                0,
                "No verification send/lookup/callback/retry flow may run"
            );
            let error = result.unwrap_err();
            assert!(error.iter_reports().any(|r| {
                r.downcast_current_context::<NoninteractiveLoginError>()
                    .is_some()
            }));
            assert!(!format!("{error:?}").contains("private-server-detail"));
        }
    }

    #[tokio::test]
    async fn strict_logged_in_completes_and_interactive_behavior_is_preserved() {
        finish_login(false, LoginState::LoggedIn, || async {
            panic!("No interactive flow needed")
        })
        .await
        .unwrap();
        let flow = Cell::new(0);
        finish_login(true, LoginState::NeedsDevice2FA, || async {
            flow.set(1);
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(flow.get(), 1);
        let error = finish_login(true, LoginState::NeedsSMS2FA(1), || async {
            Err(report!("sentinel"))
        })
        .await
        .unwrap_err();
        assert!(format!("{error:?}").contains("sentinel"));
    }
}
