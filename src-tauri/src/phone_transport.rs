//! Saved host-pairing providers with fresh authenticated identity checks.
use crate::renewal::Failure;
use idevice::{
    Idevice, IdeviceError, IdeviceService,
    lockdown::LockdownClient,
    pairing_file::PairingFile,
    provider::{IdeviceProvider, TcpProvider},
};
use std::{future::Future, pin::Pin, sync::Arc, time::Duration};
#[derive(Debug, thiserror::Error)]
#[error("Authenticated phone identity does not match enrollment")]
pub(crate) struct WrongPhone;

/// Authentication is a separate read-only session, never Pair or device setup.
pub(crate) trait PhoneIdentity: IdeviceProvider + 'static {
    fn authenticated_identity(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<String, IdeviceError>> + Send>>;
}

impl PhoneIdentity for TcpProvider {
    fn authenticated_identity(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<String, IdeviceError>> + Send>> {
        let provider = TcpProvider {
            addr: self.addr,
            scope_id: self.scope_id,
            pairing_file: self.pairing_file.clone(),
            label: self.label.clone(),
        };
        Box::pin(async move {
            let mut client = LockdownClient::connect(&provider).await?;
            client.start_session(&provider.pairing_file).await?;
            let value = client.get_value(Some("UniqueDeviceID"), None).await?;
            value
                .as_string()
                .filter(|id| !id.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| IdeviceError::Socket(std::io::Error::other(WrongPhone)))
        })
    }
}

/// IdeviceService's UDID lookup is best effort. Require an authenticated match
/// before every low-level installer connection, including AFC and install proxy.
/// The inner provider has only the selected TCP address and existing record.
#[derive(Debug)]
pub(crate) struct SavedPhone<P> {
    provider: Arc<P>,
    expected: String,
}

impl<P: PhoneIdentity> SavedPhone<P> {
    pub(crate) fn new(provider: P, expected: String) -> Result<Self, Failure> {
        if expected.is_empty() {
            return Err(Failure::WrongDevice);
        }
        Ok(Self {
            provider: Arc::new(provider),
            expected,
        })
    }
}

impl<P: PhoneIdentity> IdeviceProvider for SavedPhone<P> {
    fn connect(
        &self,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<Idevice, IdeviceError>> + Send>> {
        let provider = self.provider.clone();
        let expected = self.expected.clone();
        Box::pin(async move {
            let observed =
                tokio::time::timeout(Duration::from_secs(10), provider.authenticated_identity())
                    .await
                    .map_err(|_| IdeviceError::Timeout)??;
            if observed != expected {
                return Err(IdeviceError::Socket(std::io::Error::other(WrongPhone)));
            }
            provider.connect(port).await
        })
    }

    fn label(&self) -> &str {
        self.provider.label()
    }

    fn get_pairing_file(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<PairingFile, IdeviceError>> + Send>> {
        self.provider.get_pairing_file()
    }
}

#[cfg(test)]
mod tests;
