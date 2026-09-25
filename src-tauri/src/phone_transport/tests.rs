use super::*;
use std::{collections::VecDeque, sync::Mutex};
#[derive(Debug)]
struct FakePhone {
    identities: Mutex<VecDeque<Result<String, IdeviceError>>>,
    events: Arc<Mutex<Vec<String>>>,
}

impl PhoneIdentity for FakePhone {
    fn authenticated_identity(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<String, IdeviceError>> + Send>> {
        let result = self
            .identities
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected authentication retry");
        let events = self.events.clone();
        Box::pin(async move {
            events.lock().unwrap().push("authenticate".into());
            result
        })
    }
}

impl IdeviceProvider for FakePhone {
    fn connect(
        &self,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<Idevice, IdeviceError>> + Send>> {
        let events = self.events.clone();
        Box::pin(async move {
            events.lock().unwrap().push(format!("connect:{port}"));
            let (stream, _) = tokio::io::duplex(64);
            Ok(Idevice::new(Box::new(stream), "synthetic"))
        })
    }
    fn label(&self) -> &str {
        "synthetic"
    }
    fn get_pairing_file(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<PairingFile, IdeviceError>> + Send>> {
        Box::pin(async { Err(IdeviceError::NotFound) })
    }
}

#[tokio::test]
async fn every_installer_connection_requires_fresh_authenticated_identity() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let provider = SavedPhone::new(
        FakePhone {
            identities: Mutex::new(VecDeque::from([
                Ok("phone".into()),
                Ok("phone".into()),
                Ok("different".into()),
            ])),
            events: events.clone(),
        },
        "phone".into(),
    )
    .unwrap();
    provider.connect(62078).await.unwrap();
    provider.connect(1234).await.unwrap();
    let error = provider.connect(1235).await.unwrap_err();
    assert!(matches!(error, IdeviceError::Socket(_)));
    assert_eq!(
        *events.lock().unwrap(),
        [
            "authenticate",
            "connect:62078",
            "authenticate",
            "connect:1234",
            "authenticate"
        ]
    );
    if let IdeviceError::Socket(error) = error {
        assert!(
            error
                .get_ref()
                .is_some_and(|error| error.is::<WrongPhone>())
        );
    }
}

#[tokio::test]
async fn missing_identity_or_authentication_failure_never_opens_install_connection() {
    for observed in [
        Ok(String::new()),
        Err(IdeviceError::InvalidHostID),
        Err(IdeviceError::Timeout),
    ] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let provider = SavedPhone::new(
            FakePhone {
                identities: Mutex::new(VecDeque::from([observed])),
                events: events.clone(),
            },
            "phone".into(),
        )
        .unwrap();
        assert!(provider.connect(1234).await.is_err());
        assert_eq!(*events.lock().unwrap(), ["authenticate"]);
    }
}
