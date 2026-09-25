//! Entirely synthetic transport. Every HTTP request is intercepted without
//! calling Next; unexpected portal methods panic before any socket can open.
use crate::{
    anisette::{AnisetteClientInfo, AnisetteData, AnisetteDataGenerator, AnisetteProvider},
    auth::{apple_account::AppToken, grandslam::GrandSlam},
    dev::{developer_session::DeveloperSession, teams::DeveloperTeam},
    sideload::{
        SideloaderBuilder,
        builder::{CertificatePolicy, MaxCertsBehavior},
        cert_identity::{CertificateIdentity, CertificateReuseError},
    },
    util::storage::SideloadingStorage,
};
use plist::{Dictionary, Value};
use rootcause::prelude::*;
use rsa::{
    RsaPrivateKey,
    pkcs8::{EncodePrivateKey, LineEnding},
};
use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
};

struct SyntheticAnisette;
#[async_trait::async_trait]
impl AnisetteProvider for SyntheticAnisette {
    async fn get_anisette_data(&self) -> Result<AnisetteData, Report> {
        Ok(AnisetteData::for_certificate_policy_tests())
    }
    async fn get_client_info(&self) -> Result<AnisetteClientInfo, Report> {
        panic!("client lookup must not run")
    }
    async fn provision(&mut self, _: Arc<GrandSlam>) -> Result<(), Report> {
        panic!("provisioning must not run")
    }
    fn needs_provisioning(&self) -> Result<bool, Report> {
        Ok(false)
    }
}

#[derive(Clone)]
struct Storage {
    key: Option<Vec<u8>>,
    writes: Arc<AtomicUsize>,
    permit_writes: bool,
}
impl SideloadingStorage for Storage {
    fn store(&self, _: &str, _: &str) -> Result<(), Report> {
        assert!(self.permit_writes, "reuse-only must not write storage");
        self.writes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn retrieve(&self, _: &str) -> Result<Option<String>, Report> {
        panic!("use binary key retrieval")
    }
    fn retrieve_data(&self, key: &str) -> Result<Option<Vec<u8>>, Report> {
        assert!(key.ends_with("/key"));
        Ok(self.key.clone())
    }
}

#[derive(Clone)]
enum Response {
    Certificates(Vec<Value>),
    PortalFailure(Vec<Value>),
    HttpError,
    Malformed,
}
#[derive(Clone)]
struct Portal {
    response: Response,
    calls: Arc<Mutex<Vec<String>>>,
    permit_csr: bool,
}
#[async_trait::async_trait]
impl reqwest_middleware::Middleware for Portal {
    async fn handle(
        &self,
        request: reqwest::Request,
        _: &mut http::Extensions,
        _: reqwest_middleware::Next<'_>,
    ) -> reqwest_middleware::Result<reqwest::Response> {
        let operation = request.url().path().rsplit('/').next().unwrap().to_owned();
        self.calls.lock().unwrap().push(operation.clone());
        let mut response = Dictionary::new();
        response.insert("resultCode".into(), Value::Integer(0.into()));
        let status = if operation == "listAllDevelopmentCerts.action" {
            match &self.response {
                Response::PortalFailure(certs) => {
                    response.insert("certificates".into(), Value::Array(certs.clone()));
                    response.insert("resultCode".into(), Value::Integer(1234.into()));
                    response.insert(
                        "resultString".into(),
                        Value::String("Synthetic failed lookup".into()),
                    );
                    200
                }
                Response::Certificates(certs) => {
                    response.insert("certificates".into(), Value::Array(certs.clone()));
                    200
                }
                Response::HttpError => 503,
                Response::Malformed => {
                    return Ok(http::Response::builder()
                        .status(200)
                        .body("not a plist")
                        .unwrap()
                        .into());
                }
            }
        } else if operation == "submitDevelopmentCSR.action" && self.permit_csr {
            // Interactive default reaches this stub; no certificate is issued.
            response.insert("resultCode".into(), Value::Integer(1234.into()));
            response.insert(
                "resultString".into(),
                Value::String("Synthetic rejection".into()),
            );
            200
        } else {
            panic!("Unexpected portal operation: {operation}");
        };
        let mut bytes = Vec::new();
        Value::Dictionary(response)
            .to_writer_xml(&mut bytes)
            .unwrap();
        Ok(http::Response::builder()
            .status(status)
            .body(bytes)
            .unwrap()
            .into())
    }
}

fn session(response: Response, permit_csr: bool) -> (DeveloperSession, Arc<Mutex<Vec<String>>>) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let portal = Portal {
        response,
        calls: calls.clone(),
        permit_csr,
    };
    let client = reqwest_middleware::ClientBuilder::new(reqwest::Client::new())
        .with(portal)
        .build();
    let client = Arc::new(GrandSlam::for_certificate_policy_tests(client));
    let anisette =
        AnisetteDataGenerator::new(Arc::new(tokio::sync::RwLock::new(SyntheticAnisette)));
    (
        DeveloperSession::new(
            AppToken {
                token: "synthetic".into(),
                duration: 3600,
                expiry: u64::MAX,
            },
            "synthetic".into(),
            client,
            anisette,
        ),
        calls,
    )
}

fn key() -> &'static Vec<u8> {
    static KEY: OnceLock<Vec<u8>> = OnceLock::new();
    KEY.get_or_init(|| {
        RsaPrivateKey::new(&mut rand::thread_rng(), 2048)
            .unwrap()
            .to_pkcs8_der()
            .unwrap()
            .as_bytes()
            .to_vec()
    })
}

fn certificate(status: Option<&str>, expired: bool) -> Value {
    use rsa::pkcs8::DecodePrivateKey;
    let private = RsaPrivateKey::from_pkcs8_der(key()).unwrap();
    let signing = rcgen::KeyPair::from_pkcs8_pem_and_sign_algo(
        &private.to_pkcs8_pem(LineEnding::LF).unwrap(),
        &rcgen::PKCS_RSA_SHA256,
    )
    .unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(if expired { 2021 } else { 2099 }, 1, 1);
    let der = params.self_signed(&signing).unwrap().der().to_vec();
    let mut result = Dictionary::new();
    result.insert("machineName".into(), Value::String("iloader".into()));
    result.insert(
        "machineId".into(),
        Value::String("synthetic-machine".into()),
    );
    result.insert("certContent".into(), Value::Data(der));
    if let Some(status) = status {
        result.insert("status".into(), Value::String(status.into()));
    }
    Value::Dictionary(result)
}
fn team() -> DeveloperTeam {
    DeveloperTeam {
        name: None,
        team_id: "synthetic-team".into(),
        r#type: None,
        status: None,
    }
}
fn storage(key: Option<Vec<u8>>, permit_writes: bool) -> Storage {
    Storage {
        key,
        permit_writes,
        writes: Arc::new(AtomicUsize::new(0)),
    }
}
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn actual_signing_entry_stops_before_csr_or_key_mutation_for_every_reuse_failure() {
    runtime().block_on(async {
        for (key, response, expected, expected_calls) in [
            (None, Response::Certificates(vec![]), "missing", 0),
            (
                Some(vec![0, 1, 2]),
                Response::Certificates(vec![]),
                "could not be read",
                0,
            ),
            (
                Some(key().clone()),
                Response::Certificates(vec![]),
                "No matching",
                1,
            ),
            (
                Some(key().clone()),
                Response::Certificates(vec![certificate(Some("Issued"), true)]),
                "expired",
                1,
            ),
            (
                Some(key().clone()),
                Response::Certificates(vec![certificate(Some("Revoked"), false)]),
                "revoked",
                1,
            ),
            (
                Some(key().clone()),
                Response::Certificates(vec![certificate(None, false)]),
                "unconfirmed",
                1,
            ),
            (Some(key().clone()), Response::HttpError, "lookup failed", 1),
            (
                Some(key().clone()),
                Response::PortalFailure(vec![certificate(Some("Issued"), false)]),
                "lookup failed",
                1,
            ),
            (Some(key().clone()), Response::Malformed, "lookup failed", 1),
        ] {
            let storage = storage(key, false);
            let writes = storage.writes.clone();
            let (session, calls) = session(response, false);
            let mut signer = SideloaderBuilder::new(session, "test@example.invalid".into())
                .machine_name("iloader".into())
                .storage(Box::new(storage))
                .max_certs_behavior(MaxCertsBehavior::Revoke)
                .certificate_policy(CertificatePolicy::ReuseExistingOnly)
                .build();
            let error = Box::pin(signer.sign_app(
                PathBuf::from("synthetic-missing.ipa"),
                Some(team()),
                false,
                None::<fn(f32) -> std::future::Ready<()>>,
            ))
            .await
            .unwrap_err();
            let policy_error = error
                .iter_reports()
                .find_map(|node| node.downcast_current_context::<CertificateReuseError>())
                .expect("actual signing entry must return typed action state");
            assert!(policy_error.to_string().contains(expected));
            assert_eq!(calls.lock().unwrap().len(), expected_calls);
            assert!(
                calls
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|call| call == "listAllDevelopmentCerts.action")
            );
            assert_eq!(writes.load(Ordering::SeqCst), 0);
        }
    });
}

#[test]
fn actual_retrieval_reuses_active_matching_certificate_with_no_mutation() {
    runtime().block_on(async {
        let (mut session, calls) = session(
            Response::Certificates(vec![certificate(Some("Issued"), false)]),
            false,
        );
        let store = storage(Some(key().clone()), false);
        let identity = CertificateIdentity::retrieve_with_policy(
            "iloader",
            "test@example.invalid",
            &mut session,
            &team(),
            &store,
            &MaxCertsBehavior::Revoke,
            CertificatePolicy::ReuseExistingOnly,
        )
        .await
        .unwrap();
        assert_eq!(identity.machine_id, "synthetic-machine");
        assert_eq!(
            calls.lock().unwrap().as_slice(),
            ["listAllDevelopmentCerts.action"]
        );
        assert_eq!(store.writes.load(Ordering::SeqCst), 0);
    });
}

#[test]
fn actual_signing_entry_keeps_interactive_creation_default() {
    runtime().block_on(async {
        let (session, calls) = session(Response::Certificates(vec![]), true);
        let store = storage(None, true);
        let writes = store.writes.clone();
        let mut signer = SideloaderBuilder::new(session, "test@example.invalid".into())
            .machine_name("iloader".into())
            .storage(Box::new(store))
            .build();
        assert!(
            Box::pin(signer.sign_app(
                PathBuf::from("synthetic-missing.ipa"),
                Some(team()),
                false,
                None::<fn(f32) -> std::future::Ready<()>>
            ))
            .await
            .is_err()
        );
        assert_eq!(
            calls.lock().unwrap().as_slice(),
            [
                "listAllDevelopmentCerts.action",
                "submitDevelopmentCSR.action"
            ]
        );
        assert_eq!(writes.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn reuse_only_builder_requires_explicit_storage_before_portal_access() {
    runtime().block_on(async {
        let (session, calls) = session(Response::Certificates(vec![]), false);
        let mut signer = SideloaderBuilder::new(session, "test@example.invalid".into())
            .certificate_policy(CertificatePolicy::ReuseExistingOnly)
            .build();
        let error = Box::pin(signer.sign_app(
            PathBuf::from("synthetic-missing.ipa"),
            Some(team()),
            false,
            None::<fn(f32) -> std::future::Ready<()>>,
        ))
        .await
        .unwrap_err();
        assert!(error.iter_reports().any(|node| matches!(
            node.downcast_current_context::<CertificateReuseError>(),
            Some(CertificateReuseError::KeyUnavailable)
        )));
        assert!(calls.lock().unwrap().is_empty());
    });
}

#[test]
fn actual_signing_reuses_certificate_and_reaches_archive_without_mutations() {
    runtime().block_on(async {
        let (session, calls) = session(
            Response::Certificates(vec![certificate(Some("Issued"), false)]),
            false,
        );
        let store = storage(Some(key().clone()), false);
        let writes = store.writes.clone();
        let mut signer = SideloaderBuilder::new(session, "test@example.invalid".into())
            .machine_name("iloader".into())
            .storage(Box::new(store))
            .certificate_policy(CertificatePolicy::ReuseExistingOnly)
            .build();
        let reached = AtomicUsize::new(0);
        let error = Box::pin(signer.sign_app(
            PathBuf::from("synthetic-missing.ipa"),
            Some(team()),
            false,
            Some(|progress| {
                assert_eq!(progress, 0.1);
                reached.fetch_add(1, Ordering::SeqCst);
                std::future::ready(())
            }),
        ))
        .await
        .unwrap_err();
        assert!(error.iter_reports().any(|node| matches!(
            node.downcast_current_context::<crate::SideloadError>(),
            Some(crate::SideloadError::InvalidBundle(_))
        )));
        assert_eq!(reached.load(Ordering::SeqCst), 1);
        assert_eq!(
            calls.lock().unwrap().as_slice(),
            ["listAllDevelopmentCerts.action"]
        );
        assert_eq!(writes.load(Ordering::SeqCst), 0);
    });
}
