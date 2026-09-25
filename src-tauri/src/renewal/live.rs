//! Saved phone-only renewal through reusable account sessions.
use super::{
    Backend, Clock, Decision, Enrollment, Failure, Trigger, archive,
    journal::FileJournal,
    session_diagnostic::{Observer, StoragePolicy},
};
use crate::{
    manual_wifi::{self, PhoneConnection},
    renewal_report::RenewalReport,
    secure_storage::background_keyring_enabled,
    sideload::{SideloaderGuard, SideloaderMutex},
};
use isideload::{
    anisette::remote_v3::RemoteV3AnisetteProvider,
    auth::apple_account::AppleAccount,
    dev::{
        developer_session::DeveloperSession,
        teams::{DeveloperTeam, TeamsApi},
    },
    sideload::{
        SideloaderBuilder,
        builder::{CertificatePolicy, MaxCertsBehavior},
        bundle::Bundle,
        cert_identity::CertificateReuseError,
        install::install_app,
        sideloader::Sideloader,
    },
    util::keyring_storage::KeyringStorage,
};
use rootcause::Report;
use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tauri::{AppHandle, Manager};
mod saved_session;
use crate::phone_transport::WrongPhone;

struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> i64 {
        chrono::Utc::now().timestamp()
    }
}

struct ProductServices {
    app: AppHandle,
    backend: LiveBackend,
}
impl super::product::Services for ProductServices {
    type Engine = LiveBackend;
    fn engine(&mut self) -> &mut Self::Engine {
        &mut self.backend
    }
    async fn selected_team(&mut self, account: &str) -> Result<String, Failure> {
        let state = self.app.state::<SideloaderMutex>();
        let mut signer = SideloaderGuard::take(&state).map_err(|_| Failure::MissingCredentials)?;
        if !signer.get_mut().get_email().eq_ignore_ascii_case(account) {
            return Err(Failure::AccountMismatch);
        }
        let team = tokio::time::timeout(Duration::from_secs(60), signer.get_mut().get_team())
            .await
            .map_err(|_| Failure::Interrupted)?
            .map_err(|error| classify(&error, Failure::AccountSessionFailed))?;
        Ok(team.team_id.clone())
    }
    fn authorize_host_first_use(&mut self) -> Result<(), String> {
        self.app
            .state::<super::host::Host>()
            .authorize_first_use(&self.backend.anisette_url)?;
        super::desktop::refresh_tray(&self.app);
        Ok(())
    }
}
pub(crate) async fn manage_product(
    app: AppHandle,
    anisette_url: &str,
    action: super::product::Action,
) -> Result<super::product::ResultView, String> {
    super::management::require_execution()?;
    let directory = app
        .path()
        .app_data_dir()
        .map_err(|_| "App directory unavailable")?;
    let mut backend = LiveBackend::new(directory.clone(), anisette_url)?;
    backend.storage_policy = crate::secure_storage::saved_credentials_policy(&app);
    super::product::execute(
        &directory,
        &mut ProductServices { app, backend },
        &SystemClock,
        action,
    )
    .await
}

/// Closed gate precedes metadata, credentials, discovery and every side effect.
/// Host calls cannot bypass the build gate through saved preferences.
pub async fn run_live_job(
    app: AppHandle,
    id: &str,
    anisette_url: &str,
) -> Result<Decision, String> {
    super::management::require_execution()?;
    let directory = app
        .path()
        .app_data_dir()
        .map_err(|_| "App directory unavailable")?;
    let mut journal = FileJournal::acquire(&directory, id)?;
    let mut backend = LiveBackend::new(directory, anisette_url)?;
    backend.storage_policy = crate::secure_storage::saved_credentials_policy(&app);
    Box::pin(super::run_phone_host(
        &mut backend,
        &mut journal,
        &SystemClock,
        Trigger::Background,
    ))
    .await
}

struct Connection {
    phone_id: String,
    phone: PhoneConnection,
}
struct Session {
    signer: Sideloader,
    team: DeveloperTeam,
}
pub struct LiveBackend {
    directory: PathBuf,
    anisette_url: String,
    job: Option<Enrollment>,
    prepared: Option<Prepared>,
    connection: Option<Connection>,
    session: Option<Session>,
    storage_policy: StoragePolicy,
    session_observer: Option<Observer>,
}

impl LiveBackend {
    fn new(directory: PathBuf, anisette_url: &str) -> Result<Self, String> {
        let url = reqwest::Url::parse(anisette_url).map_err(|_| "Invalid anisette URL")?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(
                "Background anisette requires HTTPS without credentials, query or fragment".into(),
            );
        }
        Ok(Self {
            directory,
            anisette_url: url.to_string(),
            job: None,
            prepared: None,
            connection: None,
            session: None,
            storage_policy: StoragePolicy::Allowed,
            session_observer: None,
        })
    }
}

impl LiveBackend {
    async fn connect_device(&mut self, phone: &str, watch: Option<&str>) -> Result<(), Failure> {
        self.connection = None;
        if watch.is_some() {
            return Err(Failure::WatchNotSupported);
        }
        let mut report = manual_wifi::CheckReport::default();
        let connection = manual_wifi::connect_saved_phone(phone, &mut report)
            .await
            .map_err(|problem| match problem {
                manual_wifi::Problem::WrongDevice => Failure::WrongDevice,
                manual_wifi::Problem::TrustRejected
                | manual_wifi::Problem::SavedPairingUnavailable => Failure::TrustRequired,
                manual_wifi::Problem::DeviceLocked => Failure::DeviceLocked,
                _ => Failure::Offline,
            })?;
        self.connection = Some(Connection {
            phone_id: phone.into(),
            phone: connection,
        });
        Ok(())
    }
}

// An upstream IPA extraction name is derived from the source file name. Give
// each run an exclusively owned, unique name; cleanup covers signing failures.
struct Prepared {
    directory: PathBuf,
    ipa: PathBuf,
    extracted: PathBuf,
}
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
impl Prepared {
    fn create(
        archive: &archive::ArchiveIdentity,
        retained_directory: &Path,
    ) -> Result<Self, Failure> {
        let source = archive.verify(retained_directory)?;
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Failure::ArchiveMissing)?
            .as_nanos();
        let name = format!(
            "iloader-renewal-{}-{nonce}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let directory = std::env::temp_dir().join(&name);
        let extracted = std::env::temp_dir().join(format!("{name}.ipa_extracted"));
        if extracted.exists() {
            return Err(Failure::ArchiveChanged);
        }
        std::fs::create_dir(&directory).map_err(|_| Failure::ArchiveMissing)?;
        let prepared = Self {
            ipa: directory.join(format!("{name}.ipa")),
            directory,
            extracted,
        };
        std::fs::copy(source, &prepared.ipa).map_err(|_| Failure::ArchiveMissing)?;
        if archive::inspect(&prepared.ipa)? != *archive {
            return Err(Failure::ArchiveChanged);
        }
        Ok(prepared)
    }
}
impl Drop for Prepared {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.extracted);
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

pub struct Signed {
    _prepared: Prepared,
    path: PathBuf,
    phone_expiry: Option<i64>,
}

fn require_archive_enrollment(job: &Enrollment) -> Result<(), Failure> {
    if job.archive.has_watch != job.watch_id.is_some() {
        return Err(Failure::WrongDevice);
    }
    Ok(())
}

fn require_session_identity(
    account: &str,
    team: &str,
    observed_account: &str,
    observed_team: &str,
) -> Result<(), Failure> {
    if account.is_empty()
        || team.is_empty()
        || !account.eq_ignore_ascii_case(observed_account)
        || team != observed_team
    {
        return Err(Failure::AccountMismatch);
    }
    Ok(())
}

fn classify(error: &Report, fallback: Failure) -> Failure {
    let mut classified = fallback;
    for node in error.iter_reports() {
        if node
            .downcast_current_context::<CertificateReuseError>()
            .is_some()
        {
            classified = Failure::CertificateActionRequired;
        }
        if node
            .downcast_current_context::<reqwest::Error>()
            .is_some_and(|e| e.status() == Some(reqwest::StatusCode::TOO_MANY_REQUESTS))
        {
            return Failure::RateLimited;
        }
        let mut source = node.current_context_error_source();
        while let Some(error) = source {
            if error.downcast_ref::<WrongPhone>().is_some()
                || error
                    .downcast_ref::<std::io::Error>()
                    .and_then(std::io::Error::get_ref)
                    .is_some_and(|inner| inner.is::<WrongPhone>())
            {
                return Failure::WrongDevice;
            }
            if error
                .downcast_ref::<reqwest::Error>()
                .is_some_and(|e| e.status() == Some(reqwest::StatusCode::TOO_MANY_REQUESTS))
            {
                return Failure::RateLimited;
            }
            source = error.source();
        }
    }
    classified
}

fn validate_profile(
    profile: &plist::Dictionary,
    bundle_id: &str,
    team: &str,
    device: &str,
    now: i64,
) -> Result<(), Failure> {
    let contains = |key: &str, expected: &str| {
        profile
            .get(key)
            .and_then(plist::Value::as_array)
            .is_some_and(|values| {
                values
                    .iter()
                    .any(|value| value.as_string() == Some(expected))
            })
    };
    let entitlements = profile
        .get("Entitlements")
        .and_then(plist::Value::as_dictionary)
        .ok_or(Failure::Signing)?;
    let app_id = entitlements
        .get("application-identifier")
        .and_then(plist::Value::as_string)
        .ok_or(Failure::Signing)?;
    let prefix_matches = profile
        .get("ApplicationIdentifierPrefix")
        .and_then(plist::Value::as_array)
        .is_some_and(|values| {
            values
                .iter()
                .filter_map(plist::Value::as_string)
                .any(|prefix| app_id == format!("{prefix}.{bundle_id}"))
        });
    let expiry: SystemTime = profile
        .get("ExpirationDate")
        .and_then(plist::Value::as_date)
        .ok_or(Failure::Signing)?
        .into();
    let expiry = i64::try_from(
        expiry
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Failure::Signing)?
            .as_secs(),
    )
    .map_err(|_| Failure::Signing)?;
    if !contains("TeamIdentifier", team)
        || !contains("ProvisionedDevices", device)
        || !prefix_matches
        || expiry <= now
        || entitlements
            .get("com.apple.developer.team-identifier")
            .and_then(plist::Value::as_string)
            != Some(team)
    {
        return Err(Failure::Signing);
    }
    Ok(())
}

fn validate_signed_bundle(bundle: &Bundle, job: &Enrollment, now: i64) -> Result<(), Failure> {
    let (main_path, main_id) = job
        .archive
        .bundles
        .iter()
        .find(|(path, _)| path.split('/').count() == 3)
        .ok_or(Failure::ArchiveChanged)?;
    let main_root = main_path
        .strip_suffix("Info.plist")
        .ok_or(Failure::ArchiveChanged)?;
    let observed = bundle.collect_app_id_bundles();
    if observed.len() != job.archive.bundles.len() {
        return Err(Failure::ArchiveChanged);
    }
    for (path, original_id) in &job.archive.bundles {
        let relative = path
            .strip_prefix(main_root)
            .and_then(|path| path.strip_suffix("Info.plist"))
            .ok_or(Failure::ArchiveChanged)?;
        let expected_path = bundle.bundle_dir.join(relative);
        let signed = observed
            .iter()
            .find(|item| item.bundle_dir == expected_path)
            .ok_or(Failure::ArchiveChanged)?;
        let suffix = original_id
            .strip_prefix(main_id)
            .filter(|suffix| suffix.is_empty() || suffix.starts_with('.'))
            .ok_or(Failure::ArchiveChanged)?;
        let expected_id = format!("{main_id}.{}{suffix}", job.team_id);
        if signed.bundle_identifier() != Some(expected_id.as_str()) {
            return Err(Failure::ArchiveChanged);
        }
        let device = if path.split('/').any(|part| part == "Watch") {
            job.watch_id.as_deref().ok_or(Failure::WrongDevice)?
        } else {
            &job.phone_id
        };
        let bytes = std::fs::read(signed.bundle_dir.join("embedded.mobileprovision"))
            .map_err(|_| Failure::Signing)?;
        let profile =
            apple_codesign::ProvisioningProfile::parse(&bytes).map_err(|_| Failure::Signing)?;
        validate_profile(profile.plist(), &expected_id, &job.team_id, device, now)?;
    }
    Ok(())
}

impl Backend for LiveBackend {
    type Signed = Signed;
    fn observe_session(&mut self, mut observer: Observer) {
        let mut previous = self.session_observer.take();
        self.session_observer = Some(Box::new(move |report| {
            observer(report.clone())?;
            if let Some(previous) = &mut previous {
                previous(report)?;
            }
            Ok(())
        }));
    }

    async fn prepare(&mut self, job: &Enrollment) -> Result<(), Failure> {
        self.connection = None;
        self.prepared = None;
        super::management::require_phone_job(job)?;
        require_archive_enrollment(job)?;
        self.prepared = Some(Prepared::create(
            &job.archive,
            &self.directory.join("renewal"),
        )?);
        self.job = Some(job.clone());
        Ok(())
    }

    async fn discover(&mut self, phone: &str, watch: Option<&str>) -> Result<(), Failure> {
        let job = self.job.as_ref().ok_or(Failure::ArchiveMissing)?;
        super::management::require_phone_job(job)?;
        require_archive_enrollment(job)?;
        if job.phone_id != phone || job.watch_id.as_deref() != watch {
            return Err(Failure::WrongDevice);
        }
        self.connect_device(phone, watch).await
    }

    async fn session(&mut self, account: &str) -> Result<(), Failure> {
        let job = self.job.as_ref().ok_or(Failure::AccountMismatch)?;
        if let Some(session) = &mut self.session {
            return require_session_identity(
                &job.account,
                &job.team_id,
                session.signer.get_email(),
                &session.team.team_id,
            );
        }
        if !account.eq_ignore_ascii_case(&job.account) {
            return Err(Failure::AccountMismatch);
        }
        self.session = Some(
            saved_session::recover_native(
                &job.account,
                &job.team_id,
                &self.anisette_url,
                if background_keyring_enabled() {
                    self.storage_policy
                } else {
                    StoragePolicy::Disabled
                },
                &mut self.session_observer,
            )
            .await?,
        );
        Ok(())
    }

    async fn sign(&mut self, job: &Enrollment) -> Result<Signed, Failure> {
        let connection = self.connection.as_ref().ok_or(Failure::Offline)?;
        if connection.phone_id != job.phone_id || job.watch_id.is_some() {
            return Err(Failure::WrongDevice);
        }
        let session = self.session.as_mut().ok_or(Failure::MissingCredentials)?;
        require_session_identity(
            &job.account,
            &job.team_id,
            session.signer.get_email(),
            &session.team.team_id,
        )?;
        let prepared = self.prepared.take().ok_or(Failure::ArchiveMissing)?;
        if archive::inspect(&prepared.ipa)? != job.archive {
            return Err(Failure::ArchiveChanged);
        }
        let (path, _) = Box::pin(session.signer.sign_app(
            prepared.ipa.clone(),
            Some(session.team.clone()),
            false,
            None::<fn(f32) -> std::future::Ready<()>>,
        ))
        .await
        .map_err(|error| classify(&error, Failure::Signing))?;
        let bundle =
            Bundle::new(path.clone()).map_err(|error| classify(&error, Failure::Signing))?;
        validate_signed_bundle(&bundle, job, chrono::Utc::now().timestamp())?;
        if bundle.watch_apps().is_empty() == job.archive.has_watch {
            return Err(Failure::ArchiveChanged);
        }
        let mut report = RenewalReport::default();
        report.record_profiles(&bundle);
        Ok(Signed {
            _prepared: prepared,
            path,
            phone_expiry: report.iphone_profile_expiry,
        })
    }

    async fn install_iphone(&mut self, signed: &Signed) -> Result<Option<i64>, Failure> {
        let connection = self.connection.as_mut().ok_or(Failure::Offline)?;
        tokio::time::timeout(
            Duration::from_secs(300),
            Box::pin(install_app(
                &connection.phone.provider,
                &signed.path,
                |_| {},
            )),
        )
        .await
        .map_err(|_| Failure::Interrupted)?
        .map_err(|error| classify(&error, Failure::Installation))?;
        Ok(signed.phone_expiry)
    }
    async fn install_watch(&mut self, _: &Signed) -> Result<Option<i64>, Failure> {
        Err(Failure::WatchNotSupported)
    }
}

#[cfg(test)]
mod tests;
