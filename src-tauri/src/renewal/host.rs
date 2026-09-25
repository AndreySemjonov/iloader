//! One open/minimized host drains owned attempts before pause or shutdown.
use super::{
    journal::write_atomic,
    live,
    management::{Catalog, execution_available, require_execution},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tauri::{AppHandle, Emitter, Manager};
use tokio::sync::{Notify, watch};

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    pub pilot_version: u32,
    pub opted_in: bool,
    pub paused: bool,
    pub start_at_login: bool,
    pub anisette_url: String,
}
#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub settings: Settings,
    pub available: bool,
    pub running: bool,
    pub exit_pending: bool,
    pub stopped: bool,
    pub notice: Option<String>,
}
#[derive(Clone, Default)]
pub(super) struct Control {
    pub(super) active: bool,
    pub(super) stop: bool,
}
pub struct Host {
    directory: PathBuf,
    status: Arc<Mutex<Status>>,
    control: watch::Sender<Control>,
    wake: Arc<Notify>,
    _thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}
pub(crate) trait Port {
    fn jobs(&mut self) -> Result<Vec<String>, String>;
    async fn attempt(&mut self, id: &str) -> Result<(), String>;
    fn running(&mut self, value: bool);
    fn local_failure(&mut self, _error: &str) {}
}

pub(super) async fn worker(
    port: &mut impl Port,
    mut control: watch::Receiver<Control>,
    wake: Arc<Notify>,
    available: bool,
) {
    if !available {
        return;
    }
    loop {
        let state = control.borrow().clone();
        if state.stop {
            break;
        }
        if state.active {
            match port.jobs() {
                Ok(jobs) => {
                    for id in jobs {
                        if !control.borrow().active || control.borrow().stop {
                            break;
                        }
                        port.running(true);
                        // Control changes stop admission, never cancel owned work.
                        // Every native external phase is bounded; the install lease and
                        // durable outcome stay owned until the attempt settles.
                        if let Err(error) = port.attempt(&id).await {
                            port.local_failure(&error);
                        }
                        port.running(false);
                    }
                }
                Err(error) => port.local_failure(&error),
            }
        }
        if control.borrow().stop {
            break;
        }
        tokio::select! {
            changed=control.changed()=>{if changed.is_err(){break;}},
            _=wake.notified()=>{},
            _=tokio::time::sleep(Duration::from_secs(60))=>{},
        }
    }
    port.running(false);
}

impl Host {
    pub(crate) fn initialize(app: &AppHandle) -> Result<Self, String> {
        let directory = app
            .path()
            .app_data_dir()
            .map_err(|_| "Application directory unavailable")?;
        let (settings, notice) = match load_settings(&directory) {
            Ok(settings) => (settings, None),
            Err(error) => (Settings::default(), Some(error)),
        };
        let status = Arc::new(Mutex::new(Status {
            settings: settings.clone(),
            available: execution_available(),
            notice,
            stopped: !execution_available(),
            ..Default::default()
        }));
        let (control, rx) = watch::channel(Control {
            active: execution_available() && settings.opted_in && !settings.paused,
            stop: false,
        });
        let wake = Arc::new(Notify::new());
        let thread_result = (|| -> Result<Option<std::thread::JoinHandle<()>>, String> {
            if execution_available() {
                let lease = crate::install_lock::InstallLease::acquire_service(
                    &directory.join("renewal-host"),
                )
                .map_err(|_| "Another iLoader process owns the renewal host")?;
                let mut port = NativePort {
                    app: app.clone(),
                    directory: directory.clone(),
                    status: status.clone(),
                    notices: load_notices(&directory)?,
                    _host_lease: lease,
                };
                let wake = wake.clone();
                Ok(Some(
                    std::thread::Builder::new()
                        .name("iloader-renewal".into())
                        .spawn(move || {
                            if let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                                .enable_all()
                                .build()
                            {
                                runtime.block_on(worker(&mut port, rx, wake, true));
                            }
                            port.status.lock().unwrap().stopped = true;
                        })
                        .map_err(|_| "Unable to start renewal host")?,
                ))
            } else {
                Ok(None)
            }
        })();
        let thread = match thread_result {
            Ok(thread) => thread,
            Err(error) => {
                let mut status = status.lock().unwrap();
                status.available = false;
                status.stopped = true;
                status.notice = Some(error);
                None
            }
        };
        Ok(Self {
            directory,
            status,
            control,
            wake,
            _thread: Mutex::new(thread),
        })
    }
    pub fn snapshot(&self) -> Status {
        self.status.lock().unwrap().clone()
    }
    /// Product consent configures only a genuinely new host. A persisted off or
    /// paused preference is deliberate and must survive installing another app.
    pub(crate) fn authorize_first_use(&self, anisette_url: &str) -> Result<(), String> {
        require_execution()?;
        let mut status = self.status.lock().map_err(|_| "Host status unavailable")?;
        if !status.available || status.exit_pending {
            return Err("Renewal host is unavailable or exiting".into());
        }
        let path = self.directory.join("renewal-host");
        if path
            .join("settings.json")
            .try_exists()
            .map_err(|_| "Unable to inspect renewal preferences")?
        {
            return Ok(());
        }
        let settings = Settings {
            pilot_version: 1,
            opted_in: true,
            paused: false,
            start_at_login: false,
            anisette_url: anisette_url.into(),
        };
        validate_settings(&settings)?;
        commit_settings(&settings, true, |value| {
            std::fs::create_dir_all(&path).map_err(|_| "Unable to save host preferences")?;
            write_atomic(
                &path,
                "settings",
                &serde_json::to_vec(value).map_err(|_| "Unable to encode host preferences")?,
            )
        })?;
        status.settings = settings;
        self.control.send_replace(Control {
            active: true,
            stop: false,
        });
        self.wake.notify_one();
        Ok(())
    }
    pub fn configure(&self, settings: Settings) -> Result<(), String> {
        // An old persisted preference cannot bypass this build gate.
        require_execution()?;
        validate_settings(&settings)?;
        let mut status = self.status.lock().map_err(|_| "Host status unavailable")?;
        if status.exit_pending {
            return Err("iLoader is waiting to exit".into());
        }
        if !status.available {
            return Err("Renewal host is unavailable; review its status before enabling it".into());
        }
        let path = self.directory.join("renewal-host");
        commit_settings(&settings, execution_available(), |value| {
            std::fs::create_dir_all(&path).map_err(|_| "Unable to save host preferences")?;
            write_atomic(
                &path,
                "settings",
                &serde_json::to_vec(value).map_err(|_| "Unable to encode host preferences")?,
            )
        })?;
        self.control.send_replace(Control {
            active: settings.opted_in && !settings.paused,
            stop: false,
        });
        status.settings = settings;
        self.wake.notify_one();
        Ok(())
    }
    pub fn pause(&self) -> Result<(), String> {
        self.set_paused(true)
    }
    pub fn set_paused(&self, paused: bool) -> Result<(), String> {
        let mut settings = self.snapshot().settings;
        if !settings.opted_in {
            return Err("Open iLoader and explicitly opt in before resuming phone renewals".into());
        }
        settings.paused = paused;
        self.configure(settings)
    }
    pub fn wake(&self) {
        self.wake.notify_one();
    }
    pub fn shutdown(&self) {
        self.status.lock().unwrap().exit_pending = true;
        self.control.send_replace(Control {
            active: false,
            stop: true,
        });
        self.wake.notify_one();
    }
}
impl Drop for Host {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn validate_settings(settings: &Settings) -> Result<(), String> {
    let url = reqwest::Url::parse(&settings.anisette_url)
        .map_err(|_| "Choose a valid HTTPS anisette server")?;
    if settings.pilot_version != 1 || settings.start_at_login {
        return Err("These renewal settings are not supported; turn automatic renewal off and on again".into());
    }
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("Choose an HTTPS anisette server without embedded credentials".into());
    }
    Ok(())
}
fn commit_settings(
    next: &Settings,
    available: bool,
    mut persist: impl FnMut(&Settings) -> Result<(), String>,
) -> Result<(), String> {
    if !available {
        return Err("Automatic renewal is unavailable in this build".into());
    }
    if next.start_at_login {
        return Err("Windows startup is configured separately in Settings".into());
    }
    persist(next)?;
    Ok(())
}
fn load_settings(directory: &Path) -> Result<Settings, String> {
    let path = directory.join("renewal-host/settings.json");
    match std::fs::read(path) {
        Ok(bytes) => {
            let mut settings: Settings = serde_json::from_slice(&bytes)
                .map_err(|_| "Saved renewal preferences need recovery")?;
            if settings.pilot_version != 1 {
                settings.opted_in = false;
                settings.paused = true;
            }
            settings.start_at_login = false;
            Ok(settings)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Settings::default()),
        Err(_) => Err("Unable to read renewal preferences".into()),
    }
}

type Notices = BTreeMap<String, String>;
fn load_notices(directory: &Path) -> Result<Notices, String> {
    match std::fs::read(directory.join("renewal-host/notices.json")) {
        Ok(bytes) => {
            serde_json::from_slice(&bytes).map_err(|_| "Notification state needs recovery".into())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(_) => Err("Unable to read notification state".into()),
    }
}
fn notice_key(setup: &super::management::SetupView) -> Option<(String, &'static str)> {
    if setup.can_retry_connectivity && setup.account_problem.is_none() {
        return None;
    }
    if let Some(problem) = setup.account_problem.as_ref().or(setup.problem.as_ref()) {
        return Some((
            format!("action:{problem:?}"),
            "Renewal needs your attention. Open iLoader to review the saved setup.",
        ));
    }
    let success = std::iter::once(&setup.iphone)
        .chain(setup.watch.iter())
        .filter_map(|e| e.last_success)
        .max()?;
    Some((
        format!(
            "installed:{success}:{:?}",
            setup.watch.as_ref().and_then(|w| w.last_success)
        ),
        "Renewal results changed. Open iLoader for separate device results.",
    ))
}
fn new_notice(notices: &mut Notices, id: &str, key: String) -> bool {
    if notices.get(id) == Some(&key) {
        false
    } else {
        notices.insert(id.into(), key);
        true
    }
}
fn background_jobs(directory: &Path, now: i64) -> Result<Vec<String>, String> {
    Catalog::acquire(directory)?.background_jobs(now)
}

struct NativePort {
    app: AppHandle,
    directory: PathBuf,
    status: Arc<Mutex<Status>>,
    notices: Notices,
    _host_lease: crate::install_lock::InstallLease,
}
impl Port for NativePort {
    fn jobs(&mut self) -> Result<Vec<String>, String> {
        background_jobs(&self.directory, chrono::Utc::now().timestamp())
    }
    async fn attempt(&mut self, id: &str) -> Result<(), String> {
        let before = {
            let catalog = Catalog::acquire(&self.directory)?;
            catalog
                .snapshot()?
                .setups
                .iter()
                .find(|s| s.id == id)
                .and_then(notice_key)
                .map(|(key, _)| key)
        };
        let url = self.status.lock().unwrap().settings.anisette_url.clone();
        live::run_live_job(self.app.clone(), id, &url).await?;
        let catalog = Catalog::acquire(&self.directory)?;
        let snapshot = catalog.snapshot()?;
        if let Some(setup) = snapshot.setups.iter().find(|s| s.id == id) {
            if let Some((key, message)) = notice_key(setup) {
                if key.starts_with("installed:") && before.as_ref() == Some(&key) {
                    return Ok(());
                }
                let mut updated = self.notices.clone();
                if new_notice(&mut updated, id, key) {
                    let directory = self.directory.join("renewal-host");
                    std::fs::create_dir_all(&directory)
                        .map_err(|_| "Unable to save notification state")?;
                    // Persist before emitting; restarting cannot repeat the same notice.
                    write_atomic(
                        &directory,
                        "notices",
                        &serde_json::to_vec(&updated)
                            .map_err(|_| "Unable to encode notifications")?,
                    )?;
                    self.notices = updated;
                    self.status.lock().unwrap().notice = Some(message.into());
                    let _ = self.app.emit("renewal-notification", message);
                    super::desktop::refresh_tray(&self.app);
                }
            }
        }
        let _ = self.app.emit("renewal-changed", ());
        Ok(())
    }
    fn running(&mut self, value: bool) {
        self.status.lock().unwrap().running = value;
        super::desktop::refresh_tray(&self.app);
        let _ = self.app.emit("renewal-changed", ());
    }
    fn local_failure(&mut self, error: &str) {
        // Contention with an explicit install is expected; check again later.
        if error.starts_with("Another installation") {
            return;
        }
        let message = "Saved renewal state needs attention. Open iLoader to review it before the next attempt.";
        let mut status = self.status.lock().unwrap();
        if status.notice.as_deref() != Some(message) {
            status.notice = Some(message.into());
            let _ = self.app.emit("renewal-notification", message);
            drop(status);
            super::desktop::refresh_tray(&self.app);
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod integration_tests;
