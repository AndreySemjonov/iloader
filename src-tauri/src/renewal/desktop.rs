use super::host::{Host, Settings, Status};
use lifecycle::{Close, Desktop, Surface};
use std::sync::Mutex;
use tauri::{
    AppHandle, Emitter, Manager,
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
};
pub(crate) mod lifecycle;

struct DesktopState(Mutex<Desktop>);
struct NativeSurface<'a>(&'a AppHandle);

pub(crate) fn show(app: &AppHandle) -> Result<(), String> {
    NativeSurface(app).restore()
}
fn tray_label(status: &Status) -> &'static str {
    if status.exit_pending {
        "iLoader: waiting for active work before exit"
    } else if status.running && status.settings.paused {
        "iLoader: pausing after current renewal"
    } else if status.running {
        "iLoader: renewal running"
    } else if !status.available {
        "iLoader: renewal host unavailable"
    } else if !status.settings.opted_in {
        "iLoader: phone renewal is off"
    } else if status.settings.paused {
        "iLoader: phone renewals paused"
    } else if status.notice.is_some() {
        "iLoader: review renewal status"
    } else {
        "iLoader: waiting for the next eligible check"
    }
}
impl NativeSurface<'_> {
    fn menu(&self) -> Result<(Menu<tauri::Wry>, &'static str), String> {
        let app = self.0;
        let status = app.state::<Host>().snapshot();
        let label = tray_label(&status);
        let usable = status.available && status.settings.opted_in && !status.exit_pending;
        let item = |id: &str, text: &str, enabled| {
            MenuItem::with_id(app, id, text, enabled, None::<&str>)
                .map_err(|_| "Unable to create the tray menu.".to_string())
        };
        let state = item("renewal-status", label, false)?;
        let open = item("renewal-open", "Open iLoader", true)?;
        let pause = item(
            "renewal-pause",
            "Pause renewals",
            usable && !status.settings.paused,
        )?;
        let resume = item(
            "renewal-resume",
            "Resume renewals",
            usable && status.settings.paused,
        )?;
        let quit = item("renewal-quit", "Quit iLoader", !status.exit_pending)?;
        let menu = Menu::with_items(app, &[&state, &open, &pause, &resume, &quit])
            .map_err(|_| "Unable to create the tray menu.")?;
        Ok((menu, label))
    }
    fn window(&self) -> Result<tauri::WebviewWindow, String> {
        self.0
            .get_webview_window("main")
            .ok_or("The main window is unavailable.".into())
    }
}
impl Surface for NativeSurface<'_> {
    fn tray_present(&self) -> bool {
        self.0.tray_by_id("renewal").is_some()
    }
    fn create_tray(&mut self) -> Result<(), String> {
        let (menu, label) = self.menu()?;
        let icon = self
            .0
            .default_window_icon()
            .ok_or("The tray icon image is unavailable.")?;
        TrayIconBuilder::with_id("renewal")
            .icon(icon.clone())
            .menu(&menu)
            .tooltip(label)
            .build(self.0)
            .map_err(|_| "Unable to create the tray icon.")?;
        Ok(())
    }
    fn update_tray(&mut self) -> Result<(), String> {
        let (menu, label) = self.menu()?;
        let tray = self
            .0
            .tray_by_id("renewal")
            .ok_or("The tray icon is unavailable.")?;
        tray.set_menu(Some(menu))
            .map_err(|_| "Unable to update the tray menu.")?;
        tray.set_tooltip(Some(label))
            .map_err(|_| "Unable to update tray status.")?;
        tray.set_visible(true)
            .map_err(|_| "Unable to show the tray icon.")?;
        Ok(())
    }
    fn remove_tray(&mut self) {
        self.0.remove_tray_by_id("renewal");
    }
    fn unminimize(&mut self) -> Result<(), String> {
        self.window()?
            .unminimize()
            .map_err(|_| "Unable to restore the minimized window. Try Open iLoader again.".into())
    }
    fn show(&mut self) -> Result<(), String> {
        self.window()?
            .show()
            .map_err(|_| "Unable to show the window. Try Open iLoader again.".into())
    }
    fn focus(&mut self) -> Result<(), String> {
        self.window()?
            .set_focus()
            .map_err(|_| "Unable to focus the window. Try Open iLoader again.".into())
    }
    fn hide(&mut self) -> Result<(), String> {
        self.0
            .get_webview_window("main")
            .ok_or("The main window is unavailable.")?
            .hide()
            .map_err(|_| "Unable to hide the window.".into())
    }
}
fn report(app: &AppHandle, message: String) {
    let message = match show(app) {
        Ok(()) => message,
        Err(error) => format!("{message} {error}"),
    };
    if let Some(desktop) = app.try_state::<DesktopState>() {
        desktop.0.lock().unwrap().notice(message.clone());
    }
    let _ = app.emit("renewal-notification", &message);
    let _ = app.emit("renewal-changed", ());
}
// UI thread only; one stable ID survives every status update.
pub(crate) fn sync_tray(app: &AppHandle) -> Result<(), String> {
    let Some(desktop) = app.try_state::<DesktopState>() else {
        return Ok(());
    };
    if desktop.0.lock().unwrap().tray_required() {
        NativeSurface(app).ensure_tray()?;
    }
    Ok(())
}
pub(crate) fn refresh_tray(app: &AppHandle) {
    let ui = app.clone();
    // Worker threads enqueue UI work without holding the host lock.
    if app
        .run_on_main_thread(move || {
            if ui.try_state::<Host>().is_some() {
                if let Err(message) = sync_tray(&ui) {
                    report(&ui, message);
                }
            }
        })
        .is_err()
    {
        if let Some(desktop) = app.try_state::<DesktopState>() {
            desktop
                .0
                .lock()
                .unwrap()
                .notice("Unable to refresh tray status; open iLoader to review it.".into());
        }
    }
}
pub(crate) fn request_close(app: &AppHandle) {
    let result = app
        .state::<DesktopState>()
        .0
        .lock()
        .unwrap()
        .close(&mut NativeSurface(app), crate::install_lock::exiting());
    match result {
        Ok(Close::Exit) => request_exit(app),
        Ok(Close::Stay) => {}
        Err(message) => report(app, message),
    }
    let _ = app.emit("renewal-changed", ());
}
pub(crate) fn ready_to_exit(app: &AppHandle) -> bool {
    crate::install_lock::exiting()
        && crate::install_lock::idle()
        && app.state::<Host>().snapshot().stopped
}
pub(crate) fn request_exit(app: &AppHandle) {
    let first = crate::install_lock::request_exit();
    if first {
        app.state::<Host>().shutdown();
    }
    if let Err(message) = show(app) {
        report(app, message);
    }
    if !first {
        return;
    }
    if let Err(message) = sync_tray(app) {
        report(app, message);
    }
    let _ = app.emit("renewal-changed", ());
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        // Drain every manual/timed/host owner. Only this path performs real exit.
        while !ready_to_exit(&app) {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        app.exit(0);
    });
}
#[tauri::command]
pub fn renewal_desktop_status(app: AppHandle) -> lifecycle::Status {
    app.state::<DesktopState>().0.lock().unwrap().snapshot()
}
#[tauri::command]
pub async fn configure_renewal_desktop(app: AppHandle, close_to_tray: bool) -> Result<(), String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let ui = app.clone();
    app.run_on_main_thread(move || {
        let result = if crate::install_lock::exiting() {
            Err("iLoader is waiting to exit".into())
        } else if close_to_tray && !super::management::execution_available() {
            Err("Keeping iLoader in the tray is unavailable".into())
        } else {
            ui.state::<DesktopState>()
                .0
                .lock()
                .unwrap()
                .configure(close_to_tray, &mut NativeSurface(&ui))
        };
        if let Err(message) = &result {
            report(&ui, message.clone());
        }
        let _ = ui.emit("renewal-changed", ());
        let _ = tx.send(result);
    })
    .map_err(|_| "Unable to update desktop preferences")?;
    rx.await
        .map_err(|_| "Desktop preference update did not complete")?
}
fn startup_context(app: &AppHandle) -> Result<super::startup::Startup, String> {
    let directory = app
        .path()
        .app_data_dir()
        .map_err(|_| "Application directory unavailable")?;
    // Re-evaluate the actual executable for each explicit action/status read so
    // a moved/deleted file cannot be registered from a stale launch-time path.
    Ok(super::startup::Startup::new(
        &directory,
        cfg!(windows) && super::management::execution_available(),
        super::startup::current_command(),
    ))
}
#[tauri::command]
pub(crate) fn renewal_startup_status(app: AppHandle) -> super::startup::Status {
    match startup_context(&app) {
        Ok(startup) => startup.snapshot(&mut super::startup::NativeRegistry),
        Err(error) => super::startup::Status {
            notice: Some(error),
            ..Default::default()
        },
    }
}
#[tauri::command]
pub async fn configure_renewal_startup(app: AppHandle, enabled: bool) -> Result<(), String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let ui = app.clone();
    app.run_on_main_thread(move || {
        let result = if crate::install_lock::exiting() {
            Err("iLoader is waiting to exit".into())
        } else if !ui.state::<Host>().snapshot().available {
            Err(
                "The renewal host is unavailable or already open. Use the existing iLoader window."
                    .into(),
            )
        } else {
            startup_context(&ui).and_then(|startup| {
                ui.state::<DesktopState>()
                    .0
                    .lock()
                    .unwrap()
                    .configure_startup(
                        &startup,
                        &mut super::startup::NativeRegistry,
                        enabled,
                        &mut NativeSurface(&ui),
                    )
            })
        };
        if let Err(message) = &result {
            report(&ui, message.clone());
        }
        let _ = ui.emit("renewal-changed", ());
        let _ = tx.send(result);
    })
    .map_err(|_| "Unable to update Windows startup")?;
    rx.await
        .map_err(|_| "Windows startup update did not finish")?
}
#[tauri::command]
pub fn renewal_host_status(host: tauri::State<'_, Host>) -> Status {
    host.snapshot()
}
#[tauri::command]
pub fn configure_renewal_host(
    app: AppHandle,
    host: tauri::State<'_, Host>,
    settings: Settings,
) -> Result<(), String> {
    host.configure(settings)?;
    if let Err(message) = sync_tray(&app) {
        report(&app, message);
    }
    let _ = app.emit("renewal-changed", ());
    Ok(())
}
pub(crate) fn initialize(app: &AppHandle) -> Result<(), String> {
    let directory = app
        .path()
        .app_data_dir()
        .map_err(|_| "Application directory unavailable")?;
    app.manage(Host::initialize(app)?);
    // A duplicate process must also keep X-to-tray disabled. Preserve its stored
    // preference for the actual host owner rather than hiding an extra process.
    app.manage(DesktopState(Mutex::new(Desktop::load(
        &directory,
        app.state::<Host>().snapshot().available,
    ))));

    // Register once per application, never once per icon recreation. Tauri tray
    // builder menu handlers are global and survive removal of the icon.
    app.on_menu_event(|app, event| {
        let result = match event.id.as_ref() {
            "renewal-open" => show(app),
            "renewal-pause" => app.state::<Host>().set_paused(true),
            "renewal-resume" => app.state::<Host>().set_paused(false),
            "renewal-quit" => {
                request_exit(app);
                Ok(())
            }
            _ => return,
        };
        if let Err(message) = result {
            report(app, message);
        }
        if let Err(message) = sync_tray(app) {
            report(app, message);
        }
        let _ = app.emit("renewal-changed", ());
    });
    if let Err(message) = sync_tray(app) {
        report(app, message);
    }
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    let startup = startup_context(app)?;
    let result = app
        .state::<DesktopState>()
        .0
        .lock()
        .unwrap()
        .launch_startup(
            &startup,
            &mut super::startup::NativeRegistry,
            &args,
            app.state::<Host>().snapshot().available,
            &mut NativeSurface(app),
        );
    if let Err(message) = result {
        report(app, message);
    }
    // Only the verified explicit startup argument may hide; normal launch stays visible.
    Ok(())
}
