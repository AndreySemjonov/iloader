#[macro_use]
mod account;
#[macro_use]
mod device;
#[macro_use]
mod sideload;
#[macro_use]
mod pairing;
#[macro_use]
mod secure_storage;
mod error;
mod install_lock;
mod logging;
mod manual_install;
mod manual_signing;
mod manual_wifi;
mod operation;
mod phone_transport;
pub mod renewal;
mod renewal_commands;
mod renewal_report;
mod wifi_pairing;
mod wifi_rsd;

use crate::{
    account::{
        delete_account, delete_app_id, get_certificates, invalidate_account, list_app_ids,
        logged_in_as, login_new, login_stored, reset_anisette_state, revoke_certificate,
    },
    device::{
        DeviceInfoMutex, PairingCancelToken, cancel_pairing, list_devices, set_selected_device,
        setup_wifi,
    },
    pairing::{
        delete_stored_rppairing, export_pairing_cmd, has_stored_rppairing, installed_pairing_apps,
        place_pairing_cmd,
    },
    secure_storage::{force_disable_keyring, keyring_available},
    sideload::{SideloaderMutex, install_sidestore_operation, renew_wifi, sideload_operation},
};
use tauri::Manager;
use tracing_subscriber::{Layer, Registry, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_store::Builder::new().build())
        .setup(|app| {
            let log_dir = app
                .path()
                .app_data_dir()
                .expect("failed to get app data dir")
                .join("logs");

            std::fs::create_dir_all(&log_dir).ok();

            let file_appender = tracing_appender::rolling::RollingFileAppender::builder()
                .rotation(tracing_appender::rolling::Rotation::DAILY)
                .filename_prefix("iloader")
                .filename_suffix("log")
                .max_log_files(2)
                .build(&log_dir)
                .expect("failed to create log file appender");

            let file_layer = fmt::layer()
                .with_writer(file_appender)
                .with_target(true)
                .with_ansi(false)
                .with_filter(tracing_subscriber::filter::filter_fn(
                    logging::safe_log_metadata,
                ));

            let frontend_layer = logging::FrontendLoggingLayer::new(app.handle().clone())
                .with_filter(tracing_subscriber::filter::filter_fn(
                    logging::safe_log_metadata,
                ));

            Registry::default()
                // Global privacy gate runs before every sink, even if a sink's
                // diagnostic verbosity is later raised by configuration.
                .with(tracing_subscriber::filter::filter_fn(
                    logging::safe_log_metadata,
                ))
                .with(file_layer)
                .with(frontend_layer)
                .init();

            std::panic::set_hook(Box::new(|panic_info| {
                let thread = std::thread::current();
                let thread_name = thread.name().unwrap_or("<unnamed>");

                let message = if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
                    s.clone()
                } else {
                    "<non-string panic payload>".to_string()
                };

                let location = panic_info
                    .location()
                    .map(|loc| format!("{}:{}", loc.file(), loc.line()))
                    .unwrap_or_else(|| "<unknown>".to_string());

                let backtrace = std::backtrace::Backtrace::capture();

                tracing::error!(
                    target: "panic",
                    thread = thread_name,
                    location = location,
                    message = message,
                    backtrace = %backtrace,
                    "panic captured"
                );
            }));

            app.manage(DeviceInfoMutex::new(None));
            app.manage(SideloaderMutex::new(None));
            app.manage(PairingCancelToken::new(None));
            app.manage(wifi_pairing::PairingOperation::new(()));
            app.manage(wifi_pairing::RepairCancellation::default());
            renewal::desktop::initialize(app.handle()).map_err(std::io::Error::other)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            login_new,
            invalidate_account,
            logged_in_as,
            login_stored,
            delete_account,
            list_devices,
            sideload_operation,
            renew_wifi,
            manual_wifi::check_wifi_connection,
            wifi_pairing::repair_wifi_pairing,
            wifi_pairing::cancel_wifi_pairing_repair,
            renewal_commands::renewal_setups,
            renewal_commands::install_auto_renewal,
            renewal_commands::manage_renewal_app,
            renewal_commands::pause_renewal_setup,
            renewal_commands::remove_renewal_setup,
            renewal::desktop::renewal_host_status,
            renewal::desktop::renewal_desktop_status,
            renewal::desktop::renewal_startup_status,
            renewal::desktop::configure_renewal_startup,
            renewal::desktop::configure_renewal_desktop,
            renewal::desktop::configure_renewal_host,
            set_selected_device,
            setup_wifi,
            install_sidestore_operation,
            get_certificates,
            revoke_certificate,
            list_app_ids,
            delete_app_id,
            installed_pairing_apps,
            place_pairing_cmd,
            reset_anisette_state,
            export_pairing_cmd,
            delete_stored_rppairing,
            keyring_available,
            force_disable_keyring,
            cancel_pairing,
            has_stored_rppairing,
        ])
        .on_window_event(|window, event| {
            if let Some(host) = window.try_state::<renewal::host::Host>() {
                match event {
                    tauri::WindowEvent::CloseRequested { api, .. } => {
                        api.prevent_close();
                        renewal::desktop::request_close(window.app_handle());
                    }
                    tauri::WindowEvent::Focused(true) => host.wake(),
                    _ => {}
                }
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app, event| {
            if let Some(host) = app.try_state::<renewal::host::Host>() {
                match event {
                    tauri::RunEvent::Resumed => host.wake(),
                    tauri::RunEvent::ExitRequested { api, .. } => {
                        if !renewal::desktop::ready_to_exit(app) {
                            api.prevent_exit();
                            renewal::desktop::request_exit(app);
                        }
                    }
                    tauri::RunEvent::Exit => host.shutdown(),
                    _ => {}
                }
            }
        });
}
