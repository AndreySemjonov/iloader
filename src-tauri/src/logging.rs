use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::{AppHandle, Emitter};
use tracing_subscriber::layer::Context;
use tracing_subscriber::{Layer, registry::LookupSpan};

/// Protocol dependencies can log entire pairing/plist/authentication payloads.
/// This is a hard global ceiling, independent of optional sink verbosity filters.
pub fn safe_log_metadata(metadata: &tracing::Metadata<'_>) -> bool {
    let protocol_dependency = ["idevice", "isideload", "apple_codesign", "keyring"]
        .iter()
        .any(|prefix| {
            metadata.target() == *prefix || metadata.target().starts_with(&format!("{prefix}::"))
        });
    *metadata.level() <= tracing::Level::DEBUG
        && !(protocol_dependency && *metadata.level() > tracing::Level::WARN)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, sync::Mutex};
    use tracing_subscriber::layer::SubscriberExt;

    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn pairing_dictionary_debug_never_reaches_log_sink() {
        let output = Arc::new(Mutex::new(Vec::new()));
        let writer = Capture(output.clone());
        let frontend_records = Arc::new(Mutex::new(Vec::new()));
        let records = frontend_records.clone();
        let frontend = FrontendLoggingLayer {
            emit: Arc::new(move |record| records.lock().unwrap().push(record)),
        };
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::filter::filter_fn(safe_log_metadata))
            .with(
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .with_writer(move || writer.clone())
                    .with_filter(tracing_subscriber::filter::LevelFilter::TRACE),
            )
            .with(frontend.with_filter(tracing_subscriber::filter::LevelFilter::TRACE));
        struct MustNotFormat;
        impl std::fmt::Debug for MustNotFormat {
            fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                panic!("Sensitive field formatted before privacy filter");
            }
        }
        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!(target: "idevice::remote_pairing::rp_pairing_file", payload = ?MustNotFormat, "test-sensitive-dictionary-sentinel");
            tracing::debug!(target: "idevice", payload = ?MustNotFormat, "test-wire-plist-sentinel");
            tracing::trace!(target: "idevice::remote_pairing::socket", payload = ?MustNotFormat, "test-pairing-wire-sentinel");
            tracing::debug!(target: "isideload::anisette::remote_v3", payload = ?MustNotFormat, "test-provisioning-sentinel");
            tracing::debug!(target: "isideload::auth::apple_account", payload = ?MustNotFormat, "test-auth-sentinel");
            tracing::info!(target: "iloader", "safe-operation-progress");
        });
        let bytes = output.lock().unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("test-sensitive-dictionary-sentinel"));
        assert!(text.contains("safe-operation-progress"));
        assert_eq!(frontend_records.lock().unwrap().len(), 1);
        assert!(
            frontend_records.lock().unwrap()[0]
                .message
                .contains("safe-operation-progress")
        );
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtendedLogRecord {
    pub level: u8,
    pub message: String,
    pub target: Option<String>,
    pub timestamp: String,
}

pub struct FrontendLoggingLayer {
    emit: Arc<dyn Fn(ExtendedLogRecord) + Send + Sync>,
}

impl FrontendLoggingLayer {
    pub fn new(app_handle: AppHandle) -> Self {
        Self {
            emit: Arc::new(move |record| {
                let _ = app_handle.emit("log-record", &record);
            }),
        }
    }
}

impl<S> Layer<S> for FrontendLoggingLayer
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        use tracing::field::Visit;

        let metadata = event.metadata();
        let level = match *metadata.level() {
            tracing::Level::TRACE => 1u8,
            tracing::Level::DEBUG => 2u8,
            tracing::Level::INFO => 3u8,
            tracing::Level::WARN => 4u8,
            tracing::Level::ERROR => 5u8,
        };

        let target = metadata.target().to_string();

        struct EventVisitor {
            message: String,
            fields: Vec<String>,
        }

        impl EventVisitor {
            fn push_field(&mut self, field: &tracing::field::Field, value: String) {
                if field.name() == "message" {
                    self.message = value;
                } else {
                    self.fields.push(format!("{}={}", field.name(), value));
                }
            }
        }

        impl Visit for EventVisitor {
            fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
                self.push_field(field, value.to_string());
            }

            fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
                self.push_field(field, value.to_string());
            }

            fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
                self.push_field(field, value.to_string());
            }

            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                self.push_field(field, value.to_string());
            }

            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.push_field(field, format!("{:?}", value));
            }
        }

        let mut visitor = EventVisitor {
            message: String::new(),
            fields: Vec::new(),
        };
        event.record(&mut visitor);

        let message = if visitor.fields.is_empty() {
            visitor.message
        } else {
            format!("{} ({})", visitor.message, visitor.fields.join(", "))
        };

        let timestamp = chrono::Local::now()
            .format("%Y-%m-%d %H:%M:%S%.3f")
            .to_string();

        let record = ExtendedLogRecord {
            level,
            message,
            target: Some(target),
            timestamp,
        };

        (self.emit)(record);
    }
}
