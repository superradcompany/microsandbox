//! Regression coverage for secret policy diagnostics at the request boundary.

#![cfg(feature = "engine")]

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use microsandbox_network::config::builder::SecretBuilder;
use microsandbox_network::conn::ProxyConnectState;
use microsandbox_network::policy::NetworkPolicy;
use microsandbox_network::secrets::config::{SecretViolationAction, SecretsConfig};
use microsandbox_network::secrets::handle::SecretsHandle;
use microsandbox_network::secrets::handler::SecretsHandler;
use microsandbox_network::shared::{ResolvedHostnameFamily, SharedState};
use microsandbox_network::tcp::proxy::spawn_tcp_proxy;
use microsandbox_network::tls::state::TlsState;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Level, Metadata, Subscriber};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Clone, Default)]
struct CapturedLogs(Arc<Mutex<Vec<CapturedEvent>>>);

struct CapturedEvent {
    level: Level,
    fields: BTreeMap<String, String>,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Visit for CapturedEvent {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.fields
            .insert(field.name().into(), format!("{value:?}"));
    }
}

impl Subscriber for CapturedLogs {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}

    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn enter(&self, _: &Id) {}

    fn exit(&self, _: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut captured = CapturedEvent {
            level: *event.metadata().level(),
            fields: BTreeMap::new(),
        };
        event.record(&mut captured);
        self.0.lock().unwrap().push(captured);
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn assert_proxy_violation_logs(logs: &CapturedLogs) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    for action in [
        SecretViolationAction::Block,
        SecretViolationAction::BlockAndLog,
        SecretViolationAction::BlockAndTerminate,
    ] {
        for path in ["first flight", "body relay", "CONNECT"] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let config = SecretsConfig {
                secrets: vec![
                    SecretBuilder::new()
                        .env("API_KEY")
                        .value("real-secret")
                        .placeholder("$KEY")
                        .allow("api.example.com")
                        .build(),
                ],
                violation_action: action.clone(),
                ..Default::default()
            };
            let tls_state = (path == "CONNECT").then(|| {
                Arc::new(
                    TlsState::new(Default::default(), SecretsHandle::new(config.clone())).unwrap(),
                )
            });
            let shared = Arc::new(SharedState::new(4));
            shared.cache_resolved_hostname(
                "api.example.com",
                ResolvedHostnameFamily::Ipv4,
                [addr.ip()],
                Duration::from_secs(60),
            );
            let terminated = Arc::new(AtomicBool::new(false));
            let termination_flag = terminated.clone();
            shared.set_termination_hook(Arc::new(move || {
                termination_flag.store(true, Ordering::SeqCst);
            }));
            let (from_tx, from_rx) = mpsc::channel(8);
            let (to_tx, mut to_rx) = mpsc::channel(8);
            let request = match path {
                "first flight" => {
                    "GET / HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer $KEY\r\n\r\n"
                }
                "body relay" => {
                    "POST / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 4\r\n\r\n"
                }
                "CONNECT" => {
                    "CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\nProxy-Authorization: Bearer $KEY\r\n\r\n"
                }
                _ => unreachable!(),
            };
            from_tx
                .send(Bytes::from_static(request.as_bytes()))
                .await
                .unwrap();
            logs.0.lock().unwrap().clear();
            spawn_tcp_proxy(
                &tokio::runtime::Handle::current(),
                addr,
                addr,
                from_rx,
                to_tx,
                shared,
                Arc::new(NetworkPolicy::default()),
                Arc::new(config),
                tls_state,
                false,
                Arc::new(ProxyConnectState::new()),
                None,
            );
            let (mut server, _) = listener.accept().await.unwrap();
            if path == "body relay" {
                // Observing the headers upstream proves the placeholder arrives
                // in the relay loop, after first-flight inspection has finished.
                let mut headers = vec![0; request.len()];
                server.read_exact(&mut headers).await.unwrap();
                assert_eq!(headers, request.as_bytes());
                from_tx.send(Bytes::from_static(b"$KEY")).await.unwrap();
            }
            drop(from_tx);
            let mut blocked_bytes = Vec::new();
            server.read_to_end(&mut blocked_bytes).await.unwrap();
            assert!(
                blocked_bytes.is_empty(),
                "{path}: blocked data reached upstream"
            );
            assert!(to_rx.recv().await.is_none(), "{path}: proxy must close");
            assert_eq!(
                terminated.load(Ordering::SeqCst),
                action == SecretViolationAction::BlockAndTerminate
            );

            let events = logs.0.lock().unwrap();
            let violations: Vec<_> = events
                .iter()
                .filter(|event| {
                    event
                        .fields
                        .get("message")
                        .is_some_and(|message| message.contains("secret violation"))
                })
                .collect();
            if action == SecretViolationAction::Block {
                assert!(
                    violations.is_empty(),
                    "{path}: silent blocking logged a violation"
                );
            } else {
                assert_eq!(violations.len(), 1, "{path}: log each violation once");
                assert_eq!(
                    violations[0].level,
                    if action == SecretViolationAction::BlockAndLog {
                        Level::WARN
                    } else {
                        Level::ERROR
                    }
                );
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn secret_violation_logs_distinguish_blocking_from_allowed_placeholders() {
    // Keep tracing capture in its own integration-test process so concurrent
    // unit tests cannot change callsite interest while these events are emitted.
    let logs = CapturedLogs::default();
    let _subscriber = tracing::subscriber::set_default(logs.clone());

    for action in [
        SecretViolationAction::Block,
        SecretViolationAction::BlockAndLog,
        SecretViolationAction::BlockAndTerminate,
    ] {
        for tls_intercepted in [false, true] {
            for (location, request) in [
                (
                    "header",
                    "GET / HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer $KEY\r\n\r\n",
                ),
                (
                    "body",
                    "POST / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 4\r\n\r\n$KEY",
                ),
            ] {
                logs.0.lock().unwrap().clear();
                let config = SecretsConfig {
                    secrets: vec![
                        SecretBuilder::new()
                            .env("API_KEY")
                            .value("real-secret")
                            .placeholder("$KEY")
                            .allow("api.example.com")
                            .build(),
                    ],
                    violation_action: action.clone(),
                    ..Default::default()
                };
                let mut handler = SecretsHandler::new(&config, "api.example.com", tls_intercepted);
                let result = handler.substitute(request.as_bytes());
                let events = logs.0.lock().unwrap();

                if tls_intercepted {
                    let expected = if location == "header" {
                        request.replace("$KEY", "real-secret")
                    } else {
                        request.to_string()
                    };
                    assert_eq!(result.unwrap().as_ref(), expected.as_bytes());
                    assert!(
                        events.is_empty(),
                        "permitted requests must not log violations"
                    );
                    continue;
                }

                assert_eq!(result.unwrap_err(), action);
                if action == SecretViolationAction::Block {
                    assert!(events.is_empty(), "silent blocking must not log violations");
                    continue;
                }

                assert_eq!(events.len(), 1);
                let event = &events[0];
                let (level, action_name, message) = match action {
                    SecretViolationAction::BlockAndLog => (
                        Level::WARN,
                        "block-and-log",
                        "secret violation: placeholder detected where substitution or passthrough is not permitted",
                    ),
                    SecretViolationAction::BlockAndTerminate => (
                        Level::ERROR,
                        "block-and-terminate",
                        "secret violation: placeholder detected where substitution or passthrough is not permitted - terminating",
                    ),
                    SecretViolationAction::Block => unreachable!(),
                };
                assert_eq!(event.fields["message"], message);
                assert_eq!(event.level, level);
                assert_eq!(event.fields["action"], action_name);
                assert_eq!(event.fields["sni"], "api.example.com");
                assert_eq!(event.fields["location"], location);
                assert!(
                    event
                        .fields
                        .values()
                        .all(|value| !value.contains("real-secret"))
                );
            }
        }
    }

    // Use the same isolated process and subscriber to cover the real proxy's
    // logging and termination, not just the handler's returned action.
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(10), assert_proxy_violation_logs(&logs))
                .await
                .expect("proxy violation checks timed out");
        });
}
