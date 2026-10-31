//! Per-exec environment validation at builders and execution entry points.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures::future::BoxFuture;
use microsandbox_types::EnvVar;

use crate::MicrosandboxResult;
use crate::agent::AgentClient;
use crate::backend::{Backend, BackendKind, SandboxBackend, SnapshotBackend, VolumeBackend};
use crate::error::MicrosandboxError;
use crate::sandbox::{AttachOptionsBuilder, SandboxConfig, attach, build_exec_request};

use super::{ExecOptions, ExecOptionsBuilder, RlimitResource, agent};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const INVALID_ENV: [(&str, &str, &str); 4] = [
    ("A=B", "x", "must not contain '='"),
    ("", "x", "key must not be empty"),
    ("A\0B", "x", "must not contain NUL"),
    ("K", "a\0b", "value for \"K\" must not contain NUL"),
];
const VALID_ENV: [(&str, &str); 3] = [("EMPTY", ""), ("EQUALS", "a=b=c"), ("MSB_X", "1")];

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Default)]
struct TestBackend {
    connections: AtomicUsize,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Backend for TestBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Cloud
    }

    fn sandboxes(&self) -> &dyn SandboxBackend {
        unreachable!("environment validation must not use sandbox storage")
    }

    fn volumes(&self) -> &dyn VolumeBackend {
        unreachable!("environment validation must not use volume storage")
    }

    fn snapshots(&self) -> &dyn SnapshotBackend {
        unreachable!("environment validation must not use snapshot storage")
    }

    fn dial_agent<'a>(
        &'a self,
        _name: &'a str,
        _timeout: Duration,
    ) -> BoxFuture<'a, MicrosandboxResult<AgentClient>> {
        self.connections.fetch_add(1, Ordering::Relaxed);
        Box::pin(async { Err(MicrosandboxError::Runtime("test agent connection".into())) })
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn exec_env_builder_rejects_invalid_pairs() {
    let mut failures = Vec::new();

    for (key, value, expected) in INVALID_ENV {
        for tty in [false, true] {
            let results = [
                ExecOptionsBuilder::default()
                    .tty(tty)
                    .env(key, value)
                    .build(),
                ExecOptionsBuilder::default()
                    .tty(tty)
                    .envs([(key, value)])
                    .build(),
            ];

            for result in results {
                println!("exec env {key:?}={value:?}, tty={tty}: {result:?}");
                if !matches!(result, Err(MicrosandboxError::InvalidConfig(ref message)) if message.contains(expected))
                {
                    failures.push((key, tty));
                }
            }
        }
    }

    assert!(
        failures.is_empty(),
        "invalid exec env accepted: {failures:?}"
    );
}

#[test]
fn exec_env_attach_builder_rejects_invalid_pairs() {
    for (key, value, expected) in INVALID_ENV {
        for result in [
            AttachOptionsBuilder::default().env(key, value).build(),
            AttachOptionsBuilder::default().envs([(key, value)]).build(),
        ] {
            assert!(
                matches!(result, Err(MicrosandboxError::InvalidConfig(ref message)) if message.contains(expected)),
                "{key:?}: {result:?}"
            );
        }
    }
}

#[test]
fn exec_env_builders_preserve_valid_pairs_and_serialization() {
    let expected: Vec<EnvVar> = VALID_ENV
        .iter()
        .map(|&(key, value)| EnvVar::new(key, value))
        .collect();

    for tty in [false, true] {
        let options = ExecOptionsBuilder::default()
            .tty(tty)
            .envs(VALID_ENV)
            .build()
            .unwrap();
        let mut builder = ExecOptionsBuilder::default().tty(tty);
        let mut attach_builder = AttachOptionsBuilder::default();
        for (key, value) in VALID_ENV {
            builder = builder.env(key, value);
            attach_builder = attach_builder.env(key, value);
        }

        assert_eq!(options.env, expected);
        assert_eq!(builder.build().unwrap().env, expected);
        assert_eq!(attach_builder.build().unwrap().env, expected);
        assert_eq!(
            AttachOptionsBuilder::default()
                .envs(VALID_ENV)
                .build()
                .unwrap()
                .env,
            expected
        );

        let request = build_exec_request(
            &SandboxConfig::default(),
            "env".into(),
            Vec::new(),
            None,
            None,
            &options.env,
            &[],
            tty,
            24,
            80,
        );

        assert_eq!(
            &request.env[..expected.len()],
            ["EMPTY=", "EQUALS=a=b=c", "MSB_X=1"]
        );
        assert_eq!(request.tty, tty);
    }
}

#[test]
fn exec_env_rlimit_validation_is_unchanged() {
    for (soft, hard) in [(0, 0), (5, 5), (5, 10), (10, 5)] {
        let exec = ExecOptionsBuilder::default()
            .envs(VALID_ENV)
            .rlimit_range(RlimitResource::Nofile, soft, hard)
            .build()
            .map(|_| ());
        let attach = AttachOptionsBuilder::default()
            .envs(VALID_ENV)
            .rlimit_range(RlimitResource::Nofile, soft, hard)
            .build()
            .map(|_| ());

        for result in [exec, attach] {
            if soft <= hard {
                assert!(result.is_ok(), "{soft}/{hard}: {result:?}");
            } else {
                assert!(
                    matches!(result, Err(MicrosandboxError::InvalidConfig(ref message)) if message.contains("soft (10) must not exceed hard (5)"))
                );
            }
        }
    }
}

#[tokio::test]
async fn exec_env_dispatch_rejects_invalid_pairs_without_builder() {
    let backend = TestBackend::default();
    let config = SandboxConfig::default();

    for (key, value, expected) in INVALID_ENV {
        for tty in [false, true] {
            let options = ExecOptions {
                env: vec![EnvVar::new(key, value)],
                tty,
                ..Default::default()
            };
            let results = [
                agent::exec(&backend, "test", &config, "env".into(), options.clone())
                    .await
                    .map(|_| ()),
                agent::exec_stream(&backend, "test", &config, "env".into(), options.clone())
                    .await
                    .map(|_| ()),
                agent::exec_stream_with_pty_size(
                    &backend,
                    "test",
                    &config,
                    "env".into(),
                    options,
                    40,
                    120,
                )
                .await
                .map(|_| ()),
            ];

            for result in results {
                assert!(
                    matches!(result, Err(MicrosandboxError::InvalidConfig(ref message)) if message.contains(expected)),
                    "{key:?}, tty={tty}: {result:?}"
                );
            }
        }
    }

    assert_eq!(backend.connections.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn exec_env_attach_rejects_invalid_pairs_before_connecting() {
    let backend = TestBackend::default();
    let config = SandboxConfig::default();

    for (key, value, expected) in INVALID_ENV {
        let result = attach::agent::attach(
            &backend,
            "test",
            &config,
            "env".into(),
            AttachOptionsBuilder::default().env(key, value),
        )
        .await;

        assert!(
            matches!(result, Err(MicrosandboxError::InvalidConfig(ref message)) if message.contains(expected)),
            "{key:?}: {result:?}"
        );
    }

    assert_eq!(backend.connections.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn exec_env_dispatch_accepts_valid_pairs() {
    let backend = TestBackend::default();
    let config = SandboxConfig::default();

    for tty in [false, true] {
        let options = ExecOptions {
            env: VALID_ENV
                .iter()
                .map(|&(key, value)| EnvVar::new(key, value))
                .collect(),
            tty,
            ..Default::default()
        };
        let results = [
            agent::exec(&backend, "test", &config, "env".into(), options.clone())
                .await
                .map(|_| ()),
            agent::exec_stream(&backend, "test", &config, "env".into(), options.clone())
                .await
                .map(|_| ()),
            agent::exec_stream_with_pty_size(
                &backend,
                "test",
                &config,
                "env".into(),
                options,
                40,
                120,
            )
            .await
            .map(|_| ()),
        ];

        for result in results {
            assert!(
                matches!(result, Err(MicrosandboxError::Runtime(ref message)) if message == "test agent connection")
            );
        }
    }

    let result = attach::agent::attach(
        &backend,
        "test",
        &config,
        "env".into(),
        AttachOptionsBuilder::default().envs(VALID_ENV),
    )
    .await;

    assert!(
        matches!(result, Err(MicrosandboxError::Runtime(ref message)) if message == "test agent connection")
    );
    assert_eq!(backend.connections.load(Ordering::Relaxed), 7);
}
