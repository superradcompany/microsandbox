//! Opt-in lost replies after actual runtime mutations, with no protocol rewriting.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use futures::FutureExt;
use microsandbox_control_client::{
    CheckedControlRequest, ControlClientError, ControlClientResult, ControlConnection, ControlMode,
    Delivery, ErrorKind, GetCapabilities, GetCpuState, GetMemoryState, JsonReply, SetCpuTarget,
    SetMemoryTarget, UpdateSecrets, VerifiedControlConnector,
};
use microsandbox_protocol::{
    codec,
    control::{SecretChange, SecretValue, SecretsResult},
    wire::Envelope,
};
use microsandbox_protocol_client::{BoxFuture, BoxTransport, Message, RawFrame};
use microsandbox_utils::size::SizeExt;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::backend::LocalBackend;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const TOKEN: &str = "MSB_CONTROL_FIXTURE_TOKEN";
const GUARD: &str = "MSB_CONTROL_FIXTURE_GUARD";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct ReplyDropper {
    owner: Arc<dyn VerifiedControlConnector>,
    mode: ControlMode,
    dials: AtomicUsize,
    mutations: Arc<AtomicUsize>,
    relay: Mutex<Option<JoinHandle<CapturedReply>>>,
}

enum CapturedReply {
    Framed(RawFrame),
    Json(Vec<u8>),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CapturedReply {
    fn decode<R: CheckedControlRequest>(self, request: &R) -> ControlClientResult<R::Response> {
        match self {
            Self::Framed(frame) => {
                let envelope = Envelope::decode(&frame.body)?;
                request.decode(Message::new(frame, envelope))
            }
            Self::Json(line) => request.decode_json(JsonReply::parse(line)?),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl VerifiedControlConnector for ReplyDropper {
    fn connect(&self, deadline: Instant) -> BoxFuture<'_, ControlClientResult<BoxTransport>> {
        Box::pin(async move {
            let dial = self.dials.fetch_add(1, Ordering::SeqCst) + 1;
            let actual = self.owner.connect(deadline).await?;
            if dial != 2 {
                return Ok(actual);
            }
            // Discovery passes directly through the verified owner. Only the
            // operation connection is intercepted; framed welcome still passes.
            let (client, relay) = tokio::io::duplex(16 * 1024);
            let mode = self.mode;
            let mutations = self.mutations.clone();
            let task = tokio::spawn(discard_reply(mode, actual, relay, mutations));
            assert!(self.relay.lock().unwrap().replace(task).is_none());
            Ok(Box::new(client) as BoxTransport)
        })
    }

    fn verify_session(&self, deadline: Instant) -> BoxFuture<'_, ControlClientResult<()>> {
        self.owner.verify_session(deadline)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn discard_reply(
    mode: ControlMode,
    actual: BoxTransport,
    relay: DuplexStream,
    mutations: Arc<AtomicUsize>,
) -> CapturedReply {
    let (mut server_read, mut server_write) = tokio::io::split(actual);
    let (mut client_read, mut client_write) = tokio::io::split(relay);
    let upstream = async {
        match mode {
            ControlMode::Framed => loop {
                let frame = codec::read_raw_frame(&mut client_read).await.unwrap();
                let envelope = Envelope::decode(&frame.body).unwrap();
                if envelope.t != "control.hello" {
                    assert!(matches!(
                        envelope.t.as_str(),
                        "control.cpu.target" | "control.memory.target" | "control.secrets.update"
                    ));
                    mutations.fetch_add(1, Ordering::SeqCst);
                }
                codec::write_raw_frame(&mut server_write, &frame)
                    .await
                    .unwrap();
            },
            ControlMode::Json => {
                let mut reader = BufReader::new(client_read);
                loop {
                    let mut line = Vec::new();
                    assert!(reader.read_until(b'\n', &mut line).await.unwrap() > 0);
                    let request: serde_json::Value = serde_json::from_slice(&line).unwrap();
                    assert!(matches!(
                        request["op"].as_str(),
                        Some("cpu_target" | "memory_target" | "secrets_update")
                    ));
                    mutations.fetch_add(1, Ordering::SeqCst);
                    server_write.write_all(&line).await.unwrap();
                    server_write.flush().await.unwrap();
                }
            }
        }
    };
    let downstream = async {
        match mode {
            ControlMode::Framed => {
                let welcome = codec::read_raw_frame(&mut server_read).await.unwrap();
                assert_eq!(
                    Envelope::decode(&welcome.body).unwrap().t,
                    "control.welcome"
                );
                codec::write_raw_frame(&mut client_write, &welcome)
                    .await
                    .unwrap();
                CapturedReply::Framed(codec::read_raw_frame(&mut server_read).await.unwrap())
            }
            ControlMode::Json => {
                let mut line = Vec::new();
                assert!(
                    BufReader::new(server_read)
                        .read_until(b'\n', &mut line)
                        .await
                        .unwrap()
                        > 0
                );
                CapturedReply::Json(line)
            }
        }
    };
    // The real runtime has produced its full operation response. Retain that
    // evidence without forwarding a byte of it, then drop both stream halves.
    tokio::select! {
        biased;
        reply = downstream => reply,
        _ = upstream => panic!("request forwarding ended before the reply was captured"),
    }
}

async fn lose_reply<R: CheckedControlRequest>(
    owner: Arc<dyn VerifiedControlConnector>,
    mode: ControlMode,
    label: &str,
    request: &R,
) -> CapturedReply {
    tokio::time::timeout(Duration::from_secs(15), async {
        let connector = Arc::new(ReplyDropper {
            owner,
            mode,
            dials: AtomicUsize::new(0),
            mutations: Arc::new(AtomicUsize::new(0)),
            relay: Mutex::new(None),
        });
        let client = ControlConnection::connect_verified_connector(connector.clone()).await.unwrap();
        assert_eq!(client.mode(), mode);
        let error = client.request_typed(request).await.err().expect("operation reply was discarded");
        assert!(matches!(&error, ControlClientError::Client(error) if error.kind == ErrorKind::PeerClosed), "{error:?}");
        assert_eq!(error.delivery(), Delivery::Unknown);
        assert!(client.is_closed());
        assert_eq!(connector.dials.load(Ordering::SeqCst), 2);
        assert_eq!(connector.mutations.load(Ordering::SeqCst), 1);
        let task = connector.relay.lock().unwrap().take().unwrap();
        let reply = task.await.unwrap();

        let error = client.request_typed(request).await.err().expect("closed handle must fail locally");
        assert!(matches!(&error, ControlClientError::Client(error) if error.kind == ErrorKind::Closed));
        assert_eq!(error.delivery(), Delivery::NotSent);
        assert_eq!(connector.dials.load(Ordering::SeqCst), 2);
        assert_eq!(connector.mutations.load(Ordering::SeqCst), 1);

        let fresh = ControlConnection::connect_verified_connector(connector.clone()).await.unwrap();
        fresh.request_typed(&GetCapabilities).await.unwrap();
        fresh.close().await;
        assert_eq!(connector.dials.load(Ordering::SeqCst), 4);
        assert_eq!(connector.mutations.load(Ordering::SeqCst), 1);
        println!("{mode:?} lost {label} reply: PeerClosed/Unknown; one forwarded mutation; closed handle NotSent with no dial; explicit fresh setup/read passed");
        reply
    })
    .await
    .expect("live lost-reply deadline")
}

fn rotate(name: &str, value: &str) -> UpdateSecrets {
    UpdateSecrets::new(vec![SecretChange::Rotate {
        name: name.into(),
        value: SecretValue(value.into()),
    }])
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a running disposable VM with 1/2 CPUs, 256/512 MiB, TOKEN/GUARD dummy secrets, and MSB_CONTROL_TEST_HOME/NAME/MODE; back up historical DB before current SDK access"]
async fn live_lost_cpu_memory_and_secret_batch_replies_are_unknown_without_replay() {
    let home = std::env::var("MSB_CONTROL_TEST_HOME").unwrap();
    let name = std::env::var("MSB_CONTROL_TEST_NAME").unwrap();
    let mode = if std::env::var("MSB_CONTROL_TEST_MODE").unwrap() == "json" {
        ControlMode::Json
    } else {
        ControlMode::Framed
    };
    let local = Arc::new(LocalBackend::builder().home(home).build().await.unwrap());
    let backend: Arc<dyn crate::backend::Backend> = local.clone();
    crate::backend::with_backend(backend, async {
        let result = std::panic::AssertUnwindSafe(async {
            let observer = local.control_session(&name).await.unwrap().unwrap();
            assert_eq!(observer.mode(), mode);
            assert!(observer.capabilities().secrets_update);
            let owner = observer.entry.connector.clone();
            let cpu = observer.request(&GetCpuState).await.unwrap();
            let memory = observer.request(&GetMemoryState).await.unwrap();
            assert_eq!(cpu.requested_online, 1);
            assert!(cpu.possible >= 2);
            assert_eq!(memory.target_mib, 256);
            assert!(memory.max_mib >= 512);

            let request = SetCpuTarget::new(2);
            let reply = lose_reply(owner.clone(), mode, "CPU", &request).await;
            assert_eq!(reply.decode(&request).unwrap().requested_online, 2);
            assert_eq!(observer.request(&GetCpuState).await.unwrap().requested_online, 2);
            observer.request(&SetCpuTarget::new(1)).await.unwrap();

            let request = SetMemoryTarget::new(512.mib());
            let reply = lose_reply(owner.clone(), mode, "memory", &request).await;
            assert_eq!(reply.decode(&request).unwrap().target_mib, 512);
            assert_eq!(observer.request(&GetMemoryState).await.unwrap().target_mib, 512);
            observer.request(&SetMemoryTarget::new(256.mib())).await.unwrap();

            let request = rotate(TOKEN, "accepted-test-material");
            let reply = lose_reply(owner.clone(), mode, "complete secret batch", &request).await;
            assert!(matches!(reply.decode(&request).unwrap(), SecretsResult::Complete { applied_count: 1 }));

            let request = UpdateSecrets::new(vec![
                SecretChange::Remove { name: TOKEN.into() },
                SecretChange::Rotate { name: TOKEN.into(), value: SecretValue("cannot-rotate-removed-secret".into()) },
                SecretChange::Remove { name: GUARD.into() },
            ]);
            let reply = lose_reply(owner, mode, "partial secret batch", &request).await;
            match mode {
                ControlMode::Framed => assert!(matches!(reply.decode(&request).unwrap(), SecretsResult::Failed { applied_count: 1, failed_index: 1, .. })),
                ControlMode::Json => assert!(matches!(reply.decode(&request), Err(ControlClientError::LegacyRemote { .. }))),
            }

            // Membership is independently observable through the real runtime:
            // the first removal happened, and the unattempted suffix did not.
            // JSON itself still makes no claim about a structured applied count.
            let removed = observer.request(&rotate(TOKEN, "must-remain-absent")).await;
            match mode {
                ControlMode::Framed => assert!(matches!(removed.unwrap(), SecretsResult::Failed { applied_count: 0, failed_index: 0, .. })),
                ControlMode::Json => assert!(matches!(&*removed.unwrap_err(), ControlClientError::LegacyRemote { .. })),
            }
            assert!(matches!(observer.request(&rotate(GUARD, "before")).await.unwrap(), SecretsResult::Complete { applied_count: 1 }));
            assert_eq!(observer.request(&GetCpuState).await.unwrap().requested_online, 1);
            assert_eq!(observer.request(&GetMemoryState).await.unwrap().target_mib, 256);
            println!("{mode:?} independent state checks: CPU/memory mutations observed and restored; partial batch removed TOKEN and retained GUARD; runtime PID {}", observer.entry.key.pid);
        })
        .catch_unwind()
        .await;
        crate::Sandbox::get(&name).await.unwrap().stop().await.expect("stop disposable lost-reply VM");
        result.unwrap();
    })
    .await;
}
