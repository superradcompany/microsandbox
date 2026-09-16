use std::path::PathBuf;

use microsandbox_control_client::{
    ControlClient, ControlClientError, ControlConnection, ControlMessageType, ControlMode,
    ControlReply, Empty, GetCapabilities, GetCpuState, GetMemoryState, JsonControlClient,
    SecretChange, SecretValue, SetCpuTarget, SetMemoryTarget, TypedMessage, UpdateSecrets,
};
use microsandbox_protocol::{codec, wire::Envelope};

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

/// Run only against a disposable VM. The caller owns the runtime and its socket.
#[tokio::test]
#[ignore = "requires MSB_CONTROL_TEST_SOCKET for a live disposable runtime"]
async fn live_framed_client_and_native_raw_paths() {
    let path = PathBuf::from(std::env::var_os("MSB_CONTROL_TEST_SOCKET").expect("live socket"));
    let client = ControlClient::connect(&path).await.unwrap();
    let caps = client.request_typed(&GetCapabilities).await.unwrap();
    let memory = client.request_typed(&GetMemoryState).await.unwrap();
    let cpu = client.request_typed(&GetCpuState).await.unwrap();
    // Same-target writes exercise each checked mutation without changing the
    // VM's resource policy or depending on a convergence delay.
    let accepted = client
        .request_typed(&SetMemoryTarget {
            total_mib: memory.target_mib,
        })
        .await
        .unwrap();
    assert_eq!(accepted.target_mib, memory.target_mib);
    let accepted = client
        .request_typed(&SetCpuTarget::new(cpu.requested_online))
        .await
        .unwrap();
    assert_eq!(accepted.requested_online, cpu.requested_online);
    let message = client
        .request(TypedMessage::new(
            ControlMessageType::Capabilities,
            Empty {},
        ))
        .await
        .unwrap();
    assert_eq!(message.t, "control.capabilities.result");
    let envelope = Envelope::new(1, "control.cpu.state", &Empty {}).unwrap();
    let response = client
        .request_raw(0, envelope.encode().unwrap())
        .await
        .unwrap();
    assert_eq!(
        Envelope::decode(&response.body).unwrap().t,
        "control.cpu.state"
    );
    // Use a second real OS connection while both clients share the runtime.
    let second = ControlClient::connect(&path).await.unwrap();
    for _ in 0..16 {
        let (left, right) = tokio::join!(
            client.request_typed(&GetCapabilities),
            second.request_typed(&GetCapabilities)
        );
        assert_eq!(left.unwrap(), caps);
        assert_eq!(right.unwrap(), caps);
    }
    let raw = codec::RawFrame {
        id: u32::MAX,
        flags: 0,
        body: envelope.encode().unwrap(),
    };
    let mut packet = Vec::new();
    codec::write_raw_frame(&mut packet, &raw).await.unwrap();
    client.write_unchecked(packet).await.unwrap();
    assert_eq!(client.request_typed(&GetCapabilities).await.unwrap(), caps);
    client.close().await;
    second.close().await;
}

/// This same binary test is used against current CBOR-capable and historical
/// JSON-only runtimes. Set the expected format explicitly for each artifact.
#[tokio::test]
#[ignore = "requires MSB_CONTROL_TEST_SOCKET and MSB_CONTROL_TEST_MODE"]
async fn live_automatic_discovery_and_explicit_json() {
    let path = PathBuf::from(std::env::var_os("MSB_CONTROL_TEST_SOCKET").expect("live socket"));
    let expected = match std::env::var("MSB_CONTROL_TEST_MODE").as_deref() {
        Ok("json") => ControlMode::Json,
        Ok("cbor") => ControlMode::Framed,
        _ => panic!("set the expected live artifact mode"),
    };
    let client = ControlConnection::connect(&path).await.unwrap();
    assert_eq!(client.mode(), expected);
    let caps = client.request_typed(&GetCapabilities).await.unwrap();
    let memory = client.request_typed(&GetMemoryState).await.unwrap();
    let cpu = client.request_typed(&GetCpuState).await.unwrap();
    assert_eq!(
        client
            .request_typed(&SetMemoryTarget {
                total_mib: memory.target_mib
            })
            .await
            .unwrap()
            .target_mib,
        memory.target_mib
    );
    assert_eq!(
        client
            .request_typed(&SetCpuTarget::new(cpu.requested_online))
            .await
            .unwrap()
            .requested_online,
        cpu.requested_online
    );
    let native = client
        .request(TypedMessage::new(
            ControlMessageType::Capabilities,
            Empty {},
        ))
        .await
        .unwrap();
    match native {
        ControlReply::Framed(reply) => {
            assert_eq!(expected, ControlMode::Framed);
            assert_eq!(reply.t, "control.capabilities.result");
        }
        ControlReply::Json(reply) => {
            assert_eq!(expected, ControlMode::Json);
            assert_eq!(reply.value().get("ok").unwrap().as_bool(), Some(true));
            assert!(reply.raw().contains(&b'{'));
            assert!(client.framed().is_err());
        }
    }
    let json = JsonControlClient::new(&path);
    assert_eq!(json.request_typed(&GetCapabilities).await.unwrap(), caps);
    assert_eq!(
        json.request_typed(&GetMemoryState)
            .await
            .unwrap()
            .target_mib,
        memory.target_mib
    );
    // The disposable fixtures have bounded capacity (512 MiB / two CPUs).
    // Exercise real target changes through automatic mode and restore through
    // the explicit legacy adapter, proving agreement between their wire forms.
    assert_eq!(
        client
            .request_typed(&SetMemoryTarget {
                total_mib: memory.max_mib
            })
            .await
            .unwrap()
            .target_mib,
        memory.max_mib
    );
    assert_eq!(
        client
            .request_typed(&SetCpuTarget::new(cpu.possible))
            .await
            .unwrap()
            .requested_online,
        cpu.possible
    );
    assert_eq!(
        json.request_typed(&SetMemoryTarget {
            total_mib: memory.target_mib
        })
        .await
        .unwrap()
        .target_mib,
        memory.target_mib
    );
    assert_eq!(
        json.request_typed(&SetCpuTarget::new(cpu.requested_online))
            .await
            .unwrap()
            .requested_online,
        cpu.requested_online
    );
    if caps.secrets_update {
        assert!(matches!(
            client
                .request_typed(&UpdateSecrets::new(vec![]))
                .await
                .unwrap(),
            microsandbox_control_client::SecretsResult::Complete { applied_count: 0 }
        ));
    }
    if let Ok(name) = std::env::var("MSB_CONTROL_TEST_SECRET") {
        let error = json
            .request_typed(&UpdateSecrets::new(vec![
                SecretChange::Remove {
                    name: "absent-control-fixture".into(),
                },
                SecretChange::Rotate {
                    name: name.clone(),
                    value: SecretValue("after-fixture".into()),
                },
                SecretChange::SetAllowedHosts {
                    name: name.clone(),
                    hosts: vec![],
                },
            ]))
            .await
            .unwrap_err();
        assert!(matches!(error, ControlClientError::LegacyRemote { .. }));
        // Legacy failure reports no trustworthy per-entry count. Restore the
        // known dummy fixture without assigning structured meaning to its text.
        json.request_typed(&UpdateSecrets::new(vec![
            SecretChange::Rotate {
                name: name.clone(),
                value: SecretValue("before".into()),
            },
            SecretChange::SetAllowedHosts {
                name,
                hosts: vec!["example.invalid".into()],
            },
        ]))
        .await
        .unwrap();
    }
    for _ in 0..8 {
        let (left, right) = tokio::join!(
            client.request_typed(&GetCpuState),
            json.request_typed(&GetCpuState)
        );
        assert_eq!(left.unwrap().requested_online, cpu.requested_online);
        assert_eq!(right.unwrap().requested_online, cpu.requested_online);
    }
    json.close().await;
    client.clone().close().await;
    assert!(client.is_closed());
}
