//! Regression coverage for recoverable console input stalls.

use std::time::Duration;

use super::*;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn assert_pending_once<F: std::future::Future>(mut future: std::pin::Pin<&mut F>) {
    std::future::poll_fn(|cx| {
        assert!(future.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
}

fn blocked_write(shared: Arc<ConsoleSharedState>) -> tokio::task::JoinHandle<bool> {
    tokio::spawn(async move {
        #[cfg(unix)]
        let capacity = AsyncFd::new(shared.rx_capacity_wake.as_raw_fd()).unwrap();

        push_bulk_fragment_with_timeout(
            &shared,
            Bytes::from_static(b"next"),
            #[cfg(unix)]
            &capacity,
            Duration::from_millis(20),
        )
        .await
    })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn input_stall_retains_frame_and_recovers_on_capacity_notification() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let shared = Arc::new(ConsoleSharedState::with_capacity(4));
        shared.rx_ring.push(Bytes::from_static(b"full")).unwrap();
        let mut health = shared.input_stalled.subscribe();
        let started = tokio::time::Instant::now();
        let writer = blocked_write(Arc::clone(&shared));

        health.wait_for(|stalled| *stalled).await.unwrap();
        assert!(started.elapsed() >= Duration::from_millis(20));
        assert!(!writer.is_finished());
        assert!(input_is_stalled(&shared, None));

        // Dropping the popped fragment releases its byte charge; wake the
        // writer exactly as the console consumer does when capacity returns.
        assert_eq!(shared.rx_ring.pop().unwrap().as_ref(), b"full");
        shared.rx_capacity_wake.wake();

        assert!(writer.await.unwrap());
        assert_eq!(shared.rx_ring.pop().unwrap().as_ref(), b"next");
        assert!(!input_is_stalled(&shared, None));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn input_stall_shutdown_and_cancellation_release_the_health_gate() {
    for cancel in [false, true] {
        tokio::time::timeout(Duration::from_secs(2), async {
            let shared = Arc::new(ConsoleSharedState::with_capacity(4));
            shared.rx_ring.push(Bytes::from_static(b"full")).unwrap();
            let mut health = shared.input_stalled.subscribe();
            let writer = blocked_write(Arc::clone(&shared));

            health.wait_for(|stalled| *stalled).await.unwrap();

            if cancel {
                writer.abort();
                assert!(writer.await.unwrap_err().is_cancelled());
                // Wake the Windows blocking capacity waiter before its runtime exits.
                shared.close();
            } else {
                shared.close();
                assert!(!writer.await.unwrap());
            }

            assert!(!*health.borrow());
            assert_eq!(shared.rx_ring.pop().unwrap().as_ref(), b"full");
            assert!(shared.rx_ring.pop().is_none());
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn input_stall_on_bulk_lane_also_closes_client_admission() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let control = Arc::new(ConsoleSharedState::with_capacity(4));
        let bulk = Arc::new(ConsoleSharedState::with_capacity(4));
        bulk.rx_ring.push(Bytes::from_static(b"full")).unwrap();
        let writer = blocked_write(Arc::clone(&bulk));

        wait_for_input_stall(&control, Some(&bulk)).await;
        assert!(!input_is_stalled(&control, None));
        assert!(input_is_stalled(&control, Some(&bulk)));

        drop(bulk.rx_ring.pop());
        bulk.rx_capacity_wake.wake();

        assert!(writer.await.unwrap());
        assert!(!input_is_stalled(&control, Some(&bulk)));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn input_stall_temporary_backpressure_keeps_admission_open() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let shared = Arc::new(ConsoleSharedState::with_capacity(4));
        shared.rx_ring.push(Bytes::from_static(b"full")).unwrap();
        let writer_shared = Arc::clone(&shared);
        let writer = tokio::spawn(async move {
            #[cfg(unix)]
            let capacity = AsyncFd::new(writer_shared.rx_capacity_wake.as_raw_fd()).unwrap();

            push_bulk_fragment_with_timeout(
                &writer_shared,
                Bytes::from_static(b"next"),
                #[cfg(unix)]
                &capacity,
                Duration::from_secs(60),
            )
            .await
        });

        tokio::task::yield_now().await;
        assert!(!input_is_stalled(&shared, None));
        drop(shared.rx_ring.pop());
        shared.rx_capacity_wake.wake();

        assert!(writer.await.unwrap());
        assert!(!input_is_stalled(&shared, None));
        assert_eq!(shared.rx_ring.pop().unwrap().as_ref(), b"next");
    })
    .await
    .unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn input_stall_admission_gate_preserves_existing_client_output() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let directory = tempfile::tempdir_in("/tmp").unwrap();
        let endpoint = directory.path().join("agent.sock");
        let shared = Arc::new(ConsoleSharedState::with_capacity(16 * 1024));
        let mut relay = AgentRelay::new(&endpoint, Arc::clone(&shared))
            .await
            .unwrap();
        relay.ready_frame = Some(tests::encoded_message(
            MessageType::Ready,
            &Ready::default(),
        ));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (drain_tx, mut drain_rx) = mpsc::channel(1);

        let mut client = tokio::net::UnixStream::connect(&endpoint).await.unwrap();
        let run = tokio::spawn(relay.run(shutdown_rx, drain_tx));
        let mut range = [0; 8];
        client.read_exact(&mut range).await.unwrap();
        let id = u32::from_be_bytes(range[..4].try_into().unwrap());
        read_raw_frame(&mut client).await.unwrap();

        // Detection is exercised with real capacity waits in the tests above.
        // Set the lane health explicitly here to isolate the admission contract.
        shared.input_stalled.send_replace(true);
        let mut rejected = tokio::net::UnixStream::connect(&endpoint).await.unwrap();
        assert!(rejected.read_exact(&mut range).await.is_err());
        assert!(!run.is_finished());
        assert!(drain_rx.try_recv().is_err());

        shared
            .tx_ring
            .push(tests::encoded_message_id(MessageType::Pong, id, &()))
            .unwrap();
        shared.tx_wake.wake();
        let response = read_raw_frame(&mut client).await.unwrap();
        assert_eq!(
            decode_frame(response.data.as_ref()).unwrap().t,
            MessageType::Pong
        );

        shared.input_stalled.send_replace(false);
        let mut recovered = tokio::net::UnixStream::connect(&endpoint).await.unwrap();
        recovered.read_exact(&mut range).await.unwrap();
        read_raw_frame(&mut recovered).await.unwrap();

        drop(shutdown_tx);
        assert!(run.await.unwrap().is_ok());
    })
    .await
    .unwrap();
}

#[cfg(unix)]
#[tokio::test(start_paused = true)]
async fn input_stall_private_write_preserves_clock_stall_until_delivery() {
    let shared = Arc::new(ConsoleSharedState::with_capacity(4096));
    shared.rx_ring.push(Bytes::from(vec![0; 4096])).unwrap();
    let (tx, rx) = ControlWriter::new();
    tx.send(ControlWrite::clock_sync().unwrap()).await.unwrap();

    let mut health = shared.input_stalled.subscribe();
    let writer = tokio::spawn(ring_writer_task(Arc::clone(&shared), rx));
    health.wait_for(|stalled| *stalled).await.unwrap();
    health.borrow_and_update();

    let control = Arc::clone(&shared.workload_control);
    let request = tokio::spawn(async move {
        control
            .request(
                Message::with_payload(
                    MessageType::WorkloadFreeze,
                    0,
                    &microsandbox_protocol::core::WorkloadFreeze {
                        external_mount_tags: Vec::new(),
                        attempt_id: "stall".into(),
                        host_input: Default::default(),
                    },
                )
                .unwrap(),
                "stall",
            )
            .await
    });

    // The clock checks capacity before pushing. A failed push proves the private
    // write has taken over the blocked delivery, rather than merely been queued.
    for _ in 0..100 {
        if shared.rx_ring.snapshot().full_events > 0 {
            break;
        }
        tokio::task::yield_now().await;
    }

    assert!(shared.rx_ring.snapshot().full_events > 0);
    assert!(
        *health.borrow(),
        "private traffic must not reopen admission"
    );
    assert!(
        !health.has_changed().unwrap(),
        "no false recovery notification"
    );

    drop(shared.rx_ring.pop());
    shared.rx_capacity_wake.wake();
    health.wait_for(|stalled| !*stalled).await.unwrap();

    let delivered = shared.rx_ring.pop().unwrap();
    assert_eq!(
        decode_frame(&delivered).unwrap().t,
        MessageType::WorkloadFreeze
    );
    drop(delivered);

    shared.close();
    writer.await.unwrap().unwrap();
    assert!(request.await.unwrap().is_err());
}

#[cfg(unix)]
#[tokio::test(start_paused = true)]
async fn input_stall_freeze_preserves_admission_gate_until_delivery() {
    let shared = Arc::new(ConsoleSharedState::with_capacity(4096));
    shared.rx_ring.push(Bytes::from(vec![0; 4096])).unwrap();
    let (tx, rx) = ControlWriter::new();
    tx.send(ControlWrite::clock_sync().unwrap()).await.unwrap();

    let mut health = shared.input_stalled.subscribe();
    let writer = tokio::spawn(ring_writer_task(Arc::clone(&shared), rx));
    health.wait_for(|stalled| *stalled).await.unwrap();
    health.borrow_and_update();

    for _ in 0..3 {
        let gate = shared.workload_control.gate();
        shared.workload_control.parked_position().await.unwrap();
        tokio::time::advance(Duration::from_secs(3600)).await;

        assert!(*health.borrow(), "freezing must not reopen admission");
        assert!(
            !health.has_changed().unwrap(),
            "no recovery without delivery"
        );

        gate.release();
        tokio::task::yield_now().await;
        assert!(*health.borrow(), "thaw must not restart the stall deadline");
    }

    drop(shared.rx_ring.pop());
    shared.rx_capacity_wake.wake();
    health.wait_for(|stalled| !*stalled).await.unwrap();

    let delivered = shared.rx_ring.pop().unwrap();
    assert_eq!(decode_frame(&delivered).unwrap().t, MessageType::ClockSync);
    drop(delivered);

    shared.close();
    writer.await.unwrap().unwrap();
}

#[tokio::test]
async fn input_stall_completion_paths_preserve_errors_during_shutdown() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for lane in ["reader", "writer", "bulk"] {
            for outcome in ["clean", "error", "panic"] {
                // Bulk reports RuntimeResult through a channel, not a JoinHandle.
                if lane == "bulk" && outcome == "panic" {
                    continue;
                }

                for shutdown_mode in ["active", "signalled", "dropped"] {
                    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
                    let (bulk_tx, mut bulk_rx) = mpsc::channel(1);
                    let result = move || match outcome {
                        "clean" => Ok(()),
                        "error" => Err(RuntimeError::Custom("injected lane failure".into())),
                        _ => panic!("injected lane panic"),
                    };

                    let mut reader = tokio::spawn(std::future::pending::<RuntimeResult<()>>());
                    let mut writer = tokio::spawn(std::future::pending::<RuntimeResult<()>>());

                    if lane == "bulk" {
                        bulk_tx.send(result()).await.unwrap();
                    } else {
                        let handle = if lane == "reader" {
                            &mut reader
                        } else {
                            &mut writer
                        };
                        handle.abort();
                        let _ = (&mut *handle).await;
                        *handle = tokio::spawn(async move { result() });

                        // Observe actual task completion before making shutdown ready.
                        // The other handles remain pending, so this exact arm must win.
                        while !handle.is_finished() {
                            tokio::task::yield_now().await;
                        }
                    }

                    match shutdown_mode {
                        "signalled" => {
                            shutdown_tx.send_replace(true);
                        }
                        "dropped" => drop(shutdown_tx),
                        _ => {}
                    }

                    let exit =
                        wait_relay_exit(&mut reader, &mut writer, &mut bulk_rx, &mut shutdown_rx)
                            .await;
                    let context = format!("{lane}, {outcome}, {shutdown_mode}");

                    assert_eq!(exit.control_writer_usable, lane != "writer", "{context}");
                    assert_eq!(
                        exit.can_observe_failure_terminals,
                        lane == "bulk",
                        "{context}"
                    );

                    if outcome == "clean" && shutdown_mode != "active" {
                        assert!(exit.failure.is_none(), "{context}: {:?}", exit.failure);
                    } else {
                        let error = exit
                            .failure
                            .unwrap_or_else(|| panic!("lost failure: {context}"));
                        let expected = match outcome {
                            "clean" => "stopped unexpectedly",
                            "error" => "injected lane failure",
                            _ => "task failed",
                        };
                        assert!(error.to_string().contains(expected), "{context}: {error}");
                    }

                    reader.abort();
                    writer.abort();
                }
            }
        }
    })
    .await
    .unwrap();
}

#[cfg(unix)]
#[tokio::test(start_paused = true)]
async fn input_stall_countdown_excludes_paused_time_without_resetting() {
    let shared = Arc::new(ConsoleSharedState::with_capacity(4096));
    shared.rx_ring.push(Bytes::from(vec![0; 4096])).unwrap();
    let (tx, rx) = ControlWriter::new();
    tx.send(ControlWrite::clock_sync().unwrap()).await.unwrap();
    let writer = ring_writer_task(Arc::clone(&shared), rx);
    tokio::pin!(writer);

    // Poll the real scheduler directly so each time advance starts only after
    // it has observed the gate transition and armed or suspended its timer.
    assert_pending_once(writer.as_mut()).await;

    for _ in 0..2 {
        tokio::time::advance(Duration::from_secs(20)).await;
        let gate = shared.workload_control.gate();

        assert_pending_once(writer.as_mut()).await;
        shared.workload_control.parked_position().await.unwrap();

        tokio::time::advance(Duration::from_secs(3600)).await;
        assert_pending_once(writer.as_mut()).await;
        assert!(
            !input_is_stalled(&shared, None),
            "intentional pause is not a stall"
        );

        gate.release();
        assert_pending_once(writer.as_mut()).await;
    }

    // Forty seconds of actual blockage have elapsed. Only twenty remain,
    // regardless of the two hours spent parked or the number of gate changes.
    tokio::time::advance(Duration::from_secs(19)).await;
    assert_pending_once(writer.as_mut()).await;
    assert!(!input_is_stalled(&shared, None));

    tokio::time::advance(Duration::from_secs(1)).await;
    assert_pending_once(writer.as_mut()).await;
    assert!(
        input_is_stalled(&shared, None),
        "resume must not restart the countdown"
    );

    shared.close();
    writer.await.unwrap();
    assert!(!input_is_stalled(&shared, None));
}

#[tokio::test]
async fn input_stall_shutdown_without_task_completion_ignores_false_updates() {
    tokio::time::timeout(Duration::from_secs(2), async {
        for drop_sender in [false, true] {
            let mut reader = tokio::spawn(std::future::pending::<RuntimeResult<()>>());
            let mut writer = tokio::spawn(std::future::pending::<RuntimeResult<()>>());
            let reader_abort = reader.abort_handle();
            let writer_abort = writer.abort_handle();
            let (_bulk_tx, mut bulk_rx) = mpsc::channel(1);
            let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
            let exit = wait_relay_exit(&mut reader, &mut writer, &mut bulk_rx, &mut shutdown_rx);
            tokio::pin!(exit);

            assert_pending_once(exit.as_mut()).await;

            shutdown_tx.send_replace(false);
            std::future::poll_fn(|cx| {
                assert!(
                    std::future::Future::poll(exit.as_mut(), cx).is_pending(),
                    "a false update must leave the relay running"
                );
                std::task::Poll::Ready(())
            })
            .await;

            if drop_sender {
                drop(shutdown_tx);
            } else {
                shutdown_tx.send_replace(true);
            }

            let result = exit.await;
            assert!(result.failure.is_none());
            assert!(!result.control_writer_usable);
            assert!(!result.can_observe_failure_terminals);

            reader_abort.abort();
            writer_abort.abort();
        }
    })
    .await
    .unwrap();
}

#[cfg(unix)]
#[tokio::test(start_paused = true)]
async fn input_stall_private_delivery_resumes_a_suspended_countdown() {
    let shared = Arc::new(ConsoleSharedState::with_capacity(4096));
    shared.rx_ring.push(Bytes::from(vec![0; 4096])).unwrap();
    let (tx, rx) = ControlWriter::new();
    tx.send(ControlWrite::clock_sync().unwrap()).await.unwrap();
    let writer = ring_writer_task(Arc::clone(&shared), rx);
    tokio::pin!(writer);
    assert_pending_once(writer.as_mut()).await;

    tokio::time::advance(Duration::from_secs(20)).await;
    let _gate = shared.workload_control.gate();
    assert_pending_once(writer.as_mut()).await;
    tokio::time::advance(Duration::from_secs(3600)).await;
    assert_pending_once(writer.as_mut()).await;
    assert!(!input_is_stalled(&shared, None));

    let message = Message::with_payload(
        MessageType::WorkloadFreeze,
        0,
        &microsandbox_protocol::core::WorkloadFreeze {
            external_mount_tags: Vec::new(),
            attempt_id: "paused".into(),
            host_input: Default::default(),
        },
    )
    .unwrap();
    let request = shared.workload_control.request(message, "paused");
    tokio::pin!(request);
    assert_pending_once(request.as_mut()).await;
    assert_pending_once(writer.as_mut()).await;
    assert!(shared.rx_ring.snapshot().full_events > 0);

    // Private lifecycle delivery is allowed through the gate, so its blocked
    // push resumes the remaining forty seconds instead of staying suspended.
    tokio::time::advance(Duration::from_secs(39)).await;
    assert_pending_once(writer.as_mut()).await;
    assert!(!input_is_stalled(&shared, None));

    tokio::time::advance(Duration::from_secs(1)).await;
    assert_pending_once(writer.as_mut()).await;
    assert!(input_is_stalled(&shared, None));

    shared.close();
    assert!(writer.await.is_err());
    assert!(request.await.is_err());
    assert!(!input_is_stalled(&shared, None));
}
