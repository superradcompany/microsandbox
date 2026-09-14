use microsandbox_protocol::{
    codec,
    core::Ready,
    message::{Message, MessageType},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use super::*;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn connection(pool: &Arc<AgentPool>) -> (AgentClient, DuplexStream) {
    let ticket = pool.ticket();
    let (client, mut peer) = tokio::io::duplex(4096);
    let handshake = tokio::spawn(async move {
        peer.write_all(&1u32.to_be_bytes()).await.unwrap();
        peer.write_all(&1024u32.to_be_bytes()).await.unwrap();
        let ready = Message::with_payload(
            MessageType::Ready,
            0,
            &Ready {
                boot_time_ns: 0,
                init_time_ns: 0,
                ready_time_ns: 0,
                agent_version: "pool-test".into(),
            },
        )
        .unwrap();
        codec::write_message(&mut peer, &ready).await.unwrap();
        peer
    });
    let client = AgentClient::connect_stream_with_timeout(client, Duration::from_secs(1))
        .await
        .unwrap()
        .with_return_ticket(ticket);
    (client, handshake.await.unwrap())
}

async fn closed(mut peer: DuplexStream) {
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), peer.read(&mut [0]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn only_completed_leases_return_and_checkout_resets_completion() {
    let pool = Arc::new(AgentPool::default());
    let (client, peer) = connection(&pool).await;
    client.completed_exec();
    drop(client);
    let reused = pool.take().expect("completed transport should be reusable");
    assert_eq!(reused.agent_version(), "pool-test");
    assert!(pool.take().is_none(), "an active lease must be exclusive");
    // A cancelled next operation must not inherit the previous completion bit.
    drop(reused);
    assert!(pool.take().is_none());
    closed(peer).await;
}

#[tokio::test]
async fn cancellation_closes_only_its_own_transport() {
    let pool = Arc::new(AgentPool::default());
    let (cancelled, cancelled_peer) = connection(&pool).await;
    let (other, other_peer) = connection(&pool).await;
    drop(cancelled);
    closed(cancelled_peer).await;
    assert!(!other.is_closed());
    other.completed_exec();
    drop(other);
    let other = pool.take().expect("peer operation remains reusable");
    drop(other);
    closed(other_peer).await;
}

#[tokio::test]
async fn burst_keeps_only_one_idle_connection() {
    let pool = Arc::new(AgentPool::default());
    let (first, first_peer) = connection(&pool).await;
    let (second, second_peer) = connection(&pool).await;
    first.completed_exec();
    second.completed_exec();
    drop(first);
    drop(second);
    closed(first_peer).await;
    let retained = pool.take().unwrap();
    assert!(pool.take().is_none());
    drop(retained);
    closed(second_peer).await;
}

#[tokio::test]
async fn invalidation_rejects_old_active_leases_and_closes_idle_connections() {
    let pool = Arc::new(AgentPool::default());
    let (old, old_peer) = connection(&pool).await;
    pool.invalidate();
    old.completed_exec();
    drop(old);
    assert!(pool.take().is_none());
    closed(old_peer).await;
    let (current, current_peer) = connection(&pool).await;
    current.completed_exec();
    drop(current);
    pool.invalidate();
    assert!(pool.take().is_none());
    closed(current_peer).await;
}

#[tokio::test]
async fn expiry_and_absolute_age_discard_connections() {
    let pool = Arc::new(AgentPool::default());
    let (idle, idle_peer) = connection(&pool).await;
    idle.completed_exec();
    drop(idle);
    pool.expire(Instant::now() + IDLE_TIMEOUT);
    assert!(pool.take().is_none());
    closed(idle_peer).await;
    let (mut old, old_peer) = connection(&pool).await;
    old.return_ticket.as_mut().unwrap().created = Instant::now() - MAX_LIFETIME;
    old.completed_exec();
    drop(old);
    assert!(pool.take().is_none());
    closed(old_peer).await;
}

#[tokio::test]
async fn dropping_pool_does_not_keep_idle_transport_alive() {
    let pool = Arc::new(AgentPool::default());
    let (client, peer) = connection(&pool).await;
    client.completed_exec();
    drop(client);
    drop(pool);
    closed(peer).await;
}

#[tokio::test]
async fn remote_disconnect_is_never_returned_as_healthy() {
    let pool = Arc::new(AgentPool::default());
    let (client, peer) = connection(&pool).await;
    drop(peer);
    tokio::time::timeout(Duration::from_secs(1), async {
        while !client.is_closed() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    client.completed_exec();
    drop(client);
    assert!(pool.take().is_none());
}
