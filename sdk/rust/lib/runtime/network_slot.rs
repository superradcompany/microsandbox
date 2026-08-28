//! Bounded network-slot leases for active local sandbox runs.

use std::num::NonZeroU16;

use microsandbox_db::entity::sandbox as sandbox_entity;
use sea_orm::{
    ActiveEnum, ColumnTrait, ConnectionTrait, EntityTrait, Iterable, QueryFilter, Statement,
    sea_query::Expr,
};

use crate::{MicrosandboxError, MicrosandboxResult, backend::LocalBackend};

/// A valid network address-pool slot.
///
/// `NonZeroU16` encodes the complete `1..=65_535` domain used by MAC and IP
/// derivation. SQLite stores the value as a checked `INTEGER`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct NetworkSlot(NonZeroU16);

impl NetworkSlot {
    pub(super) fn get(self) -> u16 {
        self.0.get()
    }

    /// Assign the lowest available network slot to an active sandbox start.
    ///
    /// The slot is released when the sandbox stops and may change after a
    /// restart. Concurrent starts cannot receive the same slot.
    pub(super) async fn lease(local: &LocalBackend, sandbox_id: i32) -> MicrosandboxResult<Self> {
        let pools = local.db().await?;
        let db = pools.write();

        if let Some(slot) = Self::try_lease(db, sandbox_id).await? {
            return Ok(slot);
        }

        // Exhaustion can be caused by a missed terminal-state cleanup. Repair
        // those stale leases only on this cold path, then retry atomically.
        db.transaction(|txn| async move {
            Self::reclaim_inactive(&txn).await?;
            let slot = Self::try_lease(&txn, sandbox_id)
                .await?
                .ok_or_else(|| MicrosandboxError::Runtime("network slot pool exhausted".into()))?;

            Ok((txn, slot))
        })
        .await
    }

    /// Atomically claim the lowest available slot, returning `None` at capacity.
    async fn try_lease(
        db: &impl ConnectionTrait,
        sandbox_id: i32,
    ) -> MicrosandboxResult<Option<Self>> {
        const QUERY: &str = "
            UPDATE sandbox
            SET network_slot = COALESCE(network_slot, (
                SELECT MIN(candidate.slot)
                FROM (
                    SELECT 1 AS slot
                    UNION ALL
                    SELECT network_slot + 1 AS slot
                    FROM sandbox
                    WHERE network_slot < ?
                ) AS candidate
                LEFT JOIN sandbox AS occupied
                    ON occupied.network_slot = candidate.slot
                WHERE occupied.network_slot IS NULL
            ))
            WHERE id = ? AND status IN (?, ?)
            RETURNING network_slot
        ";

        let values = [
            u16::MAX.into(),
            sandbox_id.into(),
            sandbox_entity::SandboxStatus::Starting.into_value().into(),
            sandbox_entity::SandboxStatus::Running.into_value().into(),
        ];

        let conn = db.get_database_backend();
        db.query_one_raw(Statement::from_sql_and_values(conn, QUERY, values))
            .await?
            .ok_or_else(|| {
                MicrosandboxError::Runtime(format!(
                    "sandbox {sandbox_id} is missing or not starting"
                ))
            })?
            .try_get_by_index::<Option<u16>>(0)?
            .map(Self::try_from)
            .transpose()
    }

    /// Release leaked slots held by inactive sandboxes.
    async fn reclaim_inactive(db: &impl ConnectionTrait) -> MicrosandboxResult<()> {
        let inactive_statuses = sandbox_entity::SandboxStatus::iter()
            .filter(|status| !status.has_active_runtime_state());
        sandbox_entity::Entity::update_many()
            .col_expr(
                sandbox_entity::Column::NetworkSlot,
                Expr::value(Option::<u16>::None),
            )
            .filter(sandbox_entity::Column::NetworkSlot.is_not_null())
            .filter(sandbox_entity::Column::Status.is_in(inactive_statuses))
            .exec(db)
            .await?;
        Ok(())
    }
}

impl TryFrom<u16> for NetworkSlot {
    type Error = MicrosandboxError;

    fn try_from(slot: u16) -> Result<Self, Self::Error> {
        NonZeroU16::new(slot)
            .map(Self)
            .ok_or_else(|| MicrosandboxError::Runtime("network slot must be nonzero".into()))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use futures::future::join_all;
    use sea_orm::{
        ColumnTrait, ConnectionTrait, EntityTrait, PaginatorTrait, QueryFilter, QuerySelect, Set,
    };
    use tempfile::tempdir;
    use tokio::sync::Barrier;

    use super::*;

    async fn insert_sandbox_rows_with_ids(backend: &LocalBackend, ids: &[i32]) {
        let pools = backend.db().await.unwrap();
        let now = chrono::Utc::now().naive_utc();
        let models: Vec<sandbox_entity::ActiveModel> = ids
            .iter()
            .map(|id| sandbox_entity::ActiveModel {
                id: Set(*id),
                name: Set(format!("slot-test-{id}")),
                config: Set("{}".to_string()),
                status: Set(sandbox_entity::SandboxStatus::Running),
                ephemeral: Set(false),
                created_at: Set(Some(now)),
                updated_at: Set(Some(now)),
                ..Default::default()
            })
            .collect();
        if !models.is_empty() {
            sandbox_entity::Entity::insert_many(models)
                .exec(pools.write())
                .await
                .unwrap();
        }
    }

    #[test]
    fn conversion_enforces_nonzero_u16_domain() {
        assert_eq!(NetworkSlot::try_from(1).unwrap().get(), 1);
        assert_eq!(NetworkSlot::try_from(u16::MAX).unwrap().get(), u16::MAX);
        assert_eq!(
            NetworkSlot::try_from(0).unwrap_err().to_string(),
            "runtime error: network slot must be nonzero"
        );
    }

    #[tokio::test]
    async fn allocates_the_lowest_free_slot() {
        let temp = tempdir().unwrap();
        let backend = LocalBackend::builder()
            .home(temp.path().join("msb-home"))
            .build()
            .await
            .unwrap();

        insert_sandbox_rows_with_ids(&backend, &[65_700, 65_701]).await;
        assert_eq!(NetworkSlot::lease(&backend, 65_700).await.unwrap().get(), 1);
        assert_eq!(NetworkSlot::lease(&backend, 65_701).await.unwrap().get(), 2);
    }

    #[tokio::test]
    async fn recycles_the_lowest_free_slot_past_the_id_cap() {
        let temp = tempdir().unwrap();
        let backend = LocalBackend::builder()
            .home(temp.path().join("msb-home"))
            .build()
            .await
            .unwrap();

        insert_sandbox_rows_with_ids(&backend, &[1, 2, 65_700]).await;
        assert_eq!(NetworkSlot::lease(&backend, 1).await.unwrap().get(), 1);
        assert_eq!(NetworkSlot::lease(&backend, 2).await.unwrap().get(), 2);
        assert_eq!(NetworkSlot::lease(&backend, 65_700).await.unwrap().get(), 3);

        let pools = backend.db().await.unwrap();
        sandbox_entity::Entity::delete_by_id(65_700)
            .exec(pools.write())
            .await
            .unwrap();
        insert_sandbox_rows_with_ids(&backend, &[65_701]).await;
        assert_eq!(NetworkSlot::lease(&backend, 65_701).await.unwrap().get(), 3);
    }

    #[tokio::test]
    async fn finds_a_gap_below_the_highest_lease() {
        let temp = tempdir().unwrap();
        let backend = LocalBackend::builder()
            .home(temp.path().join("msb-home"))
            .build()
            .await
            .unwrap();

        insert_sandbox_rows_with_ids(&backend, &[65_700, 65_701, 65_702]).await;
        let pools = backend.db().await.unwrap();
        pools
            .write()
            .execute_unprepared(
                "UPDATE sandbox SET network_slot = 1 WHERE id = 65700;
                 UPDATE sandbox SET network_slot = 3 WHERE id = 65701;",
            )
            .await
            .unwrap();

        assert_eq!(NetworkSlot::lease(&backend, 65_702).await.unwrap().get(), 2);
    }

    #[tokio::test]
    async fn high_ids_get_distinct_persisted_slots() {
        let temp = tempdir().unwrap();
        let backend = LocalBackend::builder()
            .home(temp.path().join("msb-home"))
            .build()
            .await
            .unwrap();

        insert_sandbox_rows_with_ids(&backend, &[65_700]).await;
        let first = NetworkSlot::lease(&backend, 65_700).await.unwrap();
        insert_sandbox_rows_with_ids(&backend, &[65_701]).await;
        let second = NetworkSlot::lease(&backend, 65_701).await.unwrap();

        assert_ne!(first, second);

        let pools = backend.db().await.unwrap();
        let held: Vec<Option<u16>> = sandbox_entity::Entity::find()
            .select_only()
            .column(sandbox_entity::Column::NetworkSlot)
            .into_tuple()
            .all(pools.read())
            .await
            .unwrap();
        assert!(held.contains(&Some(first.get())));
        assert!(held.contains(&Some(second.get())));
    }

    #[tokio::test]
    async fn repeated_lease_keeps_the_existing_slot() {
        let temp = tempdir().unwrap();
        let backend = LocalBackend::builder()
            .home(temp.path().join("msb-home"))
            .build()
            .await
            .unwrap();

        insert_sandbox_rows_with_ids(&backend, &[65_700]).await;
        let pools = backend.db().await.unwrap();
        pools
            .write()
            .execute_unprepared("UPDATE sandbox SET network_slot = 3 WHERE id = 65700;")
            .await
            .unwrap();

        assert_eq!(NetworkSlot::lease(&backend, 65_700).await.unwrap().get(), 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_allocations_use_distinct_slots() {
        const COUNT: usize = 8;

        let temp = tempdir().unwrap();
        let home = temp.path().join("msb-home");
        let mut backends = Vec::with_capacity(COUNT);
        for _ in 0..COUNT {
            let backend = LocalBackend::builder().home(&home).build().await.unwrap();
            backend.db().await.unwrap();
            backends.push(backend);
        }
        let ids: Vec<i32> = (0..COUNT).map(|offset| 65_700 + offset as i32).collect();
        insert_sandbox_rows_with_ids(&backends[0], &ids).await;

        let barrier = Arc::new(Barrier::new(COUNT));
        let leases = backends.iter().zip(&ids).map(|(backend, sandbox_id)| {
            let barrier = Arc::clone(&barrier);
            async move {
                barrier.wait().await;
                NetworkSlot::lease(backend, *sandbox_id)
                    .await
                    .unwrap()
                    .get()
            }
        });
        let mut slots = join_all(leases).await;
        slots.sort_unstable();

        assert_eq!(slots, (1..=COUNT as u16).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn does_not_lease_after_start_is_stopped() {
        let temp = tempdir().unwrap();
        let backend = LocalBackend::builder()
            .home(temp.path().join("msb-home"))
            .build()
            .await
            .unwrap();
        insert_sandbox_rows_with_ids(&backend, &[65_700]).await;
        assert_eq!(NetworkSlot::lease(&backend, 65_700).await.unwrap().get(), 1);

        let pools = backend.db().await.unwrap();
        sandbox_entity::Entity::update_many()
            .col_expr(
                sandbox_entity::Column::Status,
                sea_orm::sea_query::Expr::value(sandbox_entity::SandboxStatus::Stopped),
            )
            .filter(sandbox_entity::Column::Id.eq(65_700))
            .exec(pools.write())
            .await
            .unwrap();

        let err = NetworkSlot::lease(&backend, 65_700)
            .await
            .expect_err("a stopped start attempt must not acquire a lease");
        assert!(
            err.to_string()
                .contains("sandbox 65700 is missing or not starting")
        );
        let slot: Option<u16> = sandbox_entity::Entity::find_by_id(65_700)
            .select_only()
            .column(sandbox_entity::Column::NetworkSlot)
            .into_tuple()
            .one(pools.read())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(slot, Some(1));
    }

    #[tokio::test]
    async fn leases_while_starting_before_readiness_is_published() {
        let temp = tempdir().unwrap();
        let backend = LocalBackend::builder()
            .home(temp.path().join("msb-home"))
            .build()
            .await
            .unwrap();
        insert_sandbox_rows_with_ids(&backend, &[65_700]).await;

        let pools = backend.db().await.unwrap();
        sandbox_entity::Entity::update_many()
            .col_expr(
                sandbox_entity::Column::Status,
                sea_orm::sea_query::Expr::value(sandbox_entity::SandboxStatus::Starting),
            )
            .filter(sandbox_entity::Column::Id.eq(65_700))
            .exec(pools.write())
            .await
            .unwrap();

        assert_eq!(NetworkSlot::lease(&backend, 65_700).await.unwrap().get(), 1);
    }

    #[tokio::test]
    async fn exhaustion_reclaims_inactive_slots_and_retries() {
        let temp = tempdir().unwrap();
        let backend = LocalBackend::builder()
            .home(temp.path().join("msb-home"))
            .build()
            .await
            .unwrap();

        let pools = backend.db().await.unwrap();
        pools
            .write()
            .execute_unprepared(
                "WITH RECURSIVE slots(id) AS (\
                     SELECT 1 UNION ALL SELECT id + 1 FROM slots WHERE id < 65535\
                 )\
                 INSERT INTO sandbox (id, name, config, status, network_slot, ephemeral)\
                 SELECT id, 'stopped-slot-' || id, '{}', 'Stopped', id, 0 FROM slots;\
                 INSERT INTO sandbox (id, name, config, status, ephemeral)\
                 VALUES (65700, 'slot-test-65700', '{}', 'Running', 0);",
            )
            .await
            .unwrap();

        assert_eq!(NetworkSlot::lease(&backend, 65_700).await.unwrap().get(), 1);
        let stale_count = sandbox_entity::Entity::find()
            .filter(sandbox_entity::Column::Status.eq(sandbox_entity::SandboxStatus::Stopped))
            .filter(sandbox_entity::Column::NetworkSlot.is_not_null())
            .count(pools.read())
            .await
            .unwrap();
        assert_eq!(stale_count, 0);
    }

    #[tokio::test]
    async fn pool_exhaustion_is_a_clear_error() {
        let temp = tempdir().unwrap();
        let backend = LocalBackend::builder()
            .home(temp.path().join("msb-home"))
            .build()
            .await
            .unwrap();

        let pools = backend.db().await.unwrap();
        pools
            .write()
            .execute_unprepared(
                "WITH RECURSIVE slots(id) AS (\
                     SELECT 1 UNION ALL SELECT id + 1 FROM slots WHERE id < 65535\
                 )\
                 INSERT INTO sandbox (id, name, config, status, network_slot, ephemeral)\
                 SELECT id, 'slot-test-' || id, '{}', 'Running', id, 0 FROM slots;\
                 INSERT INTO sandbox (id, name, config, status, ephemeral)\
                 VALUES (65700, 'slot-test-65700', '{}', 'Running', 0);",
            )
            .await
            .unwrap();

        let err = NetworkSlot::lease(&backend, 65_700)
            .await
            .expect_err("pool is exhausted");
        assert!(err.to_string().contains("network slot pool exhausted"));
    }
}
