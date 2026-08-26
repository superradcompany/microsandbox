//! Bounded network-slot leases for active local sandbox runs.

use std::num::NonZeroU16;

use microsandbox_db::entity::sandbox::{self as sandbox_entity, Column};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseTransaction, EntityTrait, QueryFilter, Statement,
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

    /// Lease a slot to the current startup attempt.
    ///
    /// The assignment is kept only for the active run. Terminal lifecycle
    /// transitions clear the database column, so a restart may receive a
    /// different address. SQLite serializes the read-decide-write transaction,
    /// while the partial unique index provides a final collision guard.
    pub(super) async fn lease(local: &LocalBackend, sandbox_id: i32) -> MicrosandboxResult<Self> {
        let pools = local.db().await?;
        let db = pools.write();

        db.transaction(|txn| async move {
            let slot = Self::next_available_slot(&txn).await?;
            Self::claim_slot(&txn, sandbox_id, slot).await?;
            Ok((txn, slot))
        })
        .await
    }

    /// Claim the slot only while the sandbox status is `Running`.
    async fn claim_slot(
        db: &DatabaseTransaction,
        sandbox_id: i32,
        slot: Self,
    ) -> MicrosandboxResult<()> {
        // Do not resurrect a lease if a concurrent stop won before this
        // transaction acquired the writer.
        let update = sandbox_entity::Entity::update_many()
            .col_expr(Column::NetworkSlot, Expr::value(Some(slot.get())))
            .filter(Column::Id.eq(sandbox_id))
            .filter(Column::Status.eq(sandbox_entity::SandboxStatus::Running))
            .exec(db)
            .await?;

        if update.rows_affected != 1 {
            return Err(MicrosandboxError::Runtime(format!(
                "sandbox {sandbox_id} stopped while leasing network slot"
            )));
        }

        Ok(())
    }

    /// Ask SQLite for the lowest free slot in the active leases.
    ///
    /// The lowest free slot is either 1 or the successor of an occupied slot.
    /// The partial unique index covers the candidate scan and occupancy lookup;
    /// only the selected scalar crosses into Rust.
    async fn next_available_slot(db: &DatabaseTransaction) -> MicrosandboxResult<Self> {
        const QUERY: &str = "
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
        ";

        let values = [u16::MAX.into()];
        let conn = db.get_database_backend();
        let slot = db
            .query_one_raw(Statement::from_sql_and_values(conn, QUERY, values))
            .await?
            .ok_or_else(|| MicrosandboxError::Runtime("network slot query returned no row".into()))?
            .try_get_by_index::<Option<u16>>(0)?
            .ok_or_else(|| MicrosandboxError::Runtime("network slot pool exhausted".into()))?;

        Self::try_from(slot)
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
    use sea_orm::{ConnectionTrait, EntityTrait, QuerySelect, Set};
    use tempfile::tempdir;

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

        insert_sandbox_rows_with_ids(&backend, &[1, 2]).await;
        assert_eq!(NetworkSlot::lease(&backend, 1).await.unwrap().get(), 1);
        assert_eq!(NetworkSlot::lease(&backend, 2).await.unwrap().get(), 2);
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
    async fn concurrent_allocations_use_distinct_slots() {
        let temp = tempdir().unwrap();
        let home = temp.path().join("msb-home");
        let first_backend = LocalBackend::builder().home(&home).build().await.unwrap();
        let second_backend = LocalBackend::builder().home(&home).build().await.unwrap();

        insert_sandbox_rows_with_ids(&first_backend, &[65_700, 65_701]).await;
        let (first, second) = tokio::join!(
            NetworkSlot::lease(&first_backend, 65_700),
            NetworkSlot::lease(&second_backend, 65_701),
        );

        let first = first.unwrap().get();
        let second = second.unwrap().get();
        assert_ne!(first, second);
        assert_eq!([first, second].into_iter().min(), Some(1));
        assert_eq!([first, second].into_iter().max(), Some(2));
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
                .contains("stopped while leasing network slot")
        );
        let slot: Option<u16> = sandbox_entity::Entity::find_by_id(65_700)
            .select_only()
            .column(sandbox_entity::Column::NetworkSlot)
            .into_tuple()
            .one(pools.read())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(slot, None);
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
