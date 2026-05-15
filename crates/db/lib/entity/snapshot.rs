//! Entity definition for the `snapshot_index` table.
//!
//! This table is a local cache that mirrors snapshot artifacts on disk.
//! The artifact (`manifest.json` + upper file) is the source of truth;
//! these rows exist for fast queries and parent-edge bookkeeping.

use sea_orm::entity::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The snapshot-index entity model.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "snapshot_index")]
pub struct Model {
    /// Manifest digest (`sha256:hex`). Canonical snapshot identity.
    #[sea_orm(primary_key, auto_increment = false)]
    pub digest: String,
    /// Convenience name (unique when present). NULL for digest-only entries.
    pub name: Option<String>,
    /// Manifest digest of the parent snapshot, or NULL for a root.
    pub parent_digest: Option<String>,
    /// Human-readable image reference.
    pub image_ref: String,
    /// OCI manifest digest of the image.
    pub image_manifest_digest: String,
    /// On-disk format of the upper layer (`raw` or `qcow2`).
    pub format: String,
    /// Filesystem type inside the upper (e.g. `ext4`).
    pub fstype: String,
    /// Absolute path to the artifact directory on this host.
    pub artifact_path: String,
    /// Apparent size of the upper file in bytes.
    pub size_bytes: Option<i64>,
    /// Snapshot creation time (from manifest).
    pub created_at: DateTime,
    /// When this row was inserted/refreshed.
    pub indexed_at: DateTime,
    /// Number of indexed snapshots whose `parent_digest == self.digest`.
    pub child_count: i32,
}

//--------------------------------------------------------------------------------------------------
// Types: Relations
//--------------------------------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl ActiveModelBehavior for ActiveModel {}
