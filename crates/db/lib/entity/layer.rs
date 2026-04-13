//! Entity definition for the `layer` table.

use sea_orm::entity::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The OCI layer entity model.
///
/// Keyed by `diff_id` (uncompressed content hash) — the canonical identity
/// for layer deduplication across images.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "layer")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(unique)]
    pub diff_id: String,
    pub blob_digest: String,
    pub media_type: Option<String>,
    pub compressed_size_bytes: Option<i64>,
    pub erofs_size_bytes: Option<i64>,
    pub created_at: Option<DateTime>,
    pub last_used_at: Option<DateTime>,
}

//--------------------------------------------------------------------------------------------------
// Types: Relations
//--------------------------------------------------------------------------------------------------

/// Relations for the layer entity.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// A layer has many manifest_layers.
    #[sea_orm(has_many = "super::manifest_layer::Entity")]
    ManifestLayer,
}

impl Related<super::manifest_layer::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ManifestLayer.def()
    }
}

impl Related<super::manifest::Entity> for Entity {
    fn to() -> RelationDef {
        super::manifest_layer::Relation::Manifest.def()
    }

    fn via() -> Option<RelationDef> {
        Some(super::manifest_layer::Relation::Layer.def().rev())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl ActiveModelBehavior for ActiveModel {}
