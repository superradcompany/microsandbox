//! Entity definition for the `manifest` table.

use sea_orm::entity::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The OCI manifest entity model.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "manifest")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(unique)]
    pub digest: String,
    pub media_type: Option<String>,
    pub config_digest: Option<String>,
    pub architecture: Option<String>,
    pub os: Option<String>,
    pub variant: Option<String>,
    pub layer_count: Option<i32>,
    pub total_size_bytes: Option<i64>,
    pub created_at: Option<DateTime>,
}

//--------------------------------------------------------------------------------------------------
// Types: Relations
//--------------------------------------------------------------------------------------------------

/// Relations for the manifest entity.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// A manifest has many image references (N:1 from image_ref side).
    #[sea_orm(has_many = "super::image_ref::Entity")]
    ImageRef,

    /// A manifest has one config.
    #[sea_orm(has_one = "super::config::Entity")]
    Config,

    /// A manifest has many manifest_layers.
    #[sea_orm(has_many = "super::manifest_layer::Entity")]
    ManifestLayer,

    /// A manifest may have a flat rootfs.
    #[sea_orm(has_many = "super::flat_rootfs::Entity")]
    FlatRootfs,

    /// A manifest may be referenced by sandbox_rootfs entries.
    #[sea_orm(has_many = "super::sandbox_rootfs::Entity")]
    SandboxRootfs,
}

impl Related<super::image_ref::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ImageRef.def()
    }
}

impl Related<super::config::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Config.def()
    }
}

impl Related<super::manifest_layer::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ManifestLayer.def()
    }
}

impl Related<super::flat_rootfs::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::FlatRootfs.def()
    }
}

impl Related<super::layer::Entity> for Entity {
    fn to() -> RelationDef {
        super::manifest_layer::Relation::Layer.def()
    }

    fn via() -> Option<RelationDef> {
        Some(super::manifest_layer::Relation::Manifest.def().rev())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl ActiveModelBehavior for ActiveModel {}
