//! Entity definition for the `flat_rootfs` table.
//!
//! Tracks flat-mode EROFS images (single merged image per manifest).

use sea_orm::entity::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The flat rootfs entity model.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "flat_rootfs")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub manifest_id: i32,
    pub state: String,
    pub size_bytes: Option<i64>,
    pub pinned: bool,
    pub last_used_at: Option<DateTime>,
    pub created_at: Option<DateTime>,
}

//--------------------------------------------------------------------------------------------------
// Types: Relations
//--------------------------------------------------------------------------------------------------

/// Relations for the flat_rootfs entity.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// A flat rootfs belongs to a manifest.
    #[sea_orm(
        belongs_to = "super::manifest::Entity",
        from = "Column::ManifestId",
        to = "super::manifest::Column::Id",
        on_delete = "Cascade"
    )]
    Manifest,

    /// A flat rootfs may be referenced by sandbox_rootfs entries.
    #[sea_orm(has_many = "super::sandbox_rootfs::Entity")]
    SandboxRootfs,
}

impl Related<super::manifest::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Manifest.def()
    }
}

impl Related<super::sandbox_rootfs::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::SandboxRootfs.def()
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl ActiveModelBehavior for ActiveModel {}
