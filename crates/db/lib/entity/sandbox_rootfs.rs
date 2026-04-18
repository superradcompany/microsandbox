//! Entity definition for the `sandbox_rootfs` table.
//!
//! Pins each sandbox to a manifest digest and runtime mode.

use sea_orm::entity::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The sandbox rootfs entity model.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "sandbox_rootfs")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(unique)]
    pub sandbox_id: i32,
    pub manifest_id: Option<i32>,
    pub mode: String,
    pub upper_fstype: Option<String>,
    pub created_at: Option<DateTime>,
}

/// Rootfs source mode stored in the `sandbox_rootfs.mode` column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxRootfsMode {
    /// EROFS fsmerge + VMDK (always 2 block devices).
    Erofs,
    /// Host directory bind mount.
    Bind,
    /// Pre-existing disk image (qcow2/raw/vmdk).
    DiskImage,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SandboxRootfsMode {
    /// Database string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Erofs => "erofs",
            Self::Bind => "bind",
            Self::DiskImage => "disk_image",
        }
    }

    /// Parse from database string.
    pub fn parse_str(s: &str) -> Option<Self> {
        match s {
            "erofs" => Some(Self::Erofs),
            "bind" => Some(Self::Bind),
            "disk_image" => Some(Self::DiskImage),
            _ => None,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Types: Relations
//--------------------------------------------------------------------------------------------------

/// Relations for the sandbox_rootfs entity.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// Belongs to a sandbox (1:1).
    #[sea_orm(
        belongs_to = "super::sandbox::Entity",
        from = "Column::SandboxId",
        to = "super::sandbox::Column::Id",
        on_delete = "Cascade"
    )]
    Sandbox,

    /// References a manifest (nullable for bind/disk-image).
    #[sea_orm(
        belongs_to = "super::manifest::Entity",
        from = "Column::ManifestId",
        to = "super::manifest::Column::Id",
        on_delete = "Restrict"
    )]
    Manifest,
}

impl Related<super::sandbox::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Sandbox.def()
    }
}

impl Related<super::manifest::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Manifest.def()
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl ActiveModelBehavior for ActiveModel {}
