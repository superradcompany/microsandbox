//! Entity definition for the `configs` table.

use sea_orm::entity::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The OCI image config entity model.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "config")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(unique)]
    pub manifest_id: i32,
    pub digest: String,
    pub architecture: Option<String>,
    pub os: Option<String>,
    pub os_variant: Option<String>,
    pub env: Option<String>,
    pub cmd: Option<String>,
    pub entrypoint: Option<String>,
    pub working_dir: Option<String>,
    pub volumes: Option<String>,
    pub exposed_ports: Option<String>,
    pub user: Option<String>,
    pub rootfs_type: Option<String>,
    pub rootfs_diff_ids: Option<String>,
    pub history: Option<String>,
    pub created_at: Option<DateTime>,
}

//--------------------------------------------------------------------------------------------------
// Types: Relations
//--------------------------------------------------------------------------------------------------

/// Relations for the config entity.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// A config belongs to a manifest (1:1).
    #[sea_orm(
        belongs_to = "super::manifest::Entity",
        from = "Column::ManifestId",
        to = "super::manifest::Column::Id",
        on_delete = "Cascade"
    )]
    Manifest,
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
