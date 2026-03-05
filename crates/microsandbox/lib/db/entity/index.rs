//! Entity definition for the `indexes` table.

use sea_orm::entity::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The OCI index entity model.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "index")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub image_id: i32,
    pub schema_version: Option<i32>,
    pub media_type: Option<String>,
    pub platform_os: Option<String>,
    pub platform_arch: Option<String>,
    pub platform_variant: Option<String>,
    pub annotations: Option<String>,
    pub created_at: Option<DateTime>,
}

//--------------------------------------------------------------------------------------------------
// Types: Relations
//--------------------------------------------------------------------------------------------------

/// Relations for the index entity.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// An index belongs to an image.
    #[sea_orm(
        belongs_to = "super::image::Entity",
        from = "Column::ImageId",
        to = "super::image::Column::Id",
        on_delete = "Cascade"
    )]
    Image,

    /// An index has many manifests.
    #[sea_orm(has_many = "super::manifest::Entity")]
    Manifest,
}

impl Related<super::image::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Image.def()
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
