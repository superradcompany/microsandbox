//! Entity definition for the `manifests` table.

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
    pub image_id: i32,
    pub index_id: Option<i32>,
    #[sea_orm(unique)]
    pub digest: String,
    pub schema_version: Option<i32>,
    pub media_type: Option<String>,
    pub annotations: Option<String>,
    pub created_at: Option<DateTime>,
}

//--------------------------------------------------------------------------------------------------
// Types: Relations
//--------------------------------------------------------------------------------------------------

/// Relations for the manifest entity.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// A manifest belongs to an image.
    #[sea_orm(
        belongs_to = "super::image::Entity",
        from = "Column::ImageId",
        to = "super::image::Column::Id",
        on_delete = "Cascade"
    )]
    Image,

    /// A manifest optionally belongs to an index.
    #[sea_orm(
        belongs_to = "super::index::Entity",
        from = "Column::IndexId",
        to = "super::index::Column::Id",
        on_delete = "SetNull"
    )]
    Index,

    /// A manifest has one config.
    #[sea_orm(has_one = "super::config::Entity")]
    Config,

    /// A manifest has many manifest_layers.
    #[sea_orm(has_many = "super::manifest_layer::Entity")]
    ManifestLayer,
}

impl Related<super::image::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Image.def()
    }
}

impl Related<super::index::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Index.def()
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
