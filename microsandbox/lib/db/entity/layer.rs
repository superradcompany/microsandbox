//! Entity definition for the `layers` table.

use sea_orm::entity::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The OCI layer entity model.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "layer")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(unique)]
    pub digest: String,
    pub diff_id: String,
    pub media_type: Option<String>,
    pub size_bytes: Option<i64>,
    pub created_at: Option<DateTime>,
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
