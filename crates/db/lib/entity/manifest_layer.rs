//! Entity definition for the `manifest_layer` junction table.

use sea_orm::entity::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The manifest-layer junction entity model.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "manifest_layer")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub manifest_id: i32,
    pub layer_id: i32,
    pub position: i32,
}

//--------------------------------------------------------------------------------------------------
// Types: Relations
//--------------------------------------------------------------------------------------------------

/// Relations for the manifest_layer entity.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// A manifest_layer belongs to a manifest.
    #[sea_orm(
        belongs_to = "super::manifest::Entity",
        from = "Column::ManifestId",
        to = "super::manifest::Column::Id",
        on_delete = "Cascade"
    )]
    Manifest,

    /// A manifest_layer belongs to a layer.
    #[sea_orm(
        belongs_to = "super::layer::Entity",
        from = "Column::LayerId",
        to = "super::layer::Column::Id",
        on_delete = "Restrict"
    )]
    Layer,
}

impl Related<super::manifest::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Manifest.def()
    }
}

impl Related<super::layer::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Layer.def()
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl ActiveModelBehavior for ActiveModel {}
