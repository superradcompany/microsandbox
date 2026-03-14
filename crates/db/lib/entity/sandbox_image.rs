//! Entity definition for the `sandbox_image` join table.
//!
//! Links sandboxes to their pinned images, enabling safe image GC
//! (images referenced by running sandboxes cannot be deleted).

use sea_orm::entity::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The sandbox-image join entity model.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "sandbox_image")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub sandbox_id: i32,
    pub image_id: i32,
    pub manifest_digest: String,
    pub created_at: Option<DateTime>,
}

//--------------------------------------------------------------------------------------------------
// Types: Relations
//--------------------------------------------------------------------------------------------------

/// Relations for the sandbox_image entity.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// Belongs to a sandbox.
    #[sea_orm(
        belongs_to = "super::sandbox::Entity",
        from = "Column::SandboxId",
        to = "super::sandbox::Column::Id"
    )]
    Sandbox,

    /// Belongs to an image.
    #[sea_orm(
        belongs_to = "super::image::Entity",
        from = "Column::ImageId",
        to = "super::image::Column::Id"
    )]
    Image,
}

impl Related<super::sandbox::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Sandbox.def()
    }
}

impl Related<super::image::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Image.def()
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl ActiveModelBehavior for ActiveModel {}
