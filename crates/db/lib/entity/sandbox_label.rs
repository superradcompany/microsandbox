//! Entity definition for the `sandbox_labels` table.

use sea_orm::entity::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A user-defined label attached to a sandbox for metrics attribution. Keyed on
/// `(sandbox_id, key)` so each key has at most one value per sandbox.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "sandbox_labels")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub sandbox_id: i32,
    #[sea_orm(primary_key, auto_increment = false)]
    pub key: String,
    pub value: String,
}

//--------------------------------------------------------------------------------------------------
// Types: Relations
//--------------------------------------------------------------------------------------------------

/// Relations for the sandbox_label entity.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// A label belongs to a sandbox.
    #[sea_orm(
        belongs_to = "super::sandbox::Entity",
        from = "Column::SandboxId",
        to = "super::sandbox::Column::Id",
        on_delete = "Cascade"
    )]
    Sandbox,
}

impl Related<super::sandbox::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Sandbox.def()
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl ActiveModelBehavior for ActiveModel {}
