//! Entity definition for the `volumes` table.

use sea_orm::entity::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The volume entity model.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "volume")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(unique)]
    pub name: String,
    pub quota_mib: Option<i32>,
    pub size_bytes: Option<i64>,
    pub labels: Option<String>,
    pub created_at: Option<DateTime>,
    pub updated_at: Option<DateTime>,
}

//--------------------------------------------------------------------------------------------------
// Types: Relations
//--------------------------------------------------------------------------------------------------

/// Relations for the volume entity.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl ActiveModelBehavior for ActiveModel {}
