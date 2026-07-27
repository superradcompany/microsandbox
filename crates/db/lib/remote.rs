//! Remote database backend — delegates to the `microsandbox-libsql` crate.
//!
//! This module builds the column-kind map from this crate's entities and
//! passes it to `microsandbox_libsql`'s `open_read`/`open_write`, keeping
//! the entity coupling in `microsandbox-db` where it belongs.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use sea_orm::sea_query::ColumnType;
use sea_orm::{ColumnTrait, DbErr, EntityTrait, IdenStatic, Iterable};

use crate::entity;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub(crate) use microsandbox_libsql::ColumnKind;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Open a read-side proxy connection.
pub(crate) async fn open_read(
    url: &str,
    max_connections: u32,
    acquire_timeout: Duration,
    request_timeout: Duration,
) -> Result<sea_orm::DatabaseConnection, DbErr> {
    microsandbox_libsql::open_read(
        url,
        max_connections,
        acquire_timeout,
        request_timeout,
        entity_column_kinds(),
    )
    .await
}

/// Open the write-side proxy connection (single server connection).
pub(crate) async fn open_write(
    url: &str,
    acquire_timeout: Duration,
    request_timeout: Duration,
) -> Result<sea_orm::DatabaseConnection, DbErr> {
    microsandbox_libsql::open_write(url, acquire_timeout, request_timeout, entity_column_kinds())
        .await
}

/// Build the column-kind map from every entity in this crate.
fn entity_column_kinds() -> Arc<HashMap<String, ColumnKind>> {
    let mut kinds: HashMap<String, ColumnKind> = HashMap::new();
    for (name, kind) in all_entity_kinds() {
        if let Some(previous) = kinds.insert(name.clone(), kind)
            && previous != kind
        {
            tracing::warn!(
                column = name.as_str(),
                "ambiguous column kind across tables"
            );
            kinds.insert(name, previous);
        }
    }
    Arc::new(kinds)
}

/// Every (column name, kind) pair across the database schema.
fn all_entity_kinds() -> Vec<(String, ColumnKind)> {
    let mut all = Vec::new();
    collect::<entity::config::Entity>(&mut all);
    collect::<entity::image_ref::Entity>(&mut all);
    collect::<entity::layer::Entity>(&mut all);
    collect::<entity::maintenance_lease::Entity>(&mut all);
    collect::<entity::manifest::Entity>(&mut all);
    collect::<entity::manifest_layer::Entity>(&mut all);
    collect::<entity::run::Entity>(&mut all);
    collect::<entity::sandbox::Entity>(&mut all);
    collect::<entity::sandbox_label::Entity>(&mut all);
    collect::<entity::sandbox_rootfs::Entity>(&mut all);
    collect::<entity::snapshot::Entity>(&mut all);
    collect::<entity::volume::Entity>(&mut all);
    all
}

/// Record every column of `E` with its conversion kind.
fn collect<E: EntityTrait>(all: &mut Vec<(String, ColumnKind)>) {
    for column in E::Column::iter() {
        let name = column.as_str().to_owned();
        let kind = kind_of(column.def().get_column_type());
        all.push((name, kind));
    }
}

/// Map a schema column type onto the conversion kind.
fn kind_of(column_type: &ColumnType) -> ColumnKind {
    match column_type {
        ColumnType::TinyInteger | ColumnType::SmallInteger | ColumnType::Integer => ColumnKind::I32,
        ColumnType::BigInteger => ColumnKind::I64,
        ColumnType::Float | ColumnType::Double | ColumnType::Decimal(_) => ColumnKind::F64,
        ColumnType::Boolean => ColumnKind::Bool,
        ColumnType::DateTime | ColumnType::Timestamp | ColumnType::TimestampWithTimeZone => {
            ColumnKind::DateTime
        }
        ColumnType::Binary(_) | ColumnType::VarBinary(_) | ColumnType::Blob => ColumnKind::Blob,
        _ => ColumnKind::Text,
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn column_kinds_are_unambiguous() {
        let mut seen: HashMap<String, ColumnKind> = HashMap::new();
        let mut conflicts = Vec::new();

        for (name, kind) in all_entity_kinds() {
            if let Some(previous) = seen.insert(name.clone(), kind)
                && previous != kind
            {
                conflicts.push(name);
            }
        }

        assert!(conflicts.is_empty(), "ambiguous columns: {conflicts:?}");
    }

    #[test]
    fn timestamp_columns_resolve_to_datetime() {
        let kinds = entity_column_kinds();
        use microsandbox_libsql::ColumnKind;
        assert_eq!(kinds.get("created_at").copied(), Some(ColumnKind::DateTime));
        assert_eq!(kinds.get("updated_at").copied(), Some(ColumnKind::DateTime));
    }
}
