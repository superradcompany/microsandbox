//! Value conversion between sea-orm statements and the libSQL wire protocol.

use std::collections::HashMap;

use chrono::NaiveDateTime;
use sea_orm::DbErr;
use sea_orm::sea_query::Value;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Timestamp format sqlx-sqlite writes for `NaiveDateTime` binds.
pub(crate) const DATETIME_FORMAT: &str = "%Y-%m-%d %H:%M:%S%.f";

/// Lenient fallback for ISO-8601 timestamps with a `T` separator.
pub(crate) const DATETIME_FORMAT_T: &str = "%Y-%m-%dT%H:%M:%S%.f";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The Rust-side shape a database column converts to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnKind {
    /// 32-bit integer columns (`i32` model fields).
    I32,
    /// 64-bit integer columns (`i64` model fields).
    I64,
    /// Floating-point columns.
    F64,
    /// Boolean columns (stored as SQLite integers).
    Bool,
    /// Text columns, including string-backed enums.
    Text,
    /// Binary blob columns.
    Blob,
    /// Naive datetime columns (stored as SQLite text).
    DateTime,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Look up the kind for a result column from the injected map, tolerating
/// sea-orm's `A_`/`B_` relation-query prefixes.
pub(crate) fn kind_for_column(
    name: &str,
    kinds: &HashMap<String, ColumnKind>,
) -> Option<ColumnKind> {
    // sea-orm's paginator decodes its COUNT alias as i32 on SQLite.
    if name == "num_items" {
        return Some(ColumnKind::I32);
    }

    if let Some(kind) = kinds.get(name) {
        return Some(*kind);
    }

    let stripped = name
        .strip_prefix("A_")
        .or_else(|| name.strip_prefix("B_"))?;
    kinds.get(stripped).copied()
}

/// Convert one sea-orm bind value into a libsql parameter.
pub(crate) fn to_libsql_value(value: &Value) -> Result<libsql::Value, DbErr> {
    use libsql::Value as Lv;

    let converted = match value {
        Value::Bool(v) => v.map_or(Lv::Null, |b| Lv::Integer(b.into())),
        Value::TinyInt(v) => v.map_or(Lv::Null, |i| Lv::Integer(i.into())),
        Value::SmallInt(v) => v.map_or(Lv::Null, |i| Lv::Integer(i.into())),
        Value::Int(v) => v.map_or(Lv::Null, |i| Lv::Integer(i.into())),
        Value::BigInt(v) => v.map_or(Lv::Null, Lv::Integer),
        Value::TinyUnsigned(v) => v.map_or(Lv::Null, |i| Lv::Integer(i.into())),
        Value::SmallUnsigned(v) => v.map_or(Lv::Null, |i| Lv::Integer(i.into())),
        Value::Unsigned(v) => v.map_or(Lv::Null, |i| Lv::Integer(i.into())),
        Value::BigUnsigned(Some(v)) => {
            let signed = i64::try_from(*v)
                .map_err(|_| DbErr::Custom(format!("u64 bind {v} exceeds SQLite integer range")))?;
            Lv::Integer(signed)
        }
        Value::BigUnsigned(None) => Lv::Null,
        Value::Float(v) => v.map_or(Lv::Null, |f| Lv::Real(f.into())),
        Value::Double(v) => v.map_or(Lv::Null, Lv::Real),
        Value::String(v) => v
            .as_ref()
            .map_or(Lv::Null, |s| Lv::Text(s.as_str().to_owned())),
        Value::Char(v) => v.map_or(Lv::Null, |c| Lv::Text(c.to_string())),
        Value::Bytes(v) => v.as_ref().map_or(Lv::Null, |b| Lv::Blob(b.to_vec())),
        Value::ChronoDate(v) => v
            .as_deref()
            .map_or(Lv::Null, |d| Lv::Text(d.format("%Y-%m-%d").to_string())),
        Value::ChronoTime(v) => v
            .as_deref()
            .map_or(Lv::Null, |t| Lv::Text(t.format("%H:%M:%S%.f").to_string())),
        Value::ChronoDateTime(v) => v.as_deref().map_or(Lv::Null, |dt| {
            Lv::Text(dt.format(DATETIME_FORMAT).to_string())
        }),
        Value::ChronoDateTimeUtc(v) => v.as_ref().map_or(Lv::Null, |dt| {
            Lv::Text(dt.naive_utc().format(DATETIME_FORMAT).to_string())
        }),
        Value::ChronoDateTimeLocal(v) => v.as_ref().map_or(Lv::Null, |dt| {
            Lv::Text(dt.naive_utc().format(DATETIME_FORMAT).to_string())
        }),
        Value::ChronoDateTimeWithTimeZone(v) => v.as_ref().map_or(Lv::Null, |dt| {
            Lv::Text(dt.naive_utc().format(DATETIME_FORMAT).to_string())
        }),
        #[allow(unreachable_patterns)]
        other => {
            return Err(DbErr::Custom(format!(
                "unsupported bind type for the libSQL backend: {other:?}"
            )));
        }
    };

    Ok(converted)
}

/// Convert one result cell into the `sea_query::Value` variant the entity
/// model expects for that column.
pub(crate) fn to_sea_value(
    name: &str,
    value: libsql::Value,
    kinds: &HashMap<String, ColumnKind>,
) -> Value {
    use libsql::Value as Lv;

    let kind = kind_for_column(name, kinds);

    match (kind, value) {
        (kind, Lv::Null) => null_value(kind),
        (Some(ColumnKind::I32), Lv::Integer(i)) => match i32::try_from(i) {
            Ok(v) => Value::Int(Some(v)),
            Err(_) => Value::BigInt(Some(i)),
        },
        (Some(ColumnKind::I64), Lv::Integer(i)) => Value::BigInt(Some(i)),
        (Some(ColumnKind::Bool), Lv::Integer(i)) => Value::Bool(Some(i != 0)),
        (Some(ColumnKind::F64), Lv::Integer(i)) => Value::Double(Some(i as f64)),
        (Some(ColumnKind::F64), Lv::Real(f)) => Value::Double(Some(f)),
        (Some(ColumnKind::Text), Lv::Text(s)) => Value::String(Some(Box::new(s))),
        (Some(ColumnKind::DateTime), Lv::Text(s)) => parse_datetime(name, s),
        (Some(ColumnKind::Blob), Lv::Blob(b)) => Value::Bytes(Some(Box::new(b))),
        (_, Lv::Integer(i)) => Value::BigInt(Some(i)),
        (_, Lv::Real(f)) => Value::Double(Some(f)),
        (_, Lv::Text(s)) => Value::String(Some(Box::new(s))),
        (_, Lv::Blob(b)) => Value::Bytes(Some(Box::new(b))),
    }
}

/// The typed NULL for a column kind.
pub(crate) fn null_value(kind: Option<ColumnKind>) -> Value {
    match kind {
        Some(ColumnKind::I32) => Value::Int(None),
        Some(ColumnKind::I64) => Value::BigInt(None),
        Some(ColumnKind::F64) => Value::Double(None),
        Some(ColumnKind::Bool) => Value::Bool(None),
        Some(ColumnKind::DateTime) => Value::ChronoDateTime(None),
        Some(ColumnKind::Blob) => Value::Bytes(None),
        Some(ColumnKind::Text) | None => Value::String(None),
    }
}

/// Parse a stored timestamp back into a chrono value.
fn parse_datetime(name: &str, text: String) -> Value {
    let parsed = NaiveDateTime::parse_from_str(&text, DATETIME_FORMAT)
        .or_else(|_| NaiveDateTime::parse_from_str(&text, DATETIME_FORMAT_T));

    match parsed {
        Ok(dt) => Value::ChronoDateTime(Some(Box::new(dt))),
        Err(_) => {
            tracing::warn!(column = name, "unparseable timestamp from database server");
            Value::String(Some(Box::new(text)))
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_kinds() -> HashMap<String, ColumnKind> {
        HashMap::new()
    }

    fn kinds_with(name: &str, kind: ColumnKind) -> HashMap<String, ColumnKind> {
        let mut m = HashMap::new();
        m.insert(name.to_owned(), kind);
        m
    }

    #[test]
    fn datetime_round_trips_through_text() {
        let dt = NaiveDateTime::parse_from_str("2026-01-02 03:04:05.678", DATETIME_FORMAT).unwrap();
        let kinds = kinds_with("created_at", ColumnKind::DateTime);

        let bound = to_libsql_value(&Value::ChronoDateTime(Some(Box::new(dt)))).unwrap();
        let libsql::Value::Text(text) = bound else {
            panic!("datetime must bind as text");
        };
        let back = to_sea_value("created_at", libsql::Value::Text(text), &kinds);

        assert_eq!(back, Value::ChronoDateTime(Some(Box::new(dt))));
    }

    #[test]
    fn integer_widths_follow_schema() {
        let kinds = kinds_with("id", ColumnKind::I32);
        assert_eq!(
            to_sea_value("id", libsql::Value::Integer(7), &kinds),
            Value::Int(Some(7))
        );
    }

    #[test]
    fn null_carries_column_variant() {
        let kinds = kinds_with("created_at", ColumnKind::DateTime);
        assert_eq!(
            to_sea_value("created_at", libsql::Value::Null, &kinds),
            Value::ChronoDateTime(None)
        );
    }

    #[test]
    fn unknown_columns_fall_back_to_wire_shape() {
        let kinds = empty_kinds();
        assert_eq!(
            to_sea_value("count(*)", libsql::Value::Integer(3), &kinds),
            Value::BigInt(Some(3))
        );
    }
}
