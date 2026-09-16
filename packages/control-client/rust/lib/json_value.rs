//! Lossless JSON inspection without changing serde_json's global number policy.

use std::collections::BTreeMap;
use std::fmt;

use serde::Deserializer;
use serde::de::{MapAccess, Visitor};
use serde_json::value::RawValue;
use zeroize::Zeroize;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// An original JSON number token, including its integer precision and spelling.
#[derive(Clone, PartialEq, Eq)]
pub struct JsonNumber(String);

/// Inspectable JSON that preserves number tokens and rejects duplicate keys.
#[derive(Clone, PartialEq, Eq)]
pub enum JsonValue {
    /// JSON null.
    Null,
    /// JSON boolean.
    Bool(bool),
    /// Original, validated numeric token; no float conversion has occurred.
    Number(JsonNumber),
    /// Decoded Unicode text.
    String(String),
    /// Ordered array entries.
    Array(Vec<JsonValue>),
    /// Unique object keys. Original ordering and escapes remain in reply bytes.
    Object(BTreeMap<String, JsonValue>),
}

struct ObjectVisitor {
    depth: usize,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl JsonNumber {
    /// Original token, without rounding or reformatting.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Read an unsigned integer token. Fractions and exponents are not integers
    /// in the control wire contract, even when mathematically integral.
    pub fn as_u64(&self) -> Option<u64> {
        if self.0.starts_with('-') {
            return None;
        }
        self.0.parse().ok()
    }
}

impl JsonValue {
    /// Decode exactly one JSON value, preserving unknown full-width numbers.
    /// Errors contain no payload excerpts or decoded values.
    pub fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        let raw: &RawValue = serde_json::from_slice(bytes).map_err(|_| "invalid JSON")?;
        parse_value(raw.get(), 0).map_err(|_| "invalid JSON")
    }

    /// Look up one object field without converting its numeric values.
    pub fn get(&self, name: &str) -> Option<&Self> {
        self.as_object()?.get(name)
    }

    /// Borrow object fields.
    pub fn as_object(&self) -> Option<&BTreeMap<String, Self>> {
        match self {
            Self::Object(fields) => Some(fields),
            _ => None,
        }
    }

    /// Borrow ordered array entries.
    pub fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(values) => Some(values),
            _ => None,
        }
    }

    /// Borrow decoded text.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    /// Read a boolean without coercion.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }

    /// Read a u64 integer token without a floating-point intermediate.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Number(value) => value.as_u64(),
            _ => None,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<'de> Visitor<'de> for ObjectVisitor {
    type Value = JsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON object")
    }

    fn visit_map<M: MapAccess<'de>>(self, mut access: M) -> Result<Self::Value, M::Error> {
        let mut fields = BTreeMap::new();
        while let Some(name) = access.next_key::<String>()? {
            // Checking before insertion also rejects differently escaped keys
            // that decode to the same name, including unknown extension fields.
            if fields.contains_key(&name) {
                return Err(serde::de::Error::custom("duplicate JSON field"));
            }
            let raw: &'de RawValue = access.next_value()?;
            let value = parse_value(raw.get(), self.depth + 1)
                .map_err(|_| serde::de::Error::custom("invalid JSON field"))?;
            fields.insert(name, value);
        }
        Ok(JsonValue::Object(fields))
    }
}

impl fmt::Debug for JsonValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // JSON replies may contain arbitrary peer extensions. Inspection is
        // explicit; routine error logging must not expose their contents.
        formatter.write_str("JsonValue { .. }")
    }
}

impl fmt::Debug for JsonNumber {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JsonNumber { .. }")
    }
}

impl Drop for JsonValue {
    fn drop(&mut self) {
        match self {
            Self::String(text) => text.zeroize(),
            Self::Number(number) => number.0.zeroize(),
            _ => {} // Nested values run this same drop when their owner drops.
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn parse_value(raw: &str, depth: usize) -> Result<JsonValue, serde_json::Error> {
    if depth > 128 {
        return Err(<serde_json::Error as serde::de::Error>::custom(
            "JSON nesting limit",
        ));
    }
    Ok(match raw.as_bytes().first() {
        Some(b'{') => {
            let mut decoder = serde_json::Deserializer::from_str(raw);
            let value = decoder.deserialize_map(ObjectVisitor { depth })?;
            decoder.end()?;
            value
        }
        Some(b'[') => {
            let entries: Vec<&RawValue> = serde_json::from_str(raw)?;
            JsonValue::Array(
                entries
                    .iter()
                    .map(|entry| parse_value(entry.get(), depth + 1))
                    .collect::<Result<_, _>>()?,
            )
        }
        Some(b'"') => JsonValue::String(serde_json::from_str(raw)?),
        Some(b't' | b'f') => JsonValue::Bool(serde_json::from_str(raw)?),
        Some(b'n') => JsonValue::Null,
        _ => JsonValue::Number(JsonNumber(raw.to_owned())),
    })
}
