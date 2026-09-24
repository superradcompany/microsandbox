//! Derive macros for presence-aware microsandbox configuration patches.

use proc_macro::TokenStream;
use syn::{DeriveInput, parse_macro_input};

mod config_patch;

//--------------------------------------------------------------------------------------------------
// Macros
//--------------------------------------------------------------------------------------------------

/// Generate a sparse typed patch alongside a named configuration struct.
///
/// The patch is named `TypePatch` for a target named `Type`, which must implement `Default`.
/// Fields marked `#[config_patch(nested)]` recursively use the patch generated for their type,
/// including optional nested structs. Updating an absent optional nested value starts from its
/// default. Fields marked `#[config_patch(merge)]` use [`std::iter::Extend`] semantics, while
/// `#[config_patch(merge_with = path)]` delegates to a function taking `(&mut T, T)`. Merge fields
/// also expose `replace_*` methods. Every field exposes `clear_*`, which removes that pending change
/// from the patch without changing the target. Other fields are atomic: absence leaves the target
/// unchanged and presence replaces the field, including vectors and maps.
///
/// Opt into JSON input and output with `#[config_patch(serde)]`. Generated patches derive
/// `Serialize` and `Deserialize`, omit absent fields, and ignore unknown input fields.
/// Atomic values retain their own deserialization and validation rules.
/// Atomic optional fields preserve missing/null/value via
/// `Option<Option<T>>`; `serde(with)`, `rename`, and `alias` are carried over from the value.
/// Optional nested structs must remain atomic in serde patches. Maps marked `merge` merge by
/// key and replace each supplied entry. Combine `nested, merge` on a `HashMap` or `BTreeMap`
/// to overlay generated patches for each entry instead. Tagged enum values are atomic.
/// Collection replacement flags are in-memory instructions; JSON contains only their values.
/// `#[config_patch(nullable)]` enables explicit clears for an atomic optional field without
/// enabling deserialization. Its `set_*` method accepts `Option<T>`; existing setters and
/// `clear_*` retain their meanings. Merge fields expose a borrowing `get_*` method; other fields are accessed directly.
///
/// Every fluent setter, replacement, clear, and `overlay` method also has a
/// `_mut` counterpart taking `&mut self` and returning `&mut Self`. Fluent methods delegate
/// to these mutable implementations, so both APIs use the same merge behavior.
///
/// Non-merge fields preserve their original visibility and can be updated directly, including
/// nested patches and optional values. All per-field methods inherit the source field's visibility.
/// Merge/replacement storage stays private. Standard collection
/// fields marked `merge` or `merge_with` expose `get_<field>_mut()` to borrow their pending values
/// directly. These accessors initialize absent collections empty in merge mode, retain existing
/// replacement mode, and do not run the merge strategy while the collection is being edited.
///
/// Patches provide `into_config()` to build the target from its defaults.
/// Compose the patches with `overlay` first, then call `into_config()` to apply the result to
/// the target's defaults. This does not perform validation. Use `apply_to` to update an existing
/// config instead.
///
/// ```
/// use microsandbox_types_macros::ConfigPatch;
/// #[derive(Debug, Clone, Default, ConfigPatch)]
/// struct Config {
///     cpus: u8,
///     #[config_patch(nullable)]
///     workdir: Option<String>,
/// }
/// let config = ConfigPatch::new()
///     .workdir("/workspace".into())
///     .overlay(ConfigPatch::new().cpus(4))
///     .into_config();
/// assert_eq!(config.cpus, 4);
/// assert_eq!(config.workdir.as_deref(), Some("/workspace"));
/// ```
///
/// ```compile_fail
/// use microsandbox_types_macros::ConfigPatch;
/// #[derive(Debug, Clone, ConfigPatch)]
/// struct Config {
///     value: u8,
/// }
/// ConfigPatch::new().into_config();
/// ```
///
/// ```compile_fail
/// mod model {
///     use microsandbox_types_macros::ConfigPatch;
///     #[derive(Debug, Clone, Default, ConfigPatch)]
///     pub struct Config {
///         internal: u8,
///     }
/// }
/// model::ConfigPatch::new().internal(1);
/// ```
///
/// ```compile_fail
/// mod model {
///     use microsandbox_types_macros::ConfigPatch;
///     #[derive(Debug, Clone, Default, ConfigPatch)]
///     pub struct Config {
///         #[config_patch(merge)]
///         values: Vec<u8>,
///     }
/// }
/// model::ConfigPatch::new().get_values_mut().push(1);
/// ```
#[proc_macro_derive(ConfigPatch, attributes(config_patch))]
pub fn derive_config_patch(input: TokenStream) -> TokenStream {
    config_patch::expand_config_patch(parse_macro_input!(input as DeriveInput))
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
