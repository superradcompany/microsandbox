//! Derive macros for presence-aware microsandbox configuration patches.

use proc_macro::TokenStream;
use syn::{DeriveInput, parse_macro_input};

mod config_patch;

//--------------------------------------------------------------------------------------------------
// Macros
//--------------------------------------------------------------------------------------------------

/// Generate a sparse typed patch alongside a named configuration struct.
///
/// Use `#[config_patch(name = CustomPatch)]` on the struct to override the generated patch name.
/// Fields marked `#[config_patch(nested)]` recursively use the patch generated for their type,
/// including optional nested structs. Updating an absent optional nested value starts from its
/// default. Fields marked `#[config_patch(merge)]` use [`std::iter::Extend`] semantics, while
/// `#[config_patch(merge_with = path)]` delegates to a function taking `(&mut T, T)`. Merge fields
/// also expose `replace_*` methods. Every field exposes `clear_*`, which removes that pending change
/// from the patch without changing the target. Other fields are atomic: absence leaves the target
/// unchanged and presence replaces the field, including vectors and maps.
#[proc_macro_derive(ConfigPatch, attributes(config_patch))]
pub fn derive_config_patch(input: TokenStream) -> TokenStream {
    config_patch::expand_config_patch(parse_macro_input!(input as DeriveInput))
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
