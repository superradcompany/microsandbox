//! Proc-macro implementation for the `#[msb_test]` attribute.
//!
//! Don't depend on this crate directly — depend on `test-utils`, which
//! re-exports the macro and provides the runtime helpers it expands into.

use proc_macro::TokenStream;
use quote::quote;
use syn::{ItemFn, parse_macro_input};

/// Marks an `async fn` as a microsandbox integration test.
///
/// Expands to:
///
/// ```ignore
/// #[::tokio::test]
/// #[ignore]
/// async fn <name>(<args>) -> <ret> {
///     let _msb_test_home = ::test_utils::init_isolated_home();
///     <body>
/// }
/// ```
///
/// The `#[ignore]` is automatic because every microsandbox integration test
/// requires KVM (or libkrun on macOS) and must be opted into explicitly via
/// `--run-ignored=only`.
///
/// `init_isolated_home` is a no-op unless `MSB_TEST_ISOLATE_HOME` is set, so
/// local `cargo test` runs against the real `~/.microsandbox`.
#[proc_macro_attribute]
pub fn msb_test(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut input = parse_macro_input!(item as ItemFn);

    if input.sig.asyncness.is_none() {
        return syn::Error::new_spanned(input.sig.fn_token, "#[msb_test] requires an async fn")
            .to_compile_error()
            .into();
    }

    let original_block = input.block;
    let new_block: syn::Block = syn::parse_quote!({
        let _msb_test_home = ::test_utils::init_isolated_home();
        #original_block
    });
    input.block = Box::new(new_block);

    let expanded = quote! {
        #[::tokio::test]
        #[ignore]
        #input
    };

    expanded.into()
}
