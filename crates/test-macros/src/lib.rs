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
/// #[::tokio::test(<args>)]
/// #[ignore]
/// async fn <name>(<inputs>) -> <ret> {
///     let _msb_test_home = ::test_utils::init_isolated_home();
///     <body>
/// }
/// ```
///
/// Anything passed inside `#[msb_test(...)]` is forwarded verbatim to
/// `#[tokio::test(...)]`, so the full tokio-test surface is available:
///
/// ```ignore
/// #[msb_test]                                            // #[tokio::test]
/// #[msb_test(flavor = "multi_thread")]                   // #[tokio::test(flavor = "multi_thread")]
/// #[msb_test(flavor = "multi_thread", worker_threads = 4)]
/// #[msb_test(start_paused = true)]
/// ```
///
/// The `#[ignore]` is automatic because every microsandbox integration test
/// requires KVM (or libkrun on macOS) and must be opted into explicitly via
/// `--run-ignored=only`.
///
/// `init_isolated_home` is a no-op unless `MSB_TEST_ISOLATE_HOME` is set, so
/// local `cargo test` runs against the real `~/.microsandbox`.
#[proc_macro_attribute]
pub fn msb_test(attr: TokenStream, item: TokenStream) -> TokenStream {
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

    let tokio_args = proc_macro2::TokenStream::from(attr);
    let tokio_attr = if tokio_args.is_empty() {
        quote! { #[::tokio::test] }
    } else {
        quote! { #[::tokio::test(#tokio_args)] }
    };

    let expanded = quote! {
        #tokio_attr
        #[ignore]
        #input
    };

    expanded.into()
}
