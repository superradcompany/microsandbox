//! Expansion logic for the presence-aware configuration patch derive.

use proc_macro2::Span;
use quote::{format_ident, quote};
use syn::{
    Data, DeriveInput, Fields, GenericArgument, Ident, Path, PathArguments, Type, spanned::Spanned,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct PatchField {
    ident: Ident,
    ty: Type,
    option_inner: Option<Type>,
    nested_patch: Option<Ident>,
    nested_optional: bool,
    merge: Option<MergeStrategy>,
}

enum MergeStrategy {
    Extend,
    Custom(Path),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PatchField {
    fn parse(field: syn::Field) -> syn::Result<Self> {
        let ident = field.ident.ok_or_else(|| {
            syn::Error::new(Span::call_site(), "ConfigPatch requires named fields")
        })?;
        let mut nested = false;
        let mut merge = None;
        for attr in &field.attrs {
            if !attr.path().is_ident("config_patch") {
                continue;
            }
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("nested") {
                    if nested {
                        return Err(meta.error("duplicate nested option"));
                    }
                    nested = true;
                    return Ok(());
                }
                if meta.path.is_ident("merge") {
                    if merge.replace(MergeStrategy::Extend).is_some() {
                        return Err(meta.error("duplicate merge option"));
                    }
                    return Ok(());
                }
                if meta.path.is_ident("merge_with") {
                    let path: Path = meta.value()?.parse()?;
                    if merge.replace(MergeStrategy::Custom(path)).is_some() {
                        return Err(meta.error("duplicate merge option"));
                    }
                    return Ok(());
                }
                Err(meta.error("unsupported config_patch option"))
            })?;
        }
        if nested && merge.is_some() {
            return Err(syn::Error::new(
                field.ty.span(),
                "nested and collection merge options are mutually exclusive",
            ));
        }

        let option_inner = option_inner(&field.ty).cloned();
        let nested_ty = option_inner.as_ref().unwrap_or(&field.ty);
        let nested_patch = nested
            .then(|| type_ident(nested_ty))
            .transpose()?
            .map(|ident| format_ident!("{ident}Patch"));
        let nested_optional = nested && option_inner.is_some();

        Ok(Self {
            ident,
            ty: field.ty,
            option_inner,
            nested_patch,
            nested_optional,
            merge,
        })
    }

    fn declaration(&self) -> proc_macro2::TokenStream {
        let ident = &self.ident;
        if self.merge.is_some() {
            let ty = self.option_inner.as_ref().unwrap_or(&self.ty);
            quote! { #ident: ::std::option::Option<(bool, #ty)> }
        } else if let Some(patch) = &self.nested_patch {
            if self.nested_optional {
                quote! { #ident: ::std::option::Option<#patch> }
            } else {
                quote! { #ident: #patch }
            }
        } else {
            let ty = self.option_inner.as_ref().unwrap_or(&self.ty);
            quote! { #ident: ::std::option::Option<#ty> }
        }
    }

    fn setter(&self) -> proc_macro2::TokenStream {
        let ident = &self.ident;
        if self.merge.is_some() {
            let ty = self.option_inner.as_ref().unwrap_or(&self.ty);
            let doc = format!("Merge `value` into the `{ident}` field.");
            let merge = self.merge_patch_statement(quote!(current), quote!(value));
            quote! {
                #[doc = #doc]
                pub fn #ident(mut self, value: #ty) -> Self {
                    self.#ident = ::std::option::Option::Some(match self.#ident.take() {
                        ::std::option::Option::Some((reset, mut current)) => {
                            #merge
                            (reset, current)
                        }
                        ::std::option::Option::None => (false, value),
                    });
                    self
                }
            }
        } else if let Some(patch) = &self.nested_patch {
            let doc = format!("Set the `{ident}` field in this patch.");
            if self.nested_optional {
                quote! {
                    #[doc = #doc]
                    pub fn #ident(mut self, patch: #patch) -> Self {
                        self.#ident = ::std::option::Option::Some(match self.#ident.take() {
                            ::std::option::Option::Some(current) => current.overlay(patch),
                            ::std::option::Option::None => patch,
                        });
                        self
                    }
                }
            } else {
                quote! {
                    #[doc = #doc]
                    pub fn #ident(mut self, patch: #patch) -> Self {
                        self.#ident = self.#ident.overlay(patch);
                        self
                    }
                }
            }
        } else {
            let ty = self.option_inner.as_ref().unwrap_or(&self.ty);
            let doc = format!("Set the `{ident}` field in this patch.");
            quote! {
                #[doc = #doc]
                pub fn #ident(mut self, value: #ty) -> Self {
                    self.#ident = ::std::option::Option::Some(value);
                    self
                }
            }
        }
    }

    fn replacer(&self) -> Option<proc_macro2::TokenStream> {
        self.merge.as_ref()?;
        let ident = &self.ident;
        let method = format_ident!("replace_{ident}");
        let ty = self.option_inner.as_ref().unwrap_or(&self.ty);
        let doc = format!("Replace the complete `{ident}` field.");
        Some(quote! {
            #[doc = #doc]
            pub fn #method(mut self, value: #ty) -> Self {
                self.#ident = ::std::option::Option::Some((true, value));
                self
            }
        })
    }

    fn clearer(&self) -> proc_macro2::TokenStream {
        let ident = &self.ident;
        let method = format_ident!("clear_{ident}");
        let doc =
            format!("Remove `{ident}` from this patch so applying it leaves the target unchanged.");
        if self.nested_patch.is_some() && !self.nested_optional {
            quote! {
                #[doc = #doc]
                pub fn #method(mut self) -> Self {
                    self.#ident = ::std::default::Default::default();
                    self
                }
            }
        } else {
            quote! {
                #[doc = #doc]
                pub fn #method(mut self) -> Self {
                    self.#ident = ::std::option::Option::None;
                    self
                }
            }
        }
    }

    fn modifier(&self) -> Option<proc_macro2::TokenStream> {
        let patch = self.nested_patch.as_ref()?;
        let ident = &self.ident;
        let method = format_ident!("modify_{ident}");
        let doc = format!("Transform the current nested `{ident}` patch.");
        if self.nested_optional {
            Some(quote! {
                #[doc = #doc]
                pub fn #method(mut self, modify: impl FnOnce(#patch) -> #patch) -> Self {
                    self.#ident = ::std::option::Option::Some(modify(
                        self.#ident.take().unwrap_or_else(#patch::new),
                    ));
                    self
                }
            })
        } else {
            Some(quote! {
                #[doc = #doc]
                pub fn #method(mut self, modify: impl FnOnce(#patch) -> #patch) -> Self {
                    self.#ident = modify(self.#ident);
                    self
                }
            })
        }
    }

    fn merge_patch_statement(
        &self,
        base: proc_macro2::TokenStream,
        higher: proc_macro2::TokenStream,
    ) -> proc_macro2::TokenStream {
        match self.merge.as_ref().expect("merge strategy is present") {
            MergeStrategy::Extend => quote! { #base.extend(#higher); },
            MergeStrategy::Custom(path) => quote! { #path(&mut #base, #higher); },
        }
    }

    fn merge_target_statement(
        &self,
        target: proc_macro2::TokenStream,
        higher: proc_macro2::TokenStream,
    ) -> proc_macro2::TokenStream {
        match (
            self.merge.as_ref().expect("merge strategy is present"),
            self.option_inner.is_some(),
        ) {
            (MergeStrategy::Extend, true) => quote! {
                #target
                    .get_or_insert_with(::std::default::Default::default)
                    .extend(#higher);
            },
            (MergeStrategy::Extend, false) => quote! { #target.extend(#higher); },
            (MergeStrategy::Custom(path), true) => quote! {
                match #target.as_mut() {
                    ::std::option::Option::Some(current) => #path(current, #higher),
                    ::std::option::Option::None => #target = ::std::option::Option::Some(#higher),
                }
            },
            (MergeStrategy::Custom(path), false) => quote! { #path(&mut #target, #higher); },
        }
    }

    fn overlay(&self) -> proc_macro2::TokenStream {
        let ident = &self.ident;
        if self.merge.is_some() {
            let merge = self.merge_patch_statement(quote!(current), quote!(higher_value));
            quote! {
                if let ::std::option::Option::Some((higher_reset, higher_value)) = higher.#ident {
                    if higher_reset {
                        self.#ident = ::std::option::Option::Some((true, higher_value));
                    } else {
                        self.#ident = ::std::option::Option::Some(match self.#ident.take() {
                            ::std::option::Option::Some((reset, mut current)) => {
                                #merge
                                (reset, current)
                            }
                            ::std::option::Option::None => (false, higher_value),
                        });
                    }
                }
            }
        } else if self.nested_optional {
            quote! {
                if let ::std::option::Option::Some(higher_patch) = higher.#ident {
                    self.#ident = ::std::option::Option::Some(match self.#ident.take() {
                        ::std::option::Option::Some(current) => current.overlay(higher_patch),
                        ::std::option::Option::None => higher_patch,
                    });
                }
            }
        } else if self.nested_patch.is_some() {
            quote! { self.#ident = self.#ident.overlay(higher.#ident); }
        } else {
            quote! {
                if higher.#ident.is_some() {
                    self.#ident = higher.#ident;
                }
            }
        }
    }

    fn apply(&self) -> proc_macro2::TokenStream {
        let ident = &self.ident;
        if self.merge.is_some() {
            let merge = self.merge_target_statement(quote!(target.#ident), quote!(value));
            let replace = if self.option_inner.is_some() {
                quote! { target.#ident = ::std::option::Option::Some(value); }
            } else {
                quote! { target.#ident = value; }
            };
            quote! {
                if let ::std::option::Option::Some((reset, value)) = self.#ident {
                    if reset {
                        #replace
                    } else {
                        #merge
                    }
                }
            }
        } else if self.nested_optional {
            quote! {
                if let ::std::option::Option::Some(patch) = self.#ident {
                    patch.apply_to(target.#ident.get_or_insert_with(::std::default::Default::default));
                }
            }
        } else if self.nested_patch.is_some() {
            quote! { self.#ident.apply_to(&mut target.#ident); }
        } else if self.option_inner.is_some() {
            quote! {
                if let ::std::option::Option::Some(value) = self.#ident {
                    target.#ident = ::std::option::Option::Some(value);
                }
            }
        } else {
            quote! {
                if let ::std::option::Option::Some(value) = self.#ident {
                    target.#ident = value;
                }
            }
        }
    }

    fn render_present(&self) -> proc_macro2::TokenStream {
        let ident = &self.ident;
        if self.merge.is_some() {
            if self.option_inner.is_some() {
                quote! { #ident: #ident.map(|value| (false, value)) }
            } else {
                quote! { #ident: ::std::option::Option::Some((false, #ident)) }
            }
        } else if let Some(patch) = &self.nested_patch {
            if self.nested_optional {
                quote! { #ident: #ident.map(#patch::from_present_fields) }
            } else {
                quote! { #ident: #patch::from_present_fields(#ident) }
            }
        } else if self.option_inner.is_some() {
            quote! { #ident }
        } else {
            quote! { #ident: ::std::option::Option::Some(#ident) }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn expand_config_patch(input: DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    if !input.generics.params.is_empty() {
        return Err(syn::Error::new(
            input.generics.span(),
            "ConfigPatch does not support generic structs",
        ));
    }

    let patch_ident = configured_patch_ident(&input)?;

    let Data::Struct(data) = input.data else {
        return Err(syn::Error::new(
            input.ident.span(),
            "ConfigPatch can only be derived for structs",
        ));
    };
    let Fields::Named(fields) = data.fields else {
        return Err(syn::Error::new(
            input.ident.span(),
            "ConfigPatch requires named fields",
        ));
    };

    let struct_ident = input.ident;
    let visibility = input.vis;
    let fields = fields
        .named
        .into_iter()
        .map(PatchField::parse)
        .collect::<syn::Result<Vec<_>>>()?;

    let patch_fields = fields.iter().map(PatchField::declaration);
    let setters = fields.iter().map(PatchField::setter);
    let replacers = fields.iter().filter_map(PatchField::replacer);
    let clearers = fields.iter().map(PatchField::clearer);
    let modifiers = fields.iter().filter_map(PatchField::modifier);
    let overlay_fields = fields.iter().map(PatchField::overlay);
    let apply_fields = fields.iter().map(PatchField::apply);
    let present_destructured_fields = fields.iter().map(|field| &field.ident);
    let present_fields = fields.iter().map(PatchField::render_present);

    Ok(quote! {
        #[doc = concat!("A sparse, presence-aware patch for [`", stringify!(#struct_ident), "`].")]
        #[derive(Debug, Clone, Default)]
        #visibility struct #patch_ident {
            #(#patch_fields,)*
        }

        impl #patch_ident {
            /// Create an empty patch that leaves every target field unchanged.
            pub fn new() -> Self {
                Self::default()
            }

            #(#setters)*
            #(#replacers)*
            #(#clearers)*
            #(#modifiers)*

            /// Overlay a higher-precedence patch using each field's declared strategy.
            pub fn overlay(mut self, higher: Self) -> Self {
                #(#overlay_fields)*
                self
            }

            /// Apply every present field to an existing value.
            pub fn apply_to(self, target: &mut #struct_ident) {
                #(#apply_fields)*
            }

            /// Convert non-null fields into a changeset, treating `Option::None` as absent.
            pub fn from_present_fields(value: #struct_ident) -> Self {
                let #struct_ident { #(#present_destructured_fields,)* } = value;
                Self {
                    #(#present_fields,)*
                }
            }
        }

        impl From<#struct_ident> for #patch_ident {
            fn from(value: #struct_ident) -> Self {
                Self::from_present_fields(value)
            }
        }
    })
}

fn configured_patch_ident(input: &DeriveInput) -> syn::Result<Ident> {
    let mut configured = None;
    for attr in &input.attrs {
        if !attr.path().is_ident("config_patch") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("name") {
                let ident: Ident = meta.value()?.parse()?;
                if configured.replace(ident).is_some() {
                    return Err(meta.error("duplicate config_patch name"));
                }
                return Ok(());
            }
            Err(meta.error("unsupported struct-level config_patch option"))
        })?;
    }

    Ok(configured.unwrap_or_else(|| format_ident!("{}Patch", input.ident)))
}

fn option_inner(ty: &Type) -> Option<&Type> {
    let Type::Path(path) = ty else {
        return None;
    };
    let segment = path.path.segments.last()?;
    if segment.ident != "Option" {
        return None;
    }
    let PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return None;
    };
    match arguments.args.first()? {
        GenericArgument::Type(inner) => Some(inner),
        _ => None,
    }
}

fn type_ident(ty: &Type) -> syn::Result<Ident> {
    let Type::Path(path) = ty else {
        return Err(syn::Error::new(
            ty.span(),
            "nested config patches require a named struct type",
        ));
    };
    path.path
        .segments
        .last()
        .map(|segment| segment.ident.clone())
        .ok_or_else(|| syn::Error::new(ty.span(), "missing nested struct type"))
}
