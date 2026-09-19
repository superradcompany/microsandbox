//! Expansion logic for the presence-aware configuration patch derive.
//!
//! Keep attributes about reusable patch operations. Before adding another mode,
//! compare it with a handwritten implementation for the specific field or type.

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
    visibility: syn::Visibility,
    option_inner: Option<Type>,
    nested_patch: Option<Ident>,
    nested_optional: bool,
    nested_map: Option<Type>,
    merge: Option<MergeStrategy>,
    nullable: bool,
    serde_attrs: Vec<syn::Attribute>,
    adapter: Option<Path>,
}

enum MergeStrategy {
    Extend,
    Custom(Path),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PatchField {
    fn parse(field: syn::Field, deserialize: bool) -> syn::Result<Self> {
        let ident = field.ident.clone().ok_or_else(|| {
            syn::Error::new(Span::call_site(), "ConfigPatch requires named fields")
        })?;
        let mut nullable = false;
        let mut nested = false;
        let mut merge = None;
        for attr in &field.attrs {
            if !attr.path().is_ident("config_patch") {
                continue;
            }
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("nullable") {
                    nullable = true;
                    return Ok(());
                }
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
        let option_inner = option_inner(&field.ty).cloned();
        nullable |= deserialize && option_inner.is_some();
        if nullable && (option_inner.is_none() || nested || merge.is_some()) {
            return Err(syn::Error::new(
                field.ty.span(),
                "nullable patches require an atomic Option field",
            ));
        }
        let mut serde_attrs = Vec::new();
        let mut adapter = None;
        if deserialize {
            for attr in &field.attrs {
                if attr.path().is_ident("serde") {
                    let items = attr.parse_args_with(
                        syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
                    )?;
                    for meta in items {
                        if meta.path().is_ident("rename") || meta.path().is_ident("alias") {
                            serde_attrs.push(syn::parse_quote!(#[serde(#meta)]));
                        } else if let syn::Meta::NameValue(value) = meta
                            && value.path.is_ident("with")
                        {
                            let syn::Expr::Lit(lit) = value.value else {
                                continue;
                            };
                            let syn::Lit::Str(path) = lit.lit else {
                                continue;
                            };
                            adapter = Some(path.parse()?);
                        }
                    }
                }
            }
        }
        let nested_map = if nested && merge.is_some() {
            if !matches!(merge, Some(MergeStrategy::Extend)) || option_inner.is_some() {
                return Err(syn::Error::new(
                    field.span(),
                    "nested map patches require merge on a non-optional map",
                ));
            }
            let mut ty = field.ty.clone();
            let Type::Path(path) = &mut ty else {
                return Err(syn::Error::new(field.span(), "nested merge requires a map"));
            };
            let segment = path.path.segments.last_mut().unwrap();
            if segment.ident != "HashMap" && segment.ident != "BTreeMap" {
                return Err(syn::Error::new(
                    field.span(),
                    "nested merge requires HashMap or BTreeMap",
                ));
            }
            let PathArguments::AngleBracketed(args) = &mut segment.arguments else {
                return Err(syn::Error::new(
                    field.span(),
                    "nested merge requires map type arguments",
                ));
            };
            let Some(GenericArgument::Type(Type::Path(value))) = args.args.iter_mut().nth(1) else {
                return Err(syn::Error::new(
                    field.span(),
                    "nested map values must be named structs",
                ));
            };
            let value = value.path.segments.last_mut().unwrap();
            value.ident = format_ident!("{}Patch", value.ident);
            nested = false;
            Some(ty)
        } else {
            None
        };
        let nested_ty = option_inner.as_ref().unwrap_or(&field.ty);
        let nested_patch = nested
            .then(|| type_ident(nested_ty))
            .transpose()?
            .map(|ident| format_ident!("{ident}Patch"));
        let nested_optional = nested && option_inner.is_some();

        Ok(Self {
            ident,
            ty: field.ty,
            visibility: field.vis,
            option_inner,
            nested_patch,
            nested_optional,
            nested_map,
            merge,
            nullable,
            serde_attrs,
            adapter,
        })
    }

    fn value_type(&self) -> &Type {
        self.nested_map
            .as_ref()
            .or(self.option_inner.as_ref())
            .unwrap_or(&self.ty)
    }

    fn declaration(&self) -> proc_macro2::TokenStream {
        let ident = &self.ident;
        if self.merge.is_some() {
            let ty = self.value_type();
            return quote! { #ident: ::std::option::Option<(bool, #ty)> };
        }
        let visibility = &self.visibility;
        let ty = if self.nullable {
            let ty = &self.ty;
            quote! { ::std::option::Option<#ty> }
        } else if let Some(patch) = &self.nested_patch {
            if self.nested_optional {
                quote! { ::std::option::Option<#patch> }
            } else {
                quote! { #patch }
            }
        } else {
            let ty = self.value_type();
            quote! { ::std::option::Option<#ty> }
        };
        quote! {
            #[doc = concat!("Pending update for `", stringify!(#ident), "`. Omitted values leave the target unchanged.")]
            #visibility #ident: #ty
        }
    }

    fn setter(&self) -> proc_macro2::TokenStream {
        let ident = &self.ident;
        let ty = self.value_type();
        if self.merge.is_some() {
            let merge = self.merge_patch_statement(quote!(current), quote!(value));
            mutating_method(
                &self.visibility,
                ident,
                &format!("Merge `value` into the `{ident}` field."),
                quote!(value: #ty),
                quote!(value),
                quote! {
                    self.#ident = ::std::option::Option::Some(match self.#ident.take() {
                        ::std::option::Option::Some((reset, mut current)) => {
                            #merge
                            (reset, current)
                        }
                        ::std::option::Option::None => (false, value),
                    });
                },
            )
        } else if let Some(patch) = &self.nested_patch {
            let target = if self.nested_optional {
                quote! { self.#ident.get_or_insert_with(#patch::new) }
            } else {
                quote! { self.#ident }
            };
            mutating_method(
                &self.visibility,
                ident,
                &format!("Set the `{ident}` field in this patch."),
                quote!(patch: #patch),
                quote!(patch),
                quote! { #target.overlay_mut(patch); },
            )
        } else {
            let value = if self.nullable {
                quote!(Some(value))
            } else {
                quote!(value)
            };
            let setter = mutating_method(
                &self.visibility,
                ident,
                &format!("Set the `{ident}` field in this patch."),
                quote!(value: #ty),
                quote!(value),
                quote! { self.#ident = ::std::option::Option::Some(#value); },
            );
            let nullable_setter = self.nullable.then(|| {
                mutating_method(
                    &self.visibility,
                    &format_ident!("set_{ident}"),
                    &format!("Set or explicitly clear `{ident}`."),
                    quote!(value: Option<#ty>),
                    quote!(value),
                    quote! { self.#ident = Some(value); },
                )
            });
            quote! { #nullable_setter #setter }
        }
    }

    fn replacer(&self) -> Option<proc_macro2::TokenStream> {
        self.merge.as_ref()?;
        let ident = &self.ident;
        let ty = self.value_type();
        Some(mutating_method(
            &self.visibility,
            &format_ident!("replace_{ident}"),
            &format!("Replace the complete `{ident}` field."),
            quote!(value: #ty),
            quote!(value),
            quote! { self.#ident = ::std::option::Option::Some((true, value)); },
        ))
    }

    fn clearer(&self) -> proc_macro2::TokenStream {
        let ident = &self.ident;
        let value = if self.nested_patch.is_some() && !self.nested_optional {
            quote!(::std::default::Default::default())
        } else {
            quote!(::std::option::Option::None)
        };
        mutating_method(
            &self.visibility,
            &format_ident!("clear_{ident}"),
            &format!(
                "Remove `{ident}` from this patch so applying it leaves the target unchanged."
            ),
            quote!(),
            quote!(),
            quote! { self.#ident = #value; },
        )
    }

    fn collection_accessor(&self) -> Option<proc_macro2::TokenStream> {
        self.merge.as_ref()?;
        let ty = self.value_type();
        let Type::Path(path) = ty else {
            return None;
        };
        if !matches!(
            path.path.segments.last()?.ident.to_string().as_str(),
            "Vec"
                | "VecDeque"
                | "LinkedList"
                | "HashMap"
                | "BTreeMap"
                | "HashSet"
                | "BTreeSet"
                | "BinaryHeap"
        ) {
            return None;
        }
        let ident = &self.ident;
        let method = format_ident!("get_{ident}_mut");
        let visibility = &self.visibility;
        Some(quote! {
            #[doc = concat!("Borrow the pending `", stringify!(#ident), "` collection mutably. Initializes an absent collection empty in merge mode and preserves an existing replacement mode. Edits pending values directly without running the merge strategy.")]
            #visibility fn #method(&mut self) -> &mut #ty {
                &mut self.#ident.get_or_insert_with(|| (false, ::std::default::Default::default())).1
            }
        })
    }

    fn merge_patch_statement(
        &self,
        base: proc_macro2::TokenStream,
        higher: proc_macro2::TokenStream,
    ) -> proc_macro2::TokenStream {
        if self.nested_map.is_some() {
            return quote! {
                for (key, patch) in #higher {
                    #base.entry(key).or_default().overlay_mut(patch);
                }
            };
        }
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
            quote! { self.#ident.overlay_mut(higher.#ident); }
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
        if self.nullable {
            return quote! { if let Some(value) = self.#ident { target.#ident = value; } };
        }
        if self.nested_map.is_some() {
            return quote! {
                if let ::std::option::Option::Some((reset, values)) = self.#ident {
                    if reset { target.#ident.clear(); }
                    for (key, patch) in values {
                        patch.apply_to(target.#ident.entry(key).or_default());
                    }
                }
            };
        }
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
        if self.nullable {
            return quote! { #ident: #ident.map(Some) };
        }
        if self.nested_map.is_some() {
            return quote! {
                #ident: ::std::option::Option::Some((false,
                    #ident.into_iter().map(|(key, value)| (key, value.into())).collect()))
            };
        }
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

    fn getter(&self) -> Option<proc_macro2::TokenStream> {
        self.merge.as_ref()?;
        let ident = &self.ident;
        let method = format_ident!("get_{ident}");
        let ty = self.value_type();
        let visibility = &self.visibility;
        Some(quote! {
            #[doc = concat!("Borrow the pending collection for `", stringify!(#ident), "` without its merge/replacement state.")]
            #visibility fn #method(&self) -> Option<&#ty> {
                self.#ident.as_ref().map(|(_, value)| value)
            }
        })
    }

    fn serde_attributes(&self, patch: &Ident) -> proc_macro2::TokenStream {
        let attrs = &self.serde_attrs;
        if let Some(nested) = &self.nested_patch
            && !self.nested_optional
        {
            let is_empty = format!("{nested}::is_empty");
            return quote! { #(#attrs)* #[serde(default, skip_serializing_if = #is_empty)] };
        }
        let serialize = if self.adapter.is_some() {
            let function = format!("{patch}::serialize_{}", self.ident);
            quote! { #[serde(serialize_with = #function)] }
        } else if self.merge.is_some() {
            quote! { #[serde(serialize_with = "::microsandbox_types::helpers::serialize_merge")] }
        } else {
            quote! {}
        };
        let function = if self.adapter.is_some() {
            format!("{patch}::deserialize_{}", self.ident)
        } else if self.merge.is_some() {
            "::microsandbox_types::helpers::deserialize_merge".into()
        } else {
            "::microsandbox_types::helpers::deserialize_present".into()
        };
        quote! {
            #(#attrs)*
            #serialize
            #[serde(default, deserialize_with = #function, skip_serializing_if = "Option::is_none")]
        }
    }

    fn is_empty(&self) -> proc_macro2::TokenStream {
        let ident = &self.ident;
        if self.nested_patch.is_some() && !self.nested_optional {
            quote! { self.#ident.is_empty() }
        } else {
            quote! { self.#ident.is_none() }
        }
    }

    fn serde_adapter(&self) -> Option<proc_macro2::TokenStream> {
        let adapter = self.adapter.as_ref()?;
        let ty = &self.ty;
        let method = format_ident!("deserialize_{}", self.ident);
        let serialize = format_ident!("serialize_{}", self.ident);
        // Adapters belong to the original value; the outer option records field presence.
        // Wrapping nullable values allows null even when the wire adapter uses a sentinel (e.g. 0).
        let decode = if self.option_inner.is_some() {
            let path = quote!(#adapter).to_string();
            quote! {
                #[derive(::serde::Deserialize)]
                struct Adapted(#[serde(with = #path)] #ty);
                <Option<Adapted> as ::serde::Deserialize>::deserialize(deserializer)
                    .map(|value| Some(value.and_then(|value| value.0)))
            }
        } else {
            quote! { #adapter::deserialize(deserializer).map(Some) }
        };
        Some(quote! {
            fn #method<'de, D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Option<#ty>, D::Error> {
                #decode
            }

            fn #serialize<S: ::serde::Serializer>(value: &Option<#ty>, serializer: S) -> Result<S::Ok, S::Error> {
                match value {
                    Some(value) => #adapter::serialize(value, serializer),
                    None => serializer.serialize_none(),
                }
            }
        })
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

    let patch_ident = format_ident!("{}Patch", input.ident);
    let mut deserialize = false;
    for attr in &input.attrs {
        if !attr.path().is_ident("config_patch") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("serde") {
                deserialize = true;
                return Ok(());
            }
            Err(meta.error("unsupported struct-level config_patch option"))
        })?;
    }

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
        .map(|field| PatchField::parse(field, deserialize))
        .collect::<syn::Result<Vec<_>>>()?;

    let patch_fields = fields.iter().map(|field| {
        let attrs = deserialize.then(|| field.serde_attributes(&patch_ident));
        let declaration = field.declaration();
        quote! { #attrs #declaration }
    });
    let serde_derive =
        deserialize.then(|| quote! { #[derive(::serde::Serialize, ::serde::Deserialize)] });
    let adapters = fields.iter().filter_map(PatchField::serde_adapter);
    let is_empty = deserialize.then(|| {
        let checks = fields.iter().map(PatchField::is_empty);
        quote! {
            /// Whether this patch contains no pending changes.
            pub fn is_empty(&self) -> bool {
                true #(&& #checks)*
            }
        }
    });
    let getters = fields.iter().filter_map(PatchField::getter);
    let setters = fields.iter().map(PatchField::setter);
    let replacers = fields.iter().filter_map(PatchField::replacer);
    let clearers = fields.iter().map(PatchField::clearer);
    let collection_accessors = fields.iter().filter_map(PatchField::collection_accessor);
    let overlay_fields = fields.iter().map(PatchField::overlay);
    let overlay = mutating_method(
        &syn::parse_quote!(pub),
        &format_ident!("overlay"),
        "Overlay a higher-precedence patch using each field's declared strategy.",
        quote!(higher: Self),
        quote!(higher),
        quote! { #(#overlay_fields)* },
    );
    let apply_fields = fields.iter().map(PatchField::apply);
    let present_destructured_fields = fields.iter().map(|field| &field.ident);
    let present_fields = fields.iter().map(PatchField::render_present);

    Ok(quote! {
        #[doc = concat!("A sparse, presence-aware patch for [`", stringify!(#struct_ident), "`].")]
        #[derive(Debug, Clone, Default)]
        #serde_derive
        #visibility struct #patch_ident {
            #(#patch_fields,)*
        }

        impl #patch_ident {
            #(#getters)*
            #(#adapters)*
            #is_empty
            /// Create an empty patch that leaves every target field unchanged.
            pub fn new() -> Self {
                Self::default()
            }

            #(#setters)*
            #(#replacers)*
            #(#clearers)*
            #(#collection_accessors)*

            #overlay

            /// Apply every present field to an existing value.
            pub fn apply_to(self, target: &mut #struct_ident) {
                #(#apply_fields)*
            }

            /// Apply this patch to the configuration's defaults.
            ///
            /// Compose all overlays first. This conversion does not validate the result.
            pub fn into_config(self) -> #struct_ident {
                let mut config = <#struct_ident as ::std::default::Default>::default();
                self.apply_to(&mut config);
                config
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

/// Generate the fluent wrapper and its mutable implementation together.
fn mutating_method(
    visibility: &syn::Visibility,
    name: &Ident,
    doc: &str,
    parameters: proc_macro2::TokenStream,
    arguments: proc_macro2::TokenStream,
    body: proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    let mutable_name = format_ident!("{name}_mut");
    quote! {
        #[doc = #doc]
        #visibility fn #name(mut self, #parameters) -> Self {
            self.#mutable_name(#arguments);
            self
        }

        #[doc = #doc]
        #[doc = "Mutates this patch in place and returns it for chaining."]
        #visibility fn #mutable_name(&mut self, #parameters) -> &mut Self {
            #body
            self
        }
    }
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
