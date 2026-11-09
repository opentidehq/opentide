//! `#[derive(FromNode)]`: the structural conversion of an `opentide-schema`
//! model from the YAML node tree, collecting every error (UC-1.2, #808; ADR
//! 0001, "The derive stack").
//!
//! The derive reads the serde attributes the model already carries, so names
//! and closure are written once:
//!
//! | Attribute | Effect |
//! |-----------|--------|
//! | `#[serde(deny_unknown_fields)]` | a closed model: an unused key is `extra_forbidden` |
//! | `#[serde(rename = "x")]` | the key (Pydantic's alias, looked up first) |
//! | `#[serde(alias = "y")]` | another key the field takes (Pydantic's name, `populate_by_name`) |
//! | `#[serde(default)]`, `#[serde(default = "path")]` | a missing key is the default, not "Field required" |
//! | `#[serde(rename_all = "...")]` on a unit enum | the variants' values |
//!
//! and its own, `#[from_node(...)]`:
//!
//! | Where | Attribute | Effect |
//! |-------|-----------|--------|
//! | struct | `model = "ThreatBody"` | the Python class name in `model_type` messages (default: the Rust name) |
//! | struct | `before = "path"` | `fn(&Node, &mut Context) -> bool`, run first on the raw value (a `mode="before"` model validator); `false` stops |
//! | struct | `tolerate = "PATH"` | a `&[&str]` of keys a closed model does not report (the `__legacy_keys__` pre-pass) |
//! | field | `before = "path"` | the same, on the field's value (a `mode="before"` field validator) |
//! | field | `with = "path"` | `fn(&Node, &mut Context) -> Option<T>` converts the field instead of `T: FromNode` |
//! | unit enum | `literal` | `literal_error` (a `Literal[...]`) rather than `enum` |
//! | enum | `union` | a union of its one-field variants, each with `tag = "str"` |
//!
//! serde attributes that change what is read and that the conversion does not
//! reproduce (`flatten`, `skip`, `deserialize_with`, `with`, `untagged` on a
//! non-union, a container `default`, `from`, `try_from`, `transparent`, a
//! struct `rename_all`) are compile errors, so a model cannot silently read
//! differently under serde and under the conversion.

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{format_ident, quote};
use syn::{
    Attribute, Data, DeriveInput, Expr, ExprLit, Fields, Lit, LitStr, Meta, Path, Token,
    parse_macro_input, punctuated::Punctuated, spanned::Spanned,
};

/// Derives `opentide_schema::FromNode`. See the crate documentation.
#[proc_macro_derive(FromNode, attributes(from_node))]
pub fn derive_from_node(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand(&input) {
        Ok(tokens) => tokens.into(),
        Err(error) => error.to_compile_error().into(),
    }
}

/// One `key = "value"` or bare `key` of an attribute list.
struct Item {
    key: String,
    value: Option<LitStr>,
    span: Span,
}

fn items(attrs: &[Attribute], name: &str) -> syn::Result<Vec<Item>> {
    let mut out = Vec::new();
    for attr in attrs.iter().filter(|attr| attr.path().is_ident(name)) {
        let metas = attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)?;
        for meta in metas {
            let key = meta
                .path()
                .get_ident()
                .map(ToString::to_string)
                .ok_or_else(|| syn::Error::new(meta.span(), "expected a name"))?;
            let value = match &meta {
                Meta::Path(_) => None,
                Meta::NameValue(pair) => match &pair.value {
                    Expr::Lit(ExprLit {
                        lit: Lit::Str(text),
                        ..
                    }) => Some(text.clone()),
                    other => {
                        return Err(syn::Error::new(
                            other.span(),
                            format!("#[{name}({key} = ...)]: only a string literal is supported"),
                        ));
                    }
                },
                Meta::List(list) => {
                    // serde's `rename(deserialize = ...)` and the like.
                    return Err(syn::Error::new(
                        list.span(),
                        format!("#[{name}({key}(...))] is not supported by FromNode"),
                    ));
                }
            };
            out.push(Item {
                key,
                value,
                span: meta.span(),
            });
        }
    }
    Ok(out)
}

/// The serde attributes FromNode cannot reproduce.
const SERDE_FIELD_REFUSED: &[&str] = &[
    "flatten",
    "skip",
    "skip_deserializing",
    "deserialize_with",
    "with",
    "borrow",
    "getter",
];
const SERDE_CONTAINER_REFUSED: &[&str] = &[
    "default",
    "from",
    "try_from",
    "transparent",
    "tag",
    "content",
    "remote",
    "variant_identifier",
    "field_identifier",
];

fn refuse(items: &[Item], refused: &[&str]) -> syn::Result<()> {
    for item in items {
        if refused.contains(&item.key.as_str()) {
            return Err(syn::Error::new(
                item.span,
                format!(
                    "#[serde({})] changes what is read, and FromNode does not reproduce it",
                    item.key
                ),
            ));
        }
    }
    Ok(())
}

fn path_of(item: &Item) -> syn::Result<Path> {
    let text = item
        .value
        .as_ref()
        .ok_or_else(|| syn::Error::new(item.span, format!("{} needs a path", item.key)))?;
    text.parse()
}

fn string_of(item: &Item) -> syn::Result<String> {
    item.value
        .as_ref()
        .map(LitStr::value)
        .ok_or_else(|| syn::Error::new(item.span, format!("{} needs a string", item.key)))
}

fn expand(input: &DeriveInput) -> syn::Result<TokenStream2> {
    if !input.generics.params.is_empty() {
        return Err(syn::Error::new(
            input.generics.span(),
            "FromNode models are concrete: one struct per revision (ADR 0001)",
        ));
    }
    let serde = items(&input.attrs, "serde")?;
    let own = items(&input.attrs, "from_node")?;
    match &input.data {
        Data::Struct(data) => {
            refuse(&serde, SERDE_CONTAINER_REFUSED)?;
            if let Some(item) = serde.iter().find(|item| item.key == "rename_all") {
                return Err(syn::Error::new(
                    item.span,
                    "#[serde(rename_all)] on a model: name each renamed field instead",
                ));
            }
            expand_struct(input, data, &serde, &own)
        }
        Data::Enum(data) => {
            if own.iter().any(|item| item.key == "union") {
                expand_union(input, data, &own)
            } else {
                refuse(&serde, SERDE_CONTAINER_REFUSED)?;
                if let Some(item) = serde.iter().find(|item| item.key == "untagged") {
                    return Err(syn::Error::new(
                        item.span,
                        "an untagged enum is a union: add #[from_node(union)]",
                    ));
                }
                expand_unit_enum(input, data, &serde, &own)
            }
        }
        Data::Union(_) => Err(syn::Error::new(
            input.span(),
            "FromNode is for structs and enums",
        )),
    }
}

fn expand_struct(
    input: &DeriveInput,
    data: &syn::DataStruct,
    serde: &[Item],
    own: &[Item],
) -> syn::Result<TokenStream2> {
    let name = &input.ident;
    let Fields::Named(declared) = &data.fields else {
        return Err(syn::Error::new(
            data.fields.span(),
            "a FromNode model has named fields",
        ));
    };
    let closed = serde.iter().any(|item| item.key == "deny_unknown_fields");
    let mut class_name = name.to_string();
    let mut before = None;
    let mut tolerate = quote!(&[]);
    for item in own {
        match item.key.as_str() {
            "model" => class_name = string_of(item)?,
            "before" => before = Some(path_of(item)?),
            "tolerate" => {
                let path = path_of(item)?;
                tolerate = quote!(#path);
            }
            other => {
                return Err(syn::Error::new(
                    item.span,
                    format!("unknown #[from_node({other})] on a struct"),
                ));
            }
        }
    }
    let mut bindings = Vec::new();
    let mut lets = Vec::new();
    for (index, field) in declared.named.iter().enumerate() {
        let Some(ident) = &field.ident else {
            return Err(syn::Error::new(field.span(), "a named field"));
        };
        let ty = &field.ty;
        let field_serde = items(&field.attrs, "serde")?;
        refuse(&field_serde, SERDE_FIELD_REFUSED)?;
        let field_own = items(&field.attrs, "from_node")?;
        let mut names = vec![ident.to_string().trim_start_matches("r#").to_owned()];
        let mut aliases = Vec::new();
        let mut missing = quote!(::opentide_schema::from_node::Missing::Required);
        for item in &field_serde {
            match item.key.as_str() {
                "rename" => names[0] = string_of(item)?,
                "alias" => aliases.push(string_of(item)?),
                "default" => {
                    missing = match &item.value {
                        None => quote!(::opentide_schema::from_node::Missing::Default(
                            <#ty as ::core::default::Default>::default
                        )),
                        Some(_) => {
                            let path = path_of(item)?;
                            quote!(::opentide_schema::from_node::Missing::Default(#path))
                        }
                    };
                }
                _ => {}
            }
        }
        names.extend(aliases);
        let mut field_before = quote!(::core::option::Option::None);
        let mut convert =
            quote!(<#ty as ::opentide_schema::from_node::FromNode>::from_node(__n, __cx));
        for item in &field_own {
            match item.key.as_str() {
                "before" => {
                    let path = path_of(item)?;
                    field_before = quote!(::core::option::Option::Some(#path));
                }
                "with" => {
                    let path = path_of(item)?;
                    convert = quote!(#path(__n, __cx));
                }
                other => {
                    return Err(syn::Error::new(
                        item.span,
                        format!("unknown #[from_node({other})] on a field"),
                    ));
                }
            }
        }
        let binding = format_ident!("__field_{}", index);
        lets.push(quote! {
            let #binding: ::core::option::Option<#ty> = __fields.field(
                __cx,
                &[#(#names),*],
                #missing,
                #field_before,
                |__n: &::opentide_schema::node::Node,
                 __cx: &mut ::opentide_schema::from_node::Context| #convert,
            );
        });
        bindings.push(quote!(#ident: #binding?));
    }
    let before_check = before.map(|path| {
        quote! {
            if !#path(__node, __cx) {
                return ::core::option::Option::None;
            }
        }
    });
    Ok(quote! {
        #[automatically_derived]
        impl ::opentide_schema::from_node::FromNode for #name {
            fn from_node(
                __node: &::opentide_schema::node::Node,
                __cx: &mut ::opentide_schema::from_node::Context,
            ) -> ::core::option::Option<Self> {
                #before_check
                let __entries = ::opentide_schema::from_node::model_entries(__node, __cx, #class_name)?;
                let mut __fields = ::opentide_schema::from_node::Fields::new(__node, __entries);
                #(#lets)*
                __fields.finish(__cx, #closed, #tolerate);
                ::core::option::Option::Some(Self { #(#bindings),* })
            }

            fn takes_strictly(__node: &::opentide_schema::node::Node) -> bool {
                ::core::matches!(__node.value, ::opentide_schema::node::Value::Map(_))
            }
        }
    })
}

/// serde's `rename_all` rules for unit variants.
fn rename(rule: &str, variant: &str, span: Span) -> syn::Result<String> {
    let words: Vec<String> = {
        let mut words = Vec::new();
        let mut current = String::new();
        for character in variant.chars() {
            if character.is_uppercase() && !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
            current.push(character);
        }
        if !current.is_empty() {
            words.push(current);
        }
        words
    };
    let lower = |w: &String| w.to_lowercase();
    Ok(match rule {
        "lowercase" => variant.to_lowercase(),
        "UPPERCASE" => variant.to_uppercase(),
        "snake_case" => words.iter().map(lower).collect::<Vec<_>>().join("_"),
        "kebab-case" => words.iter().map(lower).collect::<Vec<_>>().join("-"),
        "SCREAMING_SNAKE_CASE" => words
            .iter()
            .map(|w| w.to_uppercase())
            .collect::<Vec<_>>()
            .join("_"),
        "PascalCase" => variant.to_owned(),
        other => {
            return Err(syn::Error::new(
                span,
                format!("#[serde(rename_all = {other:?})] is not supported by FromNode"),
            ));
        }
    })
}

fn expand_unit_enum(
    input: &DeriveInput,
    data: &syn::DataEnum,
    serde: &[Item],
    own: &[Item],
) -> syn::Result<TokenStream2> {
    let name = &input.ident;
    let mut literal = false;
    for item in own {
        match item.key.as_str() {
            "literal" => literal = true,
            other => {
                return Err(syn::Error::new(
                    item.span,
                    format!("unknown #[from_node({other})] on an enum"),
                ));
            }
        }
    }
    let rule = serde
        .iter()
        .find(|item| item.key == "rename_all")
        .map(|item| Ok::<_, syn::Error>((string_of(item)?, item.span)))
        .transpose()?;
    let mut values = Vec::new();
    let mut arms = Vec::new();
    for (index, variant) in data.variants.iter().enumerate() {
        if !matches!(variant.fields, Fields::Unit) {
            return Err(syn::Error::new(
                variant.span(),
                "a FromNode enum has unit variants (or is a #[from_node(union)])",
            ));
        }
        let variant_serde = items(&variant.attrs, "serde")?;
        refuse(&variant_serde, SERDE_FIELD_REFUSED)?;
        let ident = &variant.ident;
        let mut value = match &rule {
            Some((rule, span)) => rename(rule, &ident.to_string(), *span)?,
            None => ident.to_string(),
        };
        for item in &variant_serde {
            if item.key == "rename" {
                value = string_of(item)?;
            }
        }
        values.push(quote!((#value, #index)));
        arms.push(quote!(#index => ::core::option::Option::Some(Self::#ident),));
    }
    Ok(quote! {
        #[automatically_derived]
        impl ::opentide_schema::from_node::FromNode for #name {
            fn from_node(
                __node: &::opentide_schema::node::Node,
                __cx: &mut ::opentide_schema::from_node::Context,
            ) -> ::core::option::Option<Self> {
                match ::opentide_schema::from_node::enum_value(__node, __cx, &[#(#values),*], #literal)? {
                    #(#arms)*
                    _ => ::core::option::Option::None,
                }
            }

            fn takes_strictly(__node: &::opentide_schema::node::Node) -> bool {
                ::core::matches!(__node.value, ::opentide_schema::node::Value::Str(_))
            }
        }
    })
}

fn expand_union(
    input: &DeriveInput,
    data: &syn::DataEnum,
    own: &[Item],
) -> syn::Result<TokenStream2> {
    let name = &input.ident;
    for item in own {
        if item.key != "union" {
            return Err(syn::Error::new(
                item.span,
                format!("unknown #[from_node({})] on a union", item.key),
            ));
        }
    }
    let mut members = Vec::new();
    for variant in &data.variants {
        let Fields::Unnamed(fields) = &variant.fields else {
            return Err(syn::Error::new(
                variant.span(),
                "a union variant holds one value: `Str(String)`",
            ));
        };
        let [field] = fields.unnamed.iter().collect::<Vec<_>>()[..] else {
            return Err(syn::Error::new(
                variant.span(),
                "a union variant holds one value: `Str(String)`",
            ));
        };
        let ty = &field.ty;
        let ident = &variant.ident;
        let tag = items(&variant.attrs, "from_node")?
            .iter()
            .find(|item| item.key == "tag")
            .map(string_of)
            .transpose()?
            .ok_or_else(|| {
                syn::Error::new(
                    variant.span(),
                    "a union variant names its Pydantic tag: #[from_node(tag = \"str\")]",
                )
            })?;
        members.push(quote! {
            ::opentide_schema::from_node::Member {
                tag: #tag,
                strict: <#ty as ::opentide_schema::from_node::FromNode>::takes_strictly,
                convert: |__n: &::opentide_schema::node::Node,
                          __cx: &mut ::opentide_schema::from_node::Context| {
                    <#ty as ::opentide_schema::from_node::FromNode>::from_node(__n, __cx).map(Self::#ident)
                },
            }
        });
    }
    Ok(quote! {
        #[automatically_derived]
        impl ::opentide_schema::from_node::FromNode for #name {
            fn from_node(
                __node: &::opentide_schema::node::Node,
                __cx: &mut ::opentide_schema::from_node::Context,
            ) -> ::core::option::Option<Self> {
                ::opentide_schema::from_node::union_value(__node, __cx, &[#(#members),*])
            }
        }
    })
}
