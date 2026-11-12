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
//! | `#[serde(rename = "x")]` | the key, looked up first |
//! | `#[serde(alias = "y")]` | another key the field takes |
//! | `#[serde(default)]`, `#[serde(default = "path")]` | a missing key is the default, not "Field required" |
//! | `#[serde(rename_all = "...")]` on a unit enum | the variants' values |
//!
//! and its own, `#[from_node(...)]`:
//!
//! | Where | Attribute | Effect |
//! |-------|-----------|--------|
//! | struct | `model = "ThreatBody"` | the model's name in `model_type` messages (default: the Rust name) |
//! | struct | `before = "path"` | `fn(&Node, &mut Context) -> bool`, run first on the raw value; `false` stops |
//! | struct | `tolerate = "PATH"` | a `&[&str]` of keys a closed model does not report (the `__legacy_keys__` pre-pass) |
//! | field | `before = "path"` | the same, on the field's value |
//! | field | `with = "path"` | `fn(&Node, &mut Context) -> Option<T>` converts the field instead of `T: FromNode` |
//! | unit enum | `literal` | the error type `literal_error` rather than `enum` |
//! | enum | `union` | a union of its one-field variants, each with `tag = "str"` |
//!
//! A struct also gets `opentide_schema::from_node::Model`: its class name and
//! each field's attribute and serialised names, in order, which the Python
//! classes read (UC-1.9, #815).
//!
//! serde attributes that change what is read and that the conversion does not
//! reproduce (`flatten`, `skip`, `deserialize_with`, `with`, `untagged` on a
//! non-union, a container `default`, `from`, `try_from`, `transparent`, a
//! struct `rename_all`, a variant's `alias` or `other`) are compile errors, as
//! is an `Option` field without `#[serde(default)]` (serde reads it as `None`
//! when missing), so a model cannot silently read differently under serde and
//! under the conversion.
//!
//! Internal to opentide, with no stability promise: depend on the
//! [`opentide`](https://docs.rs/opentide) crate, its Rust SDK, instead.

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{format_ident, quote};
use syn::{
    Attribute, Data, DeriveInput, Expr, ExprLit, Fields, Lit, LitStr, Meta, Path, Token,
    parse_macro_input, punctuated::Punctuated, spanned::Spanned,
};

/// Derives `opentide_schema::FromNode`. See the crate documentation. It
/// registers `serde` as a helper too, as serde's derives do, so a type that
/// derives only `FromNode` (a test or tooling model) can carry the same
/// attributes.
#[proc_macro_derive(FromNode, attributes(from_node, serde))]
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
/// The serde attributes of a unit variant FromNode cannot reproduce: those
/// of a field, and `alias` (another value serde takes) and `other` (any
/// value serde takes), which would make serde accept a value the
/// conversion refuses.
const SERDE_VARIANT_REFUSED: &[&str] = &[
    "flatten",
    "skip",
    "skip_deserializing",
    "deserialize_with",
    "with",
    "borrow",
    "getter",
    "alias",
    "other",
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
    let mut described = Vec::new();
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
        if is_option(ty) && !field_serde.iter().any(|item| item.key == "default") {
            // serde reads a missing `Option` as `None`; the conversion would
            // report "Field required". Saying which is meant keeps them one.
            return Err(syn::Error::new(
                field.span(),
                "an Option field needs #[serde(default)]: serde reads a missing one as None",
            ));
        }
        let attribute = ident.to_string().trim_start_matches("r#").to_owned();
        let serialised = &names[0];
        described.push(quote!((#attribute, #serialised)));
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
        }

        #[automatically_derived]
        impl ::opentide_schema::from_node::Model for #name {
            const CLASS: &'static str = #class_name;
            const FIELDS: &'static [(&'static str, &'static str)] = &[#(#described),*];
        }
    })
}

/// Whether `ty` is written `Option<...>` (any path ending in `Option`), the
/// type serde reads as `None` when its key is missing.
fn is_option(ty: &syn::Type) -> bool {
    match ty {
        syn::Type::Path(path) if path.qself.is_none() => path
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "Option"),
        syn::Type::Group(group) => is_option(&group.elem),
        syn::Type::Paren(paren) => is_option(&paren.elem),
        _ => false,
    }
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
        refuse(&variant_serde, SERDE_VARIANT_REFUSED)?;
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
                    "a union variant names its tag: #[from_node(tag = \"str\")]",
                )
            })?;
        members.push(quote! {
            ::opentide_schema::from_node::Member {
                tag: #tag,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn expanded(source: &str) -> Result<String, String> {
        let input: DeriveInput = syn::parse_str(source).unwrap();
        expand(&input)
            .map(|tokens| tokens.to_string())
            .map_err(|error| error.to_string())
    }

    #[test]
    fn a_model_takes_names_aliases_defaults_and_closure_from_serde() {
        let code = expanded(
            r#"
            #[serde(deny_unknown_fields)]
            #[from_node(model = "ThreatBody", before = "check", tolerate = "LEGACY")]
            struct Body {
                #[serde(rename = "schema", alias = "schema_id")]
                schema_id: String,
                #[serde(default)]
                tags: Vec<String>,
                #[serde(default = "yes", skip_serializing_if = "Option::is_none")]
                flag: bool,
                #[from_node(before = "vocab", with = "convert")]
                impact: Vec<String>,
                r#type: String,
            }
            "#,
        )
        .unwrap();
        assert!(code.contains("\"ThreatBody\""), "{code}");
        assert!(code.contains("& [\"schema\" , \"schema_id\"]"), "{code}");
        assert!(code.contains("Missing :: Default (yes)"), "{code}");
        assert!(
            code.contains("as :: core :: default :: Default > :: default"),
            "{code}"
        );
        assert!(code.contains("Some (vocab)"), "{code}");
        assert!(code.contains("convert (__n , __cx)"), "{code}");
        assert!(code.contains("if ! check (__node , __cx)"), "{code}");
        assert!(code.contains("finish (__cx , true , LEGACY)"), "{code}");
        assert!(code.contains("& [\"type\"]"), "{code}");
        // The fields as Python reads them: the attribute, then the key.
        assert!(
            code.contains("impl :: opentide_schema :: from_node :: Model for Body"),
            "{code}"
        );
        assert!(
            code.contains(
                "& [(\"schema_id\" , \"schema\") , (\"tags\" , \"tags\") , (\"flag\" , \"flag\") , (\"impact\" , \"impact\") , (\"type\" , \"type\")]"
            ),
            "{code}"
        );
    }

    #[test]
    fn an_option_field_with_a_default_is_accepted() {
        let code = expanded(
            "struct A { #[serde(default)] a: Option<String>, #[serde(default = \"f\")] b: Option<u8> }",
        )
        .unwrap();
        assert!(code.contains("Missing :: Default (f)"), "{code}");
        assert!(!is_option(&syn::parse_str("Vec<Option<u8>>").unwrap()));
        assert!(is_option(
            &syn::parse_str("std::option::Option<u8>").unwrap()
        ));
    }

    #[test]
    fn an_open_model_reports_no_unknown_key() {
        let code = expanded("struct Open { name: String }").unwrap();
        assert!(code.contains("finish (__cx , false , & [])"), "{code}");
        assert!(code.contains("\"Open\""), "{code}");
    }

    #[test]
    fn unit_enums_take_serde_names() {
        let code = expanded(
            r#"
            #[serde(rename_all = "snake_case")]
            #[from_node(literal)]
            enum Kind { FirstOne, #[serde(rename = "other")] Second }
            "#,
        )
        .unwrap();
        assert!(code.contains("(\"first_one\" , 0usize)"), "{code}");
        assert!(code.contains("(\"other\" , 1usize)"), "{code}");
        assert!(code.contains(", true)"), "{code}");
        for (rule, variant, value) in [
            ("lowercase", "FirstOne", "firstone"),
            ("UPPERCASE", "FirstOne", "FIRSTONE"),
            ("kebab-case", "FirstOne", "first-one"),
            ("SCREAMING_SNAKE_CASE", "FirstOne", "FIRST_ONE"),
            ("PascalCase", "FirstOne", "FirstOne"),
        ] {
            assert_eq!(rename(rule, variant, Span::call_site()).unwrap(), value);
        }
        assert!(rename("camelCase", "A", Span::call_site()).is_err());
    }

    #[test]
    fn unions_name_each_members_tag() {
        let code = expanded(
            r#"
            #[serde(untagged)]
            #[from_node(union)]
            enum Either { #[from_node(tag = "str")] Str(String), #[from_node(tag = "int")] Int(i64) }
            "#,
        )
        .unwrap();
        assert!(code.contains("tag : \"str\""), "{code}");
        assert!(code.contains("tag : \"int\""), "{code}");
        assert!(code.contains("union_value"), "{code}");
    }

    #[test]
    fn what_the_conversion_cannot_reproduce_is_refused() {
        for (source, message) in [
            (
                "struct A { #[serde(flatten)] rest: B }",
                "#[serde(flatten)] changes what is read",
            ),
            (
                "struct A { #[serde(deserialize_with = \"f\")] a: B }",
                "#[serde(deserialize_with)] changes what is read",
            ),
            (
                "#[serde(default)] struct A { a: B }",
                "#[serde(default)] changes what is read",
            ),
            (
                "#[serde(rename_all = \"lowercase\")] struct A { a: B }",
                "#[serde(rename_all)] on a model",
            ),
            ("struct A<T> { a: T }", "one struct per revision"),
            ("struct A(String);", "a FromNode model has named fields"),
            ("union A { a: u8 }", "FromNode is for structs and enums"),
            (
                "#[serde(untagged)] enum A { B(String) }",
                "an untagged enum is a union",
            ),
            ("enum A { B(String) }", "a FromNode enum has unit variants"),
            ("#[from_node(union)] enum A { B(String) }", "names its tag"),
            (
                "#[from_node(union)] enum A { B { x: u8 } }",
                "a union variant holds one value",
            ),
            (
                "#[from_node(union)] enum A { #[from_node(tag = \"x\")] B(u8, u8) }",
                "a union variant holds one value",
            ),
            (
                "#[from_node(union, literal)] enum A { B(u8) }",
                "unknown #[from_node(literal)] on a union",
            ),
            (
                "#[from_node(colour)] struct A { a: B }",
                "unknown #[from_node(colour)] on a struct",
            ),
            (
                "#[from_node(colour)] enum A { B }",
                "unknown #[from_node(colour)] on an enum",
            ),
            (
                "struct A { #[from_node(colour)] a: B }",
                "unknown #[from_node(colour)] on a field",
            ),
            (
                "struct A { #[serde(rename(deserialize = \"x\"))] a: B }",
                "is not supported by FromNode",
            ),
            (
                "struct A { #[serde(rename = 3)] a: B }",
                "only a string literal is supported",
            ),
            (
                "#[from_node(model)] struct A { a: B }",
                "model needs a string",
            ),
            (
                "#[from_node(before)] struct A { a: B }",
                "before needs a path",
            ),
            (
                "enum A { #[serde(alias = \"b\")] B }",
                "#[serde(alias)] changes what is read",
            ),
            (
                "enum A { B, #[serde(other)] Rest }",
                "#[serde(other)] changes what is read",
            ),
            (
                "struct A { a: Option<String> }",
                "an Option field needs #[serde(default)]",
            ),
            (
                "struct A { a: ::core::option::Option<u8> }",
                "an Option field needs #[serde(default)]",
            ),
        ] {
            let error = expanded(source).unwrap_err();
            assert!(error.contains(message), "{source}: {error}");
        }
    }
}
