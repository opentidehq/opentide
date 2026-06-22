"""Lightweight JSON Schema helpers without Engines dependencies."""

from __future__ import annotations


def strip_framework_keywords(dictionary: dict) -> dict:
    """Remove ``tide.*`` keys recursively from a metaschema-derived dict."""
    dict_foo = dictionary.copy()
    for field in dict_foo:
        if field.startswith("tide."):
            del dictionary[field]
        elif isinstance(dict_foo[field], dict):
            strip_framework_keywords(dictionary[field])
    return dictionary
