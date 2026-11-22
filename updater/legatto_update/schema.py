"""JSON Schema 2020-12 validation for the release documents.

Python stdlib only (no jsonschema on the server). Supports exactly the
keywords used by release/schema/*.json; a schema with any other keyword is
refused (SchemaError) so the validator can never silently ignore a rule.
"""

import datetime as _dt
import json
import os
import re

ANNOTATIONS = {"$schema", "$id", "title", "description", "$defs", "$comment"}
SUPPORTED = ANNOTATIONS | {
    "type", "const", "enum", "pattern", "minimum", "maximum", "minLength", "maxLength", "minItems",
    "maxItems", "uniqueItems", "contains", "items", "properties", "additionalProperties", "required",
    "propertyNames", "oneOf", "anyOf", "allOf", "if", "then", "else", "not", "$ref", "format",
}

SCHEMA_FILES = {
    "manifest": "manifest.schema.json",
    "promotion": "promotion.schema.json",
    "attestation": "attestation.schema.json",
    "index": "index.schema.json",
    "policy": "policy.schema.json",
}


class SchemaError(Exception):
    pass


def schema_dir() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    installed = os.path.join(here, "schema")
    if os.path.isdir(installed):
        return installed
    return os.path.normpath(os.path.join(here, "..", "..", "release", "schema"))


_CACHE: dict = {}


def load(kind: str) -> dict:
    if kind not in _CACHE:
        with open(os.path.join(schema_dir(), SCHEMA_FILES[kind]), encoding="utf-8") as fh:
            schema = json.load(fh)
        check_keywords(schema)
        _CACHE[kind] = schema
    return _CACHE[kind]


def check_keywords(node) -> None:
    """Refuse schemas that use keywords this validator does not implement."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key not in SUPPORTED:
                raise SchemaError("unsupported schema keyword: %s" % key)
            if key in ("properties", "$defs"):
                for sub in value.values():
                    check_keywords(sub)
            elif key in ("enum", "const", "required", "type"):
                continue
            elif key in ("items", "additionalProperties", "contains", "propertyNames", "if", "then",
                         "else", "not"):
                if isinstance(value, dict):
                    check_keywords(value)
            elif key in ("oneOf", "anyOf", "allOf"):
                for sub in value:
                    check_keywords(sub)


def validate(kind: str, instance) -> list:
    schema = load(kind)
    errors: list = []
    _validate(instance, schema, schema, "$", errors)
    return errors


def _type_ok(value, name: str) -> bool:
    if name == "object":
        return isinstance(value, dict)
    if name == "array":
        return isinstance(value, list)
    if name == "string":
        return isinstance(value, str)
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if name == "boolean":
        return isinstance(value, bool)
    if name == "null":
        return value is None
    raise SchemaError("unknown type %s" % name)


def _canon(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _format_ok(value: str, fmt: str) -> bool:
    if fmt == "date-time":
        try:
            _dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
            return True
        except ValueError:
            return False
    if fmt == "uri":
        return re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:[^\s]+$", value) is not None
    raise SchemaError("unsupported format %s" % fmt)


def _resolve(root: dict, ref: str) -> dict:
    if not ref.startswith("#/"):
        raise SchemaError("only local $ref is supported: %s" % ref)
    node = root
    for part in ref[2:].split("/"):
        node = node[part]
    return node


def _valid(instance, schema, root) -> bool:
    errs: list = []
    _validate(instance, schema, root, "$", errs)
    return not errs


def _validate(inst, schema, root, path, errors) -> None:  # noqa: C901 - one switch per keyword
    if schema is True:
        return
    if schema is False:
        errors.append("%s: not allowed" % path)
        return
    if "$ref" in schema:
        _validate(inst, _resolve(root, schema["$ref"]), root, path, errors)
    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_type_ok(inst, t) for t in types):
            errors.append("%s: expected %s" % (path, "/".join(types)))
            return
    if "const" in schema and _canon(inst) != _canon(schema["const"]):
        errors.append("%s: must be %s" % (path, _canon(schema["const"])))
    if "enum" in schema and _canon(inst) not in {_canon(v) for v in schema["enum"]}:
        errors.append("%s: not in enum" % path)
    if isinstance(inst, str):
        if "pattern" in schema and re.search(schema["pattern"], inst) is None:
            errors.append("%s: does not match pattern" % path)
        if "minLength" in schema and len(inst) < schema["minLength"]:
            errors.append("%s: too short" % path)
        if "maxLength" in schema and len(inst) > schema["maxLength"]:
            errors.append("%s: too long" % path)
        if "format" in schema and not _format_ok(inst, schema["format"]):
            errors.append("%s: bad %s" % (path, schema["format"]))
    if _type_ok(inst, "number"):
        if "minimum" in schema and inst < schema["minimum"]:
            errors.append("%s: below minimum" % path)
        if "maximum" in schema and inst > schema["maximum"]:
            errors.append("%s: above maximum" % path)
    if isinstance(inst, list):
        if "minItems" in schema and len(inst) < schema["minItems"]:
            errors.append("%s: too few items" % path)
        if "maxItems" in schema and len(inst) > schema["maxItems"]:
            errors.append("%s: too many items" % path)
        if schema.get("uniqueItems") and len({_canon(v) for v in inst}) != len(inst):
            errors.append("%s: items not unique" % path)
        if "items" in schema:
            for i, item in enumerate(inst):
                _validate(item, schema["items"], root, "%s[%d]" % (path, i), errors)
        if "contains" in schema and not any(_valid(item, schema["contains"], root) for item in inst):
            errors.append("%s: contains not satisfied" % path)
    if isinstance(inst, dict):
        for key in schema.get("required", []):
            if key not in inst:
                errors.append("%s: missing %s" % (path, key))
        props = schema.get("properties", {})
        for key, value in inst.items():
            if key in props:
                _validate(value, props[key], root, "%s.%s" % (path, key), errors)
            elif "additionalProperties" in schema:
                _validate(value, schema["additionalProperties"], root, "%s.%s" % (path, key), errors)
            if "propertyNames" in schema:
                _validate(key, schema["propertyNames"], root, "%s{%s}" % (path, key), errors)
    if "allOf" in schema:
        for sub in schema["allOf"]:
            _validate(inst, sub, root, path, errors)
    if "anyOf" in schema and not any(_valid(inst, sub, root) for sub in schema["anyOf"]):
        errors.append("%s: anyOf not satisfied" % path)
    if "oneOf" in schema:
        matches = sum(1 for sub in schema["oneOf"] if _valid(inst, sub, root))
        if matches != 1:
            errors.append("%s: oneOf matched %d" % (path, matches))
    if "not" in schema and _valid(inst, schema["not"], root):
        errors.append("%s: matches forbidden schema" % path)
    if "if" in schema:
        if _valid(inst, schema["if"], root):
            if "then" in schema:
                _validate(inst, schema["then"], root, path, errors)
        elif "else" in schema:
            _validate(inst, schema["else"], root, path, errors)
