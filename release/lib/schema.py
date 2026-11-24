"""Minimal JSON Schema 2020-12 validator (Python stdlib only).

Covers exactly the keywords used by release/schema/*.json. An unknown keyword
is an error, so a schema change that needs more support fails loudly instead
of being silently ignored. tests/ci cross-checks results with the reference
`jsonschema` package when it is importable.
"""

from __future__ import annotations

import json
import os
import re
import sys
from typing import Any, Dict, List

SCHEMA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "schema")
SCHEMA_FILES = {
    "manifest": "manifest.schema.json",
    "index": "index.schema.json",
    "promotion": "promotion.schema.json",
    "attestation": "attestation.schema.json",
    "policy": "policy.schema.json",
}

# Annotations and structural keywords without assertions.
_IGNORED = {"$schema", "$id", "title", "description", "$defs", "format", "default", "examples", "$comment"}
_KNOWN = _IGNORED | {
    "$ref", "type", "const", "enum", "pattern", "minLength", "maxLength", "minimum", "maximum",
    "required", "properties", "additionalProperties", "propertyNames", "items", "minItems", "maxItems",
    "uniqueItems", "contains", "oneOf", "anyOf", "allOf", "not", "if", "then", "else",
}


class SchemaError(Exception):
    """The schema itself uses something this validator does not implement."""


def _json_equal(a: Any, b: Any) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(_json_equal(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(_json_equal(x, y) for x, y in zip(a, b))
    return a == b


def _is_type(value: Any, name: str) -> bool:
    if name == "null":
        return value is None
    if name == "boolean":
        return isinstance(value, bool)
    if name == "integer":
        return (isinstance(value, int) and not isinstance(value, bool)) or (
            isinstance(value, float) and value.is_integer())
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if name == "string":
        return isinstance(value, str)
    if name == "array":
        return isinstance(value, list)
    if name == "object":
        return isinstance(value, dict)
    raise SchemaError("unknown type %r" % name)


class Validator:
    def __init__(self, schema: Dict[str, Any]):
        self.root = schema

    def _resolve(self, ref: str) -> Any:
        if not ref.startswith("#/"):
            raise SchemaError("only local $ref supported: %r" % ref)
        node: Any = self.root
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            node = node[part]
        return node

    def errors(self, instance: Any) -> List[str]:
        out: List[str] = []
        self._validate(instance, self.root, "$", out)
        return out

    def _validate(self, inst: Any, schema: Any, path: str, out: List[str]) -> None:
        if schema is True:
            return
        if schema is False:
            out.append("%s: not allowed" % path)
            return
        unknown = set(schema) - _KNOWN
        if unknown:
            raise SchemaError("unsupported keywords at %s: %s" % (path, ", ".join(sorted(unknown))))

        if "$ref" in schema:
            self._validate(inst, self._resolve(schema["$ref"]), path, out)

        if "type" in schema:
            types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
            if not any(_is_type(inst, t) for t in types):
                out.append("%s: expected %s" % (path, " or ".join(types)))
                return
        if "const" in schema and not _json_equal(inst, schema["const"]):
            out.append("%s: must be %s" % (path, json.dumps(schema["const"])))
        if "enum" in schema and not any(_json_equal(inst, e) for e in schema["enum"]):
            out.append("%s: must be one of %s" % (path, json.dumps(schema["enum"])))

        if isinstance(inst, str):
            if "pattern" in schema and re.search(schema["pattern"], inst) is None:
                out.append("%s: %r does not match %s" % (path, inst[:80], schema["pattern"]))
            if "minLength" in schema and len(inst) < schema["minLength"]:
                out.append("%s: shorter than %d" % (path, schema["minLength"]))
            if "maxLength" in schema and len(inst) > schema["maxLength"]:
                out.append("%s: longer than %d" % (path, schema["maxLength"]))

        if _is_type(inst, "number"):
            if "minimum" in schema and inst < schema["minimum"]:
                out.append("%s: below minimum %s" % (path, schema["minimum"]))
            if "maximum" in schema and inst > schema["maximum"]:
                out.append("%s: above maximum %s" % (path, schema["maximum"]))

        if isinstance(inst, dict):
            for key in schema.get("required", []):
                if key not in inst:
                    out.append("%s: missing required property %r" % (path, key))
            props = schema.get("properties", {})
            for key, value in inst.items():
                sub = "%s.%s" % (path, key)
                if "propertyNames" in schema:
                    self._validate(key, schema["propertyNames"], sub + " (name)", out)
                if key in props:
                    self._validate(value, props[key], sub, out)
                elif "additionalProperties" in schema:
                    ap = schema["additionalProperties"]
                    if ap is False:
                        out.append("%s: additional property not allowed" % sub)
                    else:
                        self._validate(value, ap, sub, out)

        if isinstance(inst, list):
            if "minItems" in schema and len(inst) < schema["minItems"]:
                out.append("%s: fewer than %d items" % (path, schema["minItems"]))
            if "maxItems" in schema and len(inst) > schema["maxItems"]:
                out.append("%s: more than %d items" % (path, schema["maxItems"]))
            if schema.get("uniqueItems"):
                for i in range(len(inst)):
                    if any(_json_equal(inst[i], inst[j]) for j in range(i)):
                        out.append("%s[%d]: duplicate item" % (path, i))
            if "items" in schema:
                for i, item in enumerate(inst):
                    self._validate(item, schema["items"], "%s[%d]" % (path, i), out)
            if "contains" in schema and not any(self._ok(item, schema["contains"]) for item in inst):
                out.append("%s: no item matches 'contains'" % path)

        for sub in schema.get("allOf", []):
            self._validate(inst, sub, path, out)
        if "anyOf" in schema and not any(self._ok(inst, s) for s in schema["anyOf"]):
            out.append("%s: matches none of anyOf" % path)
        if "oneOf" in schema:
            n = sum(1 for s in schema["oneOf"] if self._ok(inst, s))
            if n != 1:
                out.append("%s: matches %d of oneOf (exactly 1 required)" % (path, n))
        if "not" in schema and self._ok(inst, schema["not"]):
            out.append("%s: matches a forbidden schema ('not')" % path)
        if "if" in schema:
            branch = "then" if self._ok(inst, schema["if"]) else "else"
            if branch in schema:
                self._validate(inst, schema[branch], path, out)

    def _ok(self, inst: Any, schema: Any) -> bool:
        errs: List[str] = []
        self._validate(inst, schema, "$", errs)
        return not errs


_CACHE: Dict[str, Validator] = {}


def load_schema(name: str) -> Dict[str, Any]:
    if name not in SCHEMA_FILES:
        raise SchemaError("unknown schema %r (one of %s)" % (name, ", ".join(sorted(SCHEMA_FILES))))
    with open(os.path.join(SCHEMA_DIR, SCHEMA_FILES[name]), encoding="utf-8") as f:
        return json.load(f)


def validate(name: str, document: Any) -> List[str]:
    """Return a list of error strings (empty = valid) for document against schema `name`."""
    if name not in _CACHE:
        _CACHE[name] = Validator(load_schema(name))
    return _CACHE[name].errors(document)


def main(argv: List[str]) -> int:
    if len(argv) != 3:
        print("usage: schema.py <%s> FILE" % "|".join(sorted(SCHEMA_FILES)), file=sys.stderr)
        return 2
    with open(argv[2], encoding="utf-8") as f:
        doc = json.load(f)
    errs = validate(argv[1], doc)
    for e in errs:
        print("%s: %s" % (argv[2], e), file=sys.stderr)
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
