"""Good and bad documents for every schema in release/schema/ (docs/CONTRACT.md §6, area release).

Good documents live in tests/release/fixtures/schema/<schema>/good-*.json; bad ones
are single, named mutations of a good document (each breaks exactly one rule).
Every case is checked with release/lib/schema.py and, when the `jsonschema`
package is importable (ansible-lint venv, pip), also with the reference
validator — both must agree.

Usage: python3 tests/release/test_schemas.py [--reference-python PATH]
"""

from __future__ import annotations

import copy
import glob
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(REPO, "release", "lib"))
import schema  # noqa: E402

FIX = os.path.join(HERE, "fixtures", "schema")


def load(rel):
    with open(os.path.join(FIX, rel), encoding="utf-8") as f:
        return json.load(f)


def mutate(base, fn):
    doc = copy.deepcopy(load(base))
    fn(doc)
    return doc


def set_(path, value):
    def fn(doc):
        node = doc
        for p in path[:-1]:
            node = node[p]
        node[path[-1]] = value
    return fn


def del_(path):
    def fn(doc):
        node = doc
        for p in path[:-1]:
            node = node[p]
        del node[path[-1]]
    return fn


M, S = "manifest/good-feature.json", "manifest/good-security.json"
I = "index/good-index.json"
E, ST = "promotion/good-early.json", "promotion/good-stable.json"
A = "attestation/good-pass.json"
P = "policy/good-prod.json"

BAD = {
    "manifest": [
        ("missing sequence", M, del_(["sequence"])),
        ("security without advisories", S, set_(["advisories"], [])),
        ("channels without canary", M, set_(["channels"], ["early", "stable"])),
        ("unknown top-level property", M, set_(["requires_approval"], True)),
        ("artifact name with directory", M, set_(["artifacts", 3, "name"], "images/app.tar")),
        ("artifact name traversal", M, set_(["artifacts", 3, "name"], "../etc")),
        ("config artifact without files", M, del_(["artifacts", 1, "files"])),
        ("config file path traversal", M, set_(["artifacts", 1, "files", 0, "path"], "../../etc/shadow")),
        ("config file absolute path", M, set_(["artifacts", 1, "files", 0, "path"], "/etc/nftables.conf")),
        ("config applier outside allowlist", M, set_(["artifacts", 1, "files", 0, "applier"], "nftables")),
        ("binary outside allowlist", M, set_(["artifacts", 0, "binaries", 0, "name"], "restic")),
        ("binary artifact without binaries", M, del_(["artifacts", 0, "binaries"])),
        ("deb outside allowlist", M, set_(["artifacts", 2, "packages", 0, "name"], "openssh-server")),
        ("oci-archive carrying packages", M, set_(["artifacts", 3, "packages"], [{"name": "headscale", "version": "1", "sha256": "a" * 64}])),
        ("worker-bundle without worker", M, del_(["artifacts", 7, "worker"])),
        ("artifact sha256 uppercase", M, set_(["artifacts", 3, "sha256"], "A" * 64)),
        ("artifact size zero", M, set_(["artifacts", 3, "size"], 0)),
        ("no artifacts", M, set_(["artifacts"], [])),
        ("image digest without algorithm", M, set_(["images", 0, "digest"], "c" * 64)),
        ("image for arm64", M, set_(["images", 0, "platform"], "linux/arm64")),
        ("image ref without tag", M, set_(["images", 0, "ref"], "ghcr.io/jakublog/legatto/app")),
        ("n_minus_1_compatible false", M, set_(["migrations", "n_minus_1_compatible"], False)),
        ("migration name pattern", M, set_(["migrations", "files", 0, "name"], "add_tags.sql")),
        ("rollback with database", M, set_(["rollback"], "requires-db-restore")),
        ("egress IP literal", M, set_(["egress", "roles", "host", 0, "host"], "203.0.113.7")),
        ("egress port 22", M, set_(["egress", "roles", "host", 0, "port"], 22)),
        ("egress unknown role", M, set_(["egress", "roles", "root"], [])),
        ("egress unknown feature", M, set_(["egress", "features", "telemetry"], {})),
        ("egress double wildcard", M, set_(["egress", "roles", "host", 0, "host"], "*.*.legatto.pl")),
        ("egress duplicate entry", M, lambda d: d["egress"]["roles"]["host"].append(dict(d["egress"]["roles"]["host"][0]))),
        ("changelog over http", M, set_(["changelog_url"], "http://updates.legatto.pl/v1/notes.md")),
        ("released_at with offset", M, set_(["released_at"], "2026-11-21T10:00:00+01:00")),
        ("version not semver", M, set_(["version"], "1.5")),
        ("sequence zero", M, set_(["sequence"], 0)),
        ("min_contract_version zero", M, set_(["min_contract_version"], 0)),
        ("healthcheck arbitrary command", M, set_(["healthchecks"], ["shell:curl evil"])),
        ("no healthchecks", M, set_(["healthchecks"], [])),
        ("cron outside /api/cron", M, set_(["crons", 0, "path"], "/api/admin/export")),
        ("sbom format unknown", M, set_(["sbom", 0, "format"], "syft-json")),
        ("source repo outside github", M, set_(["source", "node", "repo"], "gitlab.com/x/y")),
        ("source without the node commit", M, del_(["source", "node"])),
        ("source with an unknown repository", M, set_(["source", "infra"], {"repo": "github.com/x/y", "commit": "a" * 40})),
        ("source commit short", M, set_(["source", "app", "commit"], "abc123")),
        ("advisory severity unknown", S, set_(["advisories", 0, "severity"], "urgent")),
        ("sequence as string", M, set_(["sequence"], "12")),
        ("sequence as boolean", M, set_(["sequence"], True)),
    ],
    "index": [
        ("missing expires", I, del_(["expires"])),
        ("expires not UTC Z", I, set_(["expires"], "2026-12-26 12:00:00")),
        ("sequence zero", I, set_(["sequence"], 0)),
        ("yanked without reason", I, del_(["releases", 1, "yanked_reason"])),
        ("promotions without stable", I, del_(["releases", 0, "promotions", "stable"])),
        ("promotion to canary", I, set_(["releases", 0, "promotions", "canary"], None)),
        ("manifest sha256 short", I, set_(["releases", 0, "manifest_sha256"], "abc")),
        ("krl sha256 invalid", I, set_(["krl_sha256"], "zz")),
        ("missing krl_sha256", I, del_(["krl_sha256"])),
        ("release type unknown", I, set_(["releases", 0, "type"], "hotfix")),
        ("wrong schema id", I, set_(["schema"], "legatto-index/2")),
        ("unknown property", I, set_(["signature"], "x")),
    ],
    "promotion": [
        ("stable without early_promotion_sha256", ST, del_(["early_promotion_sha256"])),
        ("early with early_promotion_sha256", E, set_(["early_promotion_sha256"], "c" * 64)),
        ("channel canary", E, set_(["channel"], "canary")),
        ("manifest sha256 uppercase", E, set_(["manifest_sha256"], "A" * 64)),
        ("missing canary attestation", E, del_(["canary_attestation_sha256"])),
        ("promoted_at not a timestamp", E, set_(["promoted_at"], "jutro")),
        ("note too long", ST, set_(["note"], "x" * 501)),
        ("legacy field ring", E, set_(["ring"], "early")),
    ],
    "attestation": [
        ("FAIL without failed_checks", A, set_(["result"], "FAIL")),
        ("FAIL with empty failed_checks", A, lambda d: d.update(result="FAIL", failed_checks=[])),
        ("result OK", A, set_(["result"], "OK")),
        ("canary slug uppercase", A, set_(["canary"], "Canary")),
        ("missing verify_report_sha256", A, del_(["verify_report_sha256"])),
        ("wrong product", A, set_(["product"], "other")),
    ],
    "policy": [
        ("prod with mirror URL", P, set_(["update_base_url"], "https://mirror.example.com/v1")),
        ("prod over http", P, set_(["update_base_url"], "http://updates.legatto.pl/v1")),
        ("feature early below 24 h", P, set_(["min_delay_hours", "feature", "early"], 12)),
        ("security stable below 4 h", P, set_(["min_delay_hours", "security", "stable"], 3)),
        ("timezone UTC", P, set_(["timezone"], "UTC")),
        ("signatures_required zero", P, set_(["signatures_required"], 0)),
        ("index validity 90 days", P, set_(["index_max_validity_days"], 90)),
        ("clock jump 120 min", P, set_(["clock_jump_block_minutes"], 120)),
        ("install window 24:00", P, set_(["install_window", "start"], "24:00")),
        ("keep one release", P, set_(["keep_releases"], 1)),
        ("env staging", P, set_(["env"], "staging")),
    ],
}


def reference_validator(python):
    """Return f(schema_name, doc) -> bool using python-jsonschema in `python`, or None."""
    if not python:
        return None
    probe = subprocess.run([python, "-c", "import jsonschema"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if probe.returncode != 0:
        return None
    code = (
        "import json,sys,jsonschema\n"
        "cases=json.load(sys.stdin)\n"
        "out=[]\n"
        "for s,d in cases:\n"
        "    v=jsonschema.Draft202012Validator(s)\n"
        "    out.append(not list(v.iter_errors(d)))\n"
        "print(json.dumps(out))\n"
    )

    def run(cases):
        payload = json.dumps([[schema.load_schema(n), d] for n, d in cases]).encode()
        res = subprocess.run([python, "-c", code], input=payload, stdout=subprocess.PIPE, check=True)
        return json.loads(res.stdout)

    return run


def main(argv):
    ref_python = argv[1] if len(argv) == 2 and argv[0] == "--reference-python" else None
    failures = []
    cases = []  # (schema, description, doc, expected_valid)
    for name in schema.SCHEMA_FILES:
        goods = sorted(glob.glob(os.path.join(FIX, name, "good-*.json")))
        if not goods:
            failures.append("%s: no good fixture" % name)
        for path in goods:
            with open(path, encoding="utf-8") as f:
                cases.append((name, os.path.relpath(path, FIX), json.load(f), True))
        if not BAD.get(name):
            failures.append("%s: no bad cases" % name)
        for desc, base, fn in BAD.get(name, []):
            cases.append((name, "%s: %s" % (name, desc), mutate(base, fn), False))

    for name, desc, doc, expected in cases:
        errors = schema.validate(name, doc)
        if (not errors) != expected:
            failures.append("schema.py %s: expected %s, got %s %s" % (
                desc, "valid" if expected else "invalid", "valid" if not errors else "invalid", errors[:3]))

    ref = reference_validator(ref_python)
    if ref is None:
        print("reference jsonschema: not available (%s) — cross-check skipped" % (ref_python or "no interpreter"))
    else:
        verdicts = ref([(n, d) for n, _, d, _ in cases])
        for (name, desc, doc, expected), ok in zip(cases, verdicts):
            if ok != expected:
                failures.append("jsonschema %s: expected %s, got %s" % (desc, "valid" if expected else "invalid",
                                                                         "valid" if ok else "invalid"))
        print("reference jsonschema: %d cases cross-checked" % len(cases))

    for f in failures:
        print("FAIL " + f)
    print("schemas: %d cases, %d failures" % (len(cases), len(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
