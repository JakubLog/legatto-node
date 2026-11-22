"""Zero-address guard for the generated public site (runs on the host after
the network-less build and before anything is uploaded to Cloudflare Pages).

The public site must not reveal where the office lives: no tailnet-only host
names (vpn./app./admin.app./studio.app./tn.), no server addresses (public
IPv4, tailnet IPv4/IPv6 or anything in the tailnet prefixes), no Supabase
endpoints or keys, and nothing that would turn the static upload into Pages
Functions. Findings name the file and the rule, never the matched text.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path

MAX_FILES = 20_000  # Cloudflare Pages limit per deployment
MAX_FILE_BYTES = 25 * 1024 * 1024
TAILNET_V4 = ipaddress.ip_network("100.64.0.0/10")  # contract: legatto_tailnet_prefix_v4
TAILNET_V6_PREFIX = "fd7a:115c:a1e0:"  # first 48 bits of legatto_tailnet_prefix_v6 (checked by tests/publicsite)
FORBIDDEN_TOP = {"_worker.js", "functions", "_routes.json"}

_IPV4_RE = re.compile(rb"(?<![0-9.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![0-9])")
_STATIC_RULES: list[tuple[str, re.Pattern[bytes]]] = [
    ("supabase-rest", re.compile(rb"/(rest|storage|functions|auth|realtime|graphql)/v1\b", re.I)),
    ("supabase-name", re.compile(rb"supabase", re.I)),
    ("jwt", re.compile(rb"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")),
    ("tailnet-v6", re.compile(re.escape(TAILNET_V6_PREFIX.encode()), re.I)),
]


@dataclass(frozen=True)
class Finding:
    file: str
    rule: str


def office_rules(env: dict[str, str]) -> list[tuple[str, re.Pattern[bytes]]]:
    """Literal patterns for this office, built from /etc/legatto/office.env."""
    domain = env["LEGATTO_OFFICE_DOMAIN"].lower()
    hosts = {
        "host-vpn": env["LEGATTO_HOST_VPN"],
        "host-crm": env["LEGATTO_HOST_CRM"],
        "host-admin": env["LEGATTO_HOST_ADMIN"],
        "host-studio": env["LEGATTO_HOST_STUDIO"],
        "host-magicdns": f"tn.{domain}",  # contract: legatto_magicdns_base_domain
    }
    rules: list[tuple[str, re.Pattern[bytes]]] = []
    for rule, host in hosts.items():
        # Host name as a whole label sequence (not a suffix of a longer name).
        rules.append((rule, re.compile(rb"(?<![A-Za-z0-9-])" + re.escape(host.lower().encode()) + rb"(?![A-Za-z0-9-])", re.I)))
    for rule, key in (("ip-public", "LEGATTO_PUBLIC_IPV4"), ("ip-tailnet4", "LEGATTO_TS_IP4")):
        rules.append((rule, re.compile(rb"(?<![0-9.])" + re.escape(env[key].encode()) + rb"(?![0-9])")))
    ip6 = ipaddress.ip_address(env["LEGATTO_TS_IP6"])
    for form in {ip6.compressed, ip6.exploded}:
        rules.append(("ip-tailnet6", re.compile(re.escape(form.encode()), re.I)))
    return rules


def _tailnet_v4(data: bytes) -> bool:
    for match in _IPV4_RE.finditer(data):
        octets = [int(x) for x in match.groups()]
        if all(o <= 255 for o in octets) and ipaddress.ip_address(".".join(map(str, octets))) in TAILNET_V4:
            return True
    return False


def scan(root: Path, env: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    if not root.is_dir():
        return [Finding(".", "missing-output")]
    for name in sorted(FORBIDDEN_TOP):
        if (root / name).exists() or (root / name).is_symlink():
            findings.append(Finding(name, "pages-functions"))
    rules = _STATIC_RULES + office_rules(env)
    count = 0
    for entry in sorted(root.rglob("*")):
        rel = entry.relative_to(root).as_posix()
        if entry.is_symlink():
            findings.append(Finding(rel, "symlink"))
            continue
        if entry.is_dir():
            continue
        if not entry.is_file():
            findings.append(Finding(rel, "special-file"))
            continue
        count += 1
        if entry.stat().st_size > MAX_FILE_BYTES:
            findings.append(Finding(rel, "file-too-large"))
            continue
        data = entry.read_bytes()
        candidates = [data, rel.encode()]
        for rule, pattern in rules:
            if any(pattern.search(blob) for blob in candidates):
                findings.append(Finding(rel, rule))
        if _tailnet_v4(data):
            findings.append(Finding(rel, "tailnet-v4"))
    if count > MAX_FILES:
        findings.append(Finding(".", "too-many-files"))
    return findings
