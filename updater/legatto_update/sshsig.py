"""sshsig verification with the OpenSSH shipped by Ubuntu (section 4.7).

For every <document>.<signer-id>.sig:
  1. parse the armored signature (namespace, public key) in Python;
  2. reject keys listed in any trusted KRL (`ssh-keygen -Q -f <krl>`);
  3. `ssh-keygen -Y find-principals` against allowed_signers;
  4. `ssh-keygen -Y verify -I <principal> -n <namespace>` for the principal
     whose local part equals <signer-id>.
A document is accepted when signatures from at least `required` distinct
principals AND distinct keys verified.
"""

import base64
import hashlib
import os
import re
import struct
import tempfile

from .host import CommandError

SIG_BEGIN = b"-----BEGIN SSH SIGNATURE-----"
SIG_END = b"-----END SSH SIGNATURE-----"
SIGNER_ID_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,62}$")


class SigFormatError(Exception):
    pass


def _read_string(buf: bytes, off: int):
    if off + 4 > len(buf):
        raise SigFormatError("truncated")
    (length,) = struct.unpack(">I", buf[off:off + 4])
    off += 4
    if off + length > len(buf):
        raise SigFormatError("truncated")
    return buf[off:off + length], off + length


def parse_signature(armored: bytes):
    """Return (key_type, public_key_blob, namespace) of an sshsig blob."""
    text = armored.strip()
    if not text.startswith(SIG_BEGIN) or not text.endswith(SIG_END):
        raise SigFormatError("not an SSH signature")
    body = b"".join(text[len(SIG_BEGIN):-len(SIG_END)].split())
    try:
        raw = base64.b64decode(body, validate=True)
    except ValueError as exc:
        raise SigFormatError("bad base64") from exc
    if raw[:6] != b"SSHSIG":
        raise SigFormatError("bad magic")
    if len(raw) < 10 or struct.unpack(">I", raw[6:10])[0] != 1:
        raise SigFormatError("unsupported version")
    pubkey, off = _read_string(raw, 10)
    namespace, off = _read_string(raw, off)
    _reserved, off = _read_string(raw, off)
    _hash_alg, off = _read_string(raw, off)
    _sig, off = _read_string(raw, off)
    if off != len(raw):
        raise SigFormatError("trailing data")
    key_type, _ = _read_string(pubkey, 0)
    return key_type.decode("ascii", "replace"), pubkey, namespace.decode("utf-8", "replace")


def fingerprint(pubkey_blob: bytes) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(pubkey_blob).digest()).decode().rstrip("=")


def _split_options(text: str):
    """Split the options field of allowed_signers on commas outside quotes."""
    out, cur, quoted = [], "", False
    for ch in text:
        if ch == '"':
            quoted = not quoted
        if ch == "," and not quoted:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur:
        out.append(cur)
    return out


def parse_allowed_signers(path: str) -> list:
    """Entries: {"principals": [...], "namespaces": [...] | None}."""
    entries = []
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split()
            principals = fields[0].split(",")
            namespaces = None
            if len(fields) > 2 and not fields[1].startswith(("ssh-", "sk-", "ecdsa-")):
                for opt in _split_options(fields[1]):
                    name, _, value = opt.partition("=")
                    if name.lower() == "namespaces":
                        namespaces = [n.strip() for n in value.strip('"').split(",") if n.strip()]
            entries.append({"principals": principals, "namespaces": namespaces})
    return entries


def signer_ids(allowed_signers: str, namespace: str) -> list:
    """Signer ids (local part of principals) that may sign in `namespace`."""
    ids = []
    for entry in parse_allowed_signers(allowed_signers):
        if entry["namespaces"] is not None and namespace not in entry["namespaces"]:
            continue
        for principal in entry["principals"]:
            local = principal.split("@", 1)[0]
            if SIGNER_ID_RE.match(local) and local not in ids:
                ids.append(local)
    return ids


class Verifier:
    def __init__(self, host, allowed_signers: str, krls: list):
        self.host = host
        self.allowed_signers = allowed_signers
        self.krls = list(krls)

    def key_revoked(self, key_type: str, blob: bytes) -> bool:
        if not self.krls:
            return False
        with tempfile.NamedTemporaryFile("w", suffix=".pub", delete=False) as fh:
            fh.write("%s %s\n" % (key_type, base64.b64encode(blob).decode()))
            pub = fh.name
        try:
            for krl in self.krls:
                rc, _out, _err = self.host.run(["ssh-keygen", "-Q", "-f", krl, pub], check=False, timeout=30)
                if rc != 0:
                    # 1 = revoked, anything else = unreadable KRL: fail closed.
                    return True
            return False
        finally:
            os.unlink(pub)

    def verify(self, document: bytes, sigs: dict, namespace: str, required: int, allowed_principals) -> dict:
        """sigs: {signer_id: armored bytes}. Only principals in `allowed_principals` count.
        Returns a result dict (never raises on bad input)."""
        principals, keys, errors = [], [], []
        with tempfile.TemporaryDirectory(prefix="legatto-sig-") as tmp:
            for signer_id, armored in sorted(sigs.items()):
                tag = "%s.sig" % signer_id
                try:
                    key_type, blob, sig_ns = parse_signature(armored)
                except SigFormatError as exc:
                    errors.append("%s: %s" % (tag, exc))
                    continue
                if sig_ns != namespace:
                    errors.append("%s: namespace %s != %s" % (tag, sig_ns, namespace))
                    continue
                if self.key_revoked(key_type, blob):
                    errors.append("%s: key revoked (KRL)" % tag)
                    continue
                sig_path = os.path.join(tmp, tag)
                with open(sig_path, "wb") as fh:
                    fh.write(armored)
                rc, out, _err = self.host.run(
                    ["ssh-keygen", "-Y", "find-principals", "-s", sig_path, "-f", self.allowed_signers],
                    check=False, timeout=30)
                found = [p.strip() for p in out.splitlines() if p.strip()] if rc == 0 else []
                matching = [p for p in found
                            if p.split("@", 1)[0] == signer_id and p in allowed_principals]
                if not matching:
                    errors.append("%s: key not trusted for this signer id and document" % tag)
                    continue
                ok_principal = None
                for principal in matching:
                    rc, _out, _err = self.host.run(
                        ["ssh-keygen", "-Y", "verify", "-f", self.allowed_signers, "-I", principal,
                         "-n", namespace, "-s", sig_path],
                        input_bytes=document, check=False, timeout=30)
                    if rc == 0:
                        ok_principal = principal
                        break
                if ok_principal is None:
                    errors.append("%s: signature invalid" % tag)
                    continue
                if ok_principal not in principals:
                    principals.append(ok_principal)
                fp = fingerprint(blob)
                if fp not in keys:
                    keys.append(fp)
        distinct = min(len(principals), len(keys))
        ok = distinct >= max(1, required)
        if not ok:
            errors.append("signatures: %d valid, %d required" % (distinct, required))
        return {"ok": ok, "principals": principals, "keys": keys, "errors": errors,
                "present": len(sigs)}


def check_krl(host, path: str) -> bool:
    """A KRL is usable when ssh-keygen can query it (exit 0 or 1)."""
    with tempfile.TemporaryDirectory(prefix="legatto-krl-") as tmp:
        key = os.path.join(tmp, "probe")
        try:
            host.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key], timeout=30)
        except CommandError:
            return False
        rc, _o, _e = host.run(["ssh-keygen", "-Q", "-f", path, key + ".pub"], check=False, timeout=30)
        return rc in (0, 1)
