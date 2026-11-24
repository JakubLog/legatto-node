"""Shared code of the release tools.

The builder (release/build.sh, here in legatto-node) and the vendor's
signing and publishing tools (sign, publish, promote, attest-publish,
resign-index, yank; they reach this module through the node checkout)
use one copy of this module and of schema.py.

Python stdlib only (3.9+). External programs: yq (YAML -> JSON), OpenSSH
ssh-keygen ($LEGATTO_SSH_KEYGEN), curl (R2 S3 API), docker and syft (build).
Nothing here prints secret values.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

NODE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
CONTRACT_YML = os.path.join(NODE, "contract", "contract.yml")
VERSIONS_YML = os.path.join(NODE, "contract", "versions.yml")
DEFAULT_ALLOWED_SIGNERS = os.path.join(NODE, "trust", "allowed_signers")
OUT_ROOT = os.path.join(NODE, "release", "out")
DEFAULT_UPDATES_URL = "https://updates.legatto.pl/v1"
GENESIS = "0" * 64
SK_KEY_TYPE = "sk-ssh-ed25519@openssh.com"
SEMVER_RE = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ReleaseError(Exception):
    """Expected failure: printed without a traceback, exit code 1 (or .code)."""

    def __init__(self, message: str, code: int = 1):
        super().__init__(message)
        self.code = code


def info(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def run_main(fn) -> None:
    """Run fn(argv) and map ReleaseError to its exit code."""
    try:
        sys.exit(fn(sys.argv[1:]) or 0)
    except ReleaseError as e:
        info("error: %s" % e)
        sys.exit(e.code)
    except KeyboardInterrupt:
        info("przerwano")
        sys.exit(130)


# --- hashing and JSON ---------------------------------------------------------------

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def document_bytes(obj: Any) -> bytes:
    """Byte form of every published JSON document (stable: sorted keys, 2-space indent, final newline)."""
    return (json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def write_document(path: str, obj: Any) -> bytes:
    data = document_bytes(obj)
    write_bytes(path, data)
    return data


def write_bytes(path: str, data: bytes, mode: int = 0o644) -> None:
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def read_json(path: str) -> Any:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        raise ReleaseError("brak pliku: %s" % path)
    except ValueError as e:
        raise ReleaseError("niepoprawny JSON w %s: %s" % (path, e))


def load_json_bytes(data: bytes, what: str) -> Any:
    try:
        return json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        raise ReleaseError("niepoprawny JSON (%s): %s" % (what, e))


# --- time ----------------------------------------------------------------------------

def fmt_ts(epoch: int) -> str:
    return _dt.datetime.fromtimestamp(int(epoch), tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(ts: str) -> int:
    try:
        return int(_dt.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_dt.timezone.utc).timestamp())
    except ValueError:
        raise ReleaseError("niepoprawny czas UTC: %r" % ts)


def now_epoch() -> int:
    return int(_dt.datetime.now(tz=_dt.timezone.utc).timestamp())


# --- semver --------------------------------------------------------------------------

def semver_key(v: str) -> Tuple:
    m = SEMVER_RE.match(v)
    if not m:
        raise ReleaseError("niepoprawna wersja semver: %r" % v)
    major, minor, patch, pre = int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4)
    if pre is None:
        return (major, minor, patch, 1, ())
    ids = []
    for part in pre.split("."):
        ids.append((0, int(part), "") if part.isdigit() else (1, 0, part))
    return (major, minor, patch, 0, tuple(ids))


def check_semver(v: str) -> str:
    semver_key(v)
    return v


# --- YAML inputs (contract, versions) ------------------------------------------------------

def yaml_to_json(path: str) -> Any:
    yq = shutil.which("yq")
    if not yq:
        raise ReleaseError("brak yq (mikefarah/yq v4, https://github.com/mikefarah/yq)", 4)
    out = subprocess.run([yq, "-o=json", ".", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if out.returncode != 0:
        raise ReleaseError("yq nie odczytał %s: %s" % (path, out.stderr.decode(errors="replace").strip()))
    return json.loads(out.stdout.decode("utf-8"))


_CONTRACT: Optional[Dict[str, Any]] = None


def contract() -> Dict[str, Any]:
    global _CONTRACT
    if _CONTRACT is None:
        _CONTRACT = yaml_to_json(CONTRACT_YML)
    return _CONTRACT


def namespace(kind: str) -> str:
    return contract()["legatto_signature"]["namespaces"][kind]


# --- subprocess ----------------------------------------------------------------------

def run(cmd: Sequence[str], *, cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None,
        capture: bool = False, input_bytes: Optional[bytes] = None, quiet: bool = False) -> subprocess.CompletedProcess:
    if not quiet:
        info("+ " + " ".join(cmd))
    full_env = None
    if env is not None:
        full_env = dict(os.environ)
        full_env.update(env)
    res = subprocess.run(list(cmd), cwd=cwd, env=full_env, input=input_bytes,
                         stdout=subprocess.PIPE if capture else None,
                         stderr=subprocess.PIPE if capture else None)
    if res.returncode != 0:
        detail = ""
        if capture and res.stderr:
            detail = ": " + res.stderr.decode(errors="replace").strip()[-2000:]
        raise ReleaseError("polecenie nie powiodło się (%d): %s%s" % (res.returncode, cmd[0], detail))
    return res


def need_tool(name: str, hint: str = "") -> str:
    path = shutil.which(name)
    if not path:
        raise ReleaseError("brak narzędzia %s%s" % (name, (" — " + hint) if hint else ""), 4)
    return path


# --- confirmation ----------------------------------------------------------------------

def confirm_typed(expected: str, prompt: str) -> None:
    """The operator must type `expected` (the release version) to continue."""
    info(prompt)
    sys.stderr.write("Wpisz %s, aby kontynuować: " % expected)
    sys.stderr.flush()
    line = sys.stdin.readline()
    if line.strip() != expected:
        raise ReleaseError("nie potwierdzono (wpisano %r, oczekiwano %r)" % (line.strip(), expected))


# --- sshsig ----------------------------------------------------------------------------------

def ssh_keygen() -> str:
    path = os.environ.get("LEGATTO_SSH_KEYGEN") or "/opt/homebrew/bin/ssh-keygen"
    if not os.path.isfile(path) or not os.access(path, os.X_OK):
        found = shutil.which("ssh-keygen")
        if os.environ.get("LEGATTO_SSH_KEYGEN") or not found:
            raise ReleaseError("brak ssh-keygen: %s (ustaw LEGATTO_SSH_KEYGEN)" % path, 4)
        path = found
    return path


def allowed_signers_path() -> str:
    return os.environ.get("LEGATTO_ALLOWED_SIGNERS") or DEFAULT_ALLOWED_SIGNERS


def parse_allowed_signers(path: str) -> List[Dict[str, Any]]:
    """Return [{principals, namespaces, keytype, key}] from an allowed_signers file."""
    if not os.path.isfile(path):
        raise ReleaseError("brak allowed_signers: %s (ustaw LEGATTO_ALLOWED_SIGNERS)" % path, 4)
    entries = []
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            tokens = _split_signers_line(line)
            if len(tokens) < 3:
                continue
            principals = tokens[0].split(",")
            rest = tokens[1:]
            options: Dict[str, str] = {}
            if not (rest[0].startswith("ssh-") or rest[0].startswith("sk-") or rest[0].startswith("ecdsa-")):
                for opt in _split_options(rest[0]):
                    k, _, v = opt.partition("=")
                    options[k.lower()] = v.strip('"')
                rest = rest[1:]
            if len(rest) < 2:
                continue
            ns = options.get("namespaces")
            entries.append({
                "principals": principals,
                "namespaces": ns.split(",") if ns else None,
                "keytype": rest[0],
                "key": rest[1],
            })
    return entries


def _split_options(text: str) -> List[str]:
    """Split `a="x,y",b` on commas outside double quotes."""
    out, cur, quoted = [], "", False
    for c in text:
        if c == '"':
            quoted = not quoted
        if c == "," and not quoted:
            out.append(cur)
            cur = ""
        else:
            cur += c
    out.append(cur)
    return [o for o in out if o]


def _split_signers_line(line: str) -> List[str]:
    tokens, cur, quoted = [], "", False
    for c in line:
        if c == '"':
            quoted = not quoted
            cur += c
        elif c in " \t" and not quoted:
            if cur:
                tokens.append(cur)
                cur = ""
        else:
            cur += c
    if cur:
        tokens.append(cur)
    return tokens


class Signer:
    """A release signing key: $LEGATTO_SIGNING_KEY (private key or FIDO2 handle) + its principal."""

    def __init__(self, required_namespace: str):
        key = os.environ.get("LEGATTO_SIGNING_KEY")
        if not key:
            raise ReleaseError("ustaw LEGATTO_SIGNING_KEY (uchwyt klucza ed25519-sk, np. ~/.ssh/id_legatto_release_sk)", 4)
        if not os.path.isfile(key) or not os.path.isfile(key + ".pub"):
            raise ReleaseError("brak klucza lub %s.pub: %s" % (key, key), 4)
        self.key = key
        with open(key + ".pub", encoding="utf-8") as f:
            parts = f.read().split()
        if len(parts) < 2:
            raise ReleaseError("niepoprawny klucz publiczny %s.pub" % key)
        self.keytype, self.blob = parts[0], parts[1]
        if self.keytype != SK_KEY_TYPE:
            if os.environ.get("LEGATTO_ALLOW_SOFTWARE_KEY") != "1":
                raise ReleaseError(
                    "klucz %s nie jest kluczem sprzętowym (%s, oczekiwano %s); "
                    "klucze programowe tylko dla testów: LEGATTO_ALLOW_SOFTWARE_KEY=1" % (key, self.keytype, SK_KEY_TYPE), 4)
            info("UWAGA: podpis kluczem programowym (%s) — tylko środowisko testowe" % self.keytype)
        self.allowed = allowed_signers_path()
        principal = os.environ.get("LEGATTO_SIGNER")
        matches = [e for e in parse_allowed_signers(self.allowed) if e["key"] == self.blob]
        if principal:
            matches = [e for e in matches if principal in e["principals"]]
        if not matches:
            raise ReleaseError("klucz %s nie występuje w %s%s" % (
                key, self.allowed, (" jako " + principal) if principal else ""), 4)
        entry = matches[0]
        self.principal = principal or entry["principals"][0]
        if entry["namespaces"] is not None and required_namespace not in entry["namespaces"]:
            raise ReleaseError("principal %s nie ma namespace %s w %s" % (self.principal, required_namespace, self.allowed), 4)
        self.signer_id = self.principal.split("@", 1)[0]
        if not re.match(r"^[a-z0-9][a-z0-9._-]{0,63}$", self.signer_id):
            raise ReleaseError("niepoprawny identyfikator podpisującego: %r" % self.signer_id)

    def sig_path(self, document: str) -> str:
        return "%s.%s.sig" % (document, self.signer_id)

    def sign(self, document: str, ns: str) -> str:
        """Sign document with namespace ns; returns <document>.<signer-id>.sig."""
        target = self.sig_path(document)
        if os.path.exists(target):
            raise ReleaseError("podpis już istnieje: %s" % target)
        produced = document + ".sig"
        if os.path.exists(produced):
            raise ReleaseError("pozostałość po poprzednim podpisie: %s — usuń ją" % produced)
        if self.keytype == SK_KEY_TYPE:
            info(">>> Dotknij klucza sprzętowego (podpis %s, namespace %s) <<<" % (os.path.basename(document), ns))
        res = subprocess.run([ssh_keygen(), "-Y", "sign", "-f", self.key, "-n", ns, document])
        if res.returncode != 0 or not os.path.isfile(produced):
            if os.path.exists(produced):
                os.unlink(produced)
            raise ReleaseError("ssh-keygen -Y sign nie powiódł się (%d)" % res.returncode)
        os.replace(produced, target)
        verify_signature(document, target, self.principal, ns, self.allowed)
        info("podpisano: %s (%s, %s)" % (os.path.basename(target), self.principal, ns))
        return target


def verify_signature(document: str, sig: str, principal: str, ns: str, allowed: str) -> None:
    with open(document, "rb") as f:
        data = f.read()
    res = subprocess.run([ssh_keygen(), "-Y", "verify", "-f", allowed, "-I", principal, "-n", ns, "-s", sig],
                         input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if res.returncode != 0:
        raise ReleaseError("podpis %s nie przechodzi weryfikacji (%s, %s): %s" % (
            os.path.basename(sig), principal, ns, res.stderr.decode(errors="replace").strip()))


def find_principals(sig: str, allowed: str, ns: str) -> List[str]:
    res = subprocess.run([ssh_keygen(), "-Y", "find-principals", "-f", allowed, "-n", ns, "-s", sig],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if res.returncode != 0:
        return []
    return [p for p in res.stdout.decode().split() if p]


def verified_principals(document: str, ns: str, allowed: str, principal_set: Iterable[str]) -> List[str]:
    """Distinct principals from principal_set with a valid signature file next to document."""
    allowed_principals = set(principal_set)
    directory, base = os.path.split(os.path.abspath(document))
    good: List[str] = []
    for name in sorted(os.listdir(directory)):
        if not (name.startswith(base + ".") and name.endswith(".sig")) or name == base + ".sig":
            continue
        sig = os.path.join(directory, name)
        signer_id = name[len(base) + 1:-4]
        for principal in find_principals(sig, allowed, ns):
            if principal not in allowed_principals or principal.split("@", 1)[0] != signer_id:
                continue
            try:
                verify_signature(document, sig, principal, ns, allowed)
            except ReleaseError as e:
                info("odrzucony podpis: %s" % e)
                continue
            if principal not in good:
                good.append(principal)
    return good


def require_signatures(document: str, kind: str, principals_kind: str = "release") -> List[str]:
    ns = namespace(kind)
    allowed = allowed_signers_path()
    principals = contract()["legatto_signature"]["principals"][principals_kind]
    good = verified_principals(document, ns, allowed, principals)
    need = int(contract()["legatto_signature"]["signatures_required_default"])
    if len(good) < need:
        raise ReleaseError("%s: ważnych podpisów %d (%s), wymagane %d" % (
            os.path.basename(document), len(good), ns, need))
    return good


# --- transparency log ----------------------------------------------------------------------

def tlog_parse(data: bytes) -> List[Dict[str, Any]]:
    """Parse and verify the JSONL hash chain of transparency.log."""
    entries: List[Dict[str, Any]] = []
    prev = GENESIS
    for n, raw in enumerate(data.decode("utf-8").splitlines(), 1):
        if not raw.strip():
            raise ReleaseError("transparency.log: pusta linia %d" % n)
        entry = load_json_bytes(raw.encode("utf-8"), "transparency.log:%d" % n)
        body = {k: v for k, v in entry.items() if k != "hash"}
        if entry.get("seq") != n or entry.get("prev") != prev or entry.get("hash") != sha256_bytes(canonical(body)):
            raise ReleaseError("transparency.log: łańcuch uszkodzony w linii %d" % n)
        prev = entry["hash"]
        entries.append(entry)
    return entries


def tlog_append(data: bytes, event: str, ts: str, fields: Dict[str, Any]) -> bytes:
    entries = tlog_parse(data)
    entry: Dict[str, Any] = {"seq": len(entries) + 1, "ts": ts, "event": event,
                             "prev": entries[-1]["hash"] if entries else GENESIS}
    entry.update(fields)
    entry["hash"] = sha256_bytes(canonical(entry))
    return data + canonical(entry) + b"\n"


# --- storage: R2 (S3 API through curl --aws-sigv4) or a local directory ---------------------------------

CACHE_IMMUTABLE = "public, max-age=31536000, immutable"
CACHE_MUTABLE = "no-cache, max-age=0"


class Store:
    """Destination of `make publish|promote`: LEGATTO_UPDATES_DEST.

    r2://<bucket>[/<prefix>]  Cloudflare R2 through its S3 API (curl --aws-sigv4);
                              credentials from R2_ACCOUNT_ID, R2_ACCESS_KEY_ID,
                              R2_SECRET_ACCESS_KEY in the process environment
                              (never in argv: curl reads them from stdin);
                              R2_ENDPOINT/R2_REGION override the endpoint (tests).
    file:///<directory>       local mirror (test offices, tests).

    Release objects are immutable: written once (If-None-Match: *), an
    existing identical object is accepted, anything else is refused. A bucket
    lock on <prefix>/releases/ enforces the same on the server (HTTP 409).
    """

    def __init__(self, dest: str):
        self.dest = dest
        if dest.startswith("file://"):
            self.kind = "file"
            self.root = dest[len("file://"):]
            if not os.path.isabs(self.root):
                raise ReleaseError("LEGATTO_UPDATES_DEST file:// wymaga ścieżki absolutnej")
            os.makedirs(self.root, exist_ok=True)
        elif dest.startswith("r2://"):
            self.kind = "r2"
            bucket, _, prefix = dest[len("r2://"):].partition("/")
            if not re.match(r"^[a-z0-9][a-z0-9-]{1,62}$", bucket):
                raise ReleaseError("niepoprawny bucket R2: %r" % bucket)
            self.bucket, self.prefix = bucket, prefix.strip("/")
            missing = [k for k in ("R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY") if not os.environ.get(k)]
            endpoint = os.environ.get("R2_ENDPOINT")
            if not endpoint:
                account = os.environ.get("R2_ACCOUNT_ID", "")
                if not re.match(r"^[0-9a-f]{32}$", account):
                    missing.append("R2_ACCOUNT_ID")
                endpoint = "https://%s.r2.cloudflarestorage.com" % account
            if missing:
                raise ReleaseError("brak zmiennych %s (token R2 tylko w środowisku procesu)" % ", ".join(missing), 4)
            self.endpoint = endpoint.rstrip("/")
            self.region = os.environ.get("R2_REGION", "auto")
            self.curl = need_tool("curl")
        else:
            raise ReleaseError("LEGATTO_UPDATES_DEST musi zaczynać się od r2:// albo file:// (jest: %r)" % dest, 2)

    @classmethod
    def from_env(cls) -> "Store":
        dest = os.environ.get("LEGATTO_UPDATES_DEST")
        if not dest:
            raise ReleaseError("ustaw LEGATTO_UPDATES_DEST (r2://<bucket>/v1 albo file:///katalog)", 4)
        return cls(dest)

    def public_url(self, key: str) -> str:
        base = os.environ.get("LEGATTO_UPDATES_URL")
        if not base:
            base = "file://" + self.root if self.kind == "file" else DEFAULT_UPDATES_URL
        return base.rstrip("/") + "/" + key

    # -- file backend
    def _path(self, key: str) -> str:
        if key.startswith("/") or ".." in key.split("/"):
            raise ReleaseError("niepoprawny klucz: %r" % key)
        return os.path.join(self.root, key)

    # -- r2 backend
    def _url(self, key: str) -> str:
        parts = [self.bucket] + ([self.prefix] if self.prefix else []) + [key]
        return "%s/%s" % (self.endpoint, "/".join(parts))

    def _curl(self, args: List[str]) -> Tuple[int, Dict[str, str]]:
        cfg = 'user = "%s:%s"\n' % (os.environ["R2_ACCESS_KEY_ID"].replace('"', ""),
                                    os.environ["R2_SECRET_ACCESS_KEY"].replace('"', ""))
        with tempfile.NamedTemporaryFile(prefix="curl-hdr-", delete=False) as h:
            hdr = h.name
        try:
            cmd = [self.curl, "-K", "-", "--silent", "--show-error", "--aws-sigv4",
                   "aws:amz:%s:s3" % self.region, "-D", hdr, "-w", "%{http_code}"] + args
            res = subprocess.run(cmd, input=cfg.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if res.returncode != 0:
                raise ReleaseError("curl (R2) nie powiódł się: %s" % res.stderr.decode(errors="replace").strip())
            code = int(res.stdout.decode().strip()[-3:])
            headers: Dict[str, str] = {}
            with open(hdr, encoding="latin-1") as f:
                for line in f:
                    k, sep, v = line.partition(":")
                    if sep:
                        headers[k.strip().lower()] = v.strip()
            return code, headers
        finally:
            os.unlink(hdr)

    def get(self, key: str) -> Tuple[Optional[bytes], Optional[str]]:
        """Return (content, etag) or (None, None) when the object does not exist."""
        if self.kind == "file":
            p = self._path(key)
            if not os.path.isfile(p):
                return None, None
            with open(p, "rb") as f:
                data = f.read()
            return data, sha256_bytes(data)
        with tempfile.NamedTemporaryFile(prefix="r2-get-", delete=False) as t:
            out = t.name
        try:
            code, headers = self._curl(["-o", out, self._url(key)])
            if code == 404:
                return None, None
            if code != 200:
                raise ReleaseError("R2 GET %s: HTTP %d" % (key, code))
            with open(out, "rb") as f:
                return f.read(), headers.get("etag")
        finally:
            os.unlink(out)

    def head(self, key: str) -> Optional[Tuple[int, Optional[str]]]:
        """(size, sha256) of an existing object, None when it does not exist.

        R2 reports the sha256 recorded at upload (x-amz-meta-sha256); None when absent.
        """
        if self.kind == "file":
            p = self._path(key)
            if not os.path.isfile(p):
                return None
            return os.path.getsize(p), sha256_file(p)
        code, headers = self._curl(["-I", "-o", os.devnull, self._url(key)])
        if code == 404:
            return None
        if code != 200:
            raise ReleaseError("R2 HEAD %s: HTTP %d" % (key, code))
        try:
            size = int(headers.get("content-length", ""))
        except ValueError:
            raise ReleaseError("R2 HEAD %s: brak Content-Length" % key)
        sha = headers.get("x-amz-meta-sha256", "")
        return size, (sha if SHA256_RE.match(sha) else None)

    def _existing_immutable(self, key: str, sha256: str, size: int) -> bool:
        """True when key holds exactly this content, False when absent; refuses other content."""
        current = self.head(key)
        if current is None:
            return False
        cur_size, cur_sha = current
        if cur_sha is None and cur_size == size:
            data, _ = self.get(key)
            cur_sha = sha256_bytes(data) if data is not None else None
        if (cur_size, cur_sha) != (size, sha256):
            raise ReleaseError("%s już istnieje z inną treścią — wydania są niezmienne" % key)
        return True

    def put(self, key: str, src: str, content_type: str, *, immutable: bool,
            if_match: Optional[str] = None, if_absent: bool = False) -> str:
        """Upload file src under key. Returns 'uploaded' or 'unchanged'.

        immutable: never overwrite; an existing identical object is accepted
        without uploading it again (checked with HEAD first).
        if_match / if_absent: compare-and-swap for mutable documents.
        """
        digest = sha256_file(src)
        size = os.path.getsize(src)
        if immutable and self._existing_immutable(key, digest, size):
            return "unchanged"
        if self.kind == "file":
            p = self._path(key)
            if os.path.exists(p):
                current = sha256_file(p)
                if if_absent or (if_match is not None and current != if_match):
                    raise ReleaseError("%s zmienił się w trakcie operacji (równoległa publikacja?)" % key)
            elif if_match is not None:
                raise ReleaseError("%s zniknął w trakcie operacji" % key)
            with open(src, "rb") as f:
                write_bytes(p, f.read())
            return "uploaded"
        args = ["-X", "PUT", "-T", src, "-H", "Content-Type: " + content_type,
                "-H", "Cache-Control: " + (CACHE_IMMUTABLE if immutable else CACHE_MUTABLE),
                "-H", "x-amz-meta-sha256: " + digest]
        if immutable or if_absent:
            args += ["-H", "If-None-Match: *"]
        elif if_match is not None:
            args += ["-H", "If-Match: " + if_match]
        code, _ = self._curl(args + ["-o", os.devnull, self._url(key)])
        if code in (200, 201):
            return "uploaded"
        if code in (409, 412) and immutable:  # 409: object protected by the bucket lock
            if self._existing_immutable(key, digest, size):
                return "unchanged"
            raise ReleaseError("R2 PUT %s: HTTP %d, a obiektu nie ma" % (key, code))
        if code == 412:
            raise ReleaseError("%s zmienił się w trakcie operacji (równoległa publikacja?)" % key)
        raise ReleaseError("R2 PUT %s: HTTP %d" % (key, code))

    def copy(self, src_key: str, key: str, sha256: str, size: int) -> str:
        """Copy an immutable object already published under src_key to key, on the server.

        Returns 'copied' or 'unchanged'. Nothing is uploaded from this
        machine: an unchanged image archive of an earlier release is reused.
        """
        if self._existing_immutable(key, sha256, size):
            return "unchanged"
        if self.head(src_key) != (size, sha256):
            raise ReleaseError("%s: źródło kopii nie ma oczekiwanej treści (sha256/rozmiar)" % src_key)
        if self.kind == "file":
            src, dst = self._path(src_key), self._path(key)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            tmp = "%s.copy-%d" % (dst, os.getpid())
            shutil.copyfile(src, tmp)
            os.replace(tmp, dst)
        else:
            source = "/".join([self.bucket] + ([self.prefix] if self.prefix else []) + [src_key])
            code, _ = self._curl(["-X", "PUT", "--data-binary", "", "-H", "Content-Type:",
                                  "-H", "x-amz-copy-source: " + urllib.parse.quote(source),
                                  "-H", "x-amz-metadata-directive: COPY",
                                  "-H", "cf-copy-destination-if-none-match: *",
                                  "-o", os.devnull, self._url(key)])
            if code in (409, 412):
                if self._existing_immutable(key, sha256, size):
                    return "unchanged"
                raise ReleaseError("R2 COPY %s: HTTP %d, a obiektu nie ma" % (key, code))
            if code != 200:
                raise ReleaseError("R2 COPY %s -> %s: HTTP %d" % (src_key, key, code))
        if self.head(key) != (size, sha256):
            raise ReleaseError("%s: kopia nie ma oczekiwanej treści (sha256/rozmiar)" % key)
        return "copied"


def http_get(url: str) -> Optional[bytes]:
    """GET url (https or file); None on 404 / missing file."""
    if url.startswith("file://"):
        p = url[len("file://"):]
        if not os.path.isfile(p):
            return None
        with open(p, "rb") as f:
            return f.read()
    req = urllib.request.Request(url, headers={"Cache-Control": "no-cache", "User-Agent": "legatto-release"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise ReleaseError("GET %s: HTTP %d" % (url, e.code))
    except urllib.error.URLError as e:
        raise ReleaseError("GET %s: %s" % (url, e.reason))


def content_type(name: str) -> str:
    if name.endswith(".json"):
        return "application/json"
    if name.endswith(".md"):
        return "text/markdown; charset=utf-8"
    if name.endswith(".sig") or name.endswith(".log"):
        return "text/plain; charset=utf-8"
    if name.endswith(".gz"):
        return "application/gzip"
    if name.endswith(".tar"):
        return "application/x-tar"
    if name.endswith(".deb"):
        return "application/vnd.debian.binary-package"
    return "application/octet-stream"


# --- release directory -----------------------------------------------------------------------

def out_dir(version: str) -> str:
    return os.path.join(OUT_ROOT, version)


def verify_bundle_files(bundle: str, manifest: Dict[str, Any]) -> None:
    """Every artifact present with the manifest size and sha256; nothing unlisted."""
    listed = {a["name"] for a in manifest["artifacts"]}
    for a in manifest["artifacts"]:
        p = os.path.join(bundle, a["name"])
        if not os.path.isfile(p):
            raise ReleaseError("brak artefaktu %s" % a["name"])
        if os.path.getsize(p) != a["size"] or sha256_file(p) != a["sha256"]:
            raise ReleaseError("artefakt %s nie zgadza się z manifestem (rozmiar/sha256)" % a["name"])
    for name in os.listdir(bundle):
        if name == "manifest.json" or (name.startswith("manifest.json.") and name.endswith(".sig")):
            continue
        if name not in listed:
            raise ReleaseError("plik spoza manifestu w paczce: %s" % name)


# --- published documents ----------------------------------------------------------------------

def remote_get(key: str, public_only: bool = False) -> Optional[bytes]:
    """Read a published file: from LEGATTO_UPDATES_DEST when set (authoritative), else LEGATTO_UPDATES_URL.

    public_only: always the public read URL (the builder never needs storage credentials).
    """
    if os.environ.get("LEGATTO_UPDATES_DEST") and not public_only:
        return Store.from_env().get(key)[0]
    base = os.environ.get("LEGATTO_UPDATES_URL") or DEFAULT_UPDATES_URL
    return http_get(base.rstrip("/") + "/" + key)


def fetch_verified(key: str, kind: str, principals_kind: str, workdir: str,
                   need: Optional[int] = None, public_only: bool = False) -> Optional[Tuple[str, bytes]]:
    """Download a published document and its signatures into workdir and verify them.

    Returns (local path, bytes) or None when the document does not exist.
    `need` defaults to signatures_required_default from the contract.
    """
    data = remote_get(key, public_only)
    if data is None:
        return None
    path = os.path.join(workdir, key)
    write_bytes(path, data)
    principals = contract()["legatto_signature"]["principals"][principals_kind]
    for principal in principals:
        sig_key = "%s.%s.sig" % (key, principal.split("@", 1)[0])
        sig = remote_get(sig_key, public_only)
        if sig is not None:
            write_bytes(os.path.join(workdir, sig_key), sig)
    ns = namespace(kind)
    good = verified_principals(path, ns, allowed_signers_path(), principals)
    required = need if need is not None else int(contract()["legatto_signature"]["signatures_required_default"])
    if len(good) < required:
        raise ReleaseError("%s: ważnych podpisów %d (%s), wymagane %d" % (key, len(good), ns, required))
    return path, data


def fetch_index(store: Store, workdir: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """The published index.json, verified (release keys, namespace legatto-index) and schema-checked.

    Returns (index, etag), or (None, None) when nothing was ever published. The
    etag guards the compare-and-swap upload of the next index.
    """
    from schema import validate

    key = contract()["legatto_release_layout"]["index"]
    data, etag = store.get(key)
    if data is None:
        return None, None
    got = fetch_verified(key, "index", "release", workdir)
    if got is None or got[1] != data:
        raise ReleaseError("index.json zmienił się w trakcie odczytu — spróbuj ponownie")
    index = load_json_bytes(data, key)
    errors = validate("index", index)
    if errors:
        raise ReleaseError("opublikowany index.json niezgodny ze schematem:\n  " + "\n  ".join(errors))
    return index, etag


def next_index(current: Optional[Dict[str, Any]], now: int) -> Dict[str, Any]:
    """Copy of the index with a new sequence and validity window (legatto_index_validity_days)."""
    days = int(contract()["legatto_index_validity_days"])
    if current is None:
        idx: Dict[str, Any] = {"schema": "legatto-index/1", "product": "legatto", "sequence": 0,
                               "releases": [], "krl_sha256": None}
    else:
        idx = json.loads(json.dumps(current))
    idx["sequence"] = int(idx["sequence"]) + 1
    idx["issued_at"] = fmt_ts(now)
    idx["expires"] = fmt_ts(now + days * 86400)
    return idx


def publish_index_and_log(store: Store, workdir: str, index: Dict[str, Any], index_etag: Optional[str],
                          index_existed: bool, events: List[Tuple[str, Dict[str, Any]]], now: int) -> None:
    """Sign index.json (namespace legatto-index), append transparency.log, then upload log, signature, index.

    The index goes last: it is the only pointer servers follow.
    """
    from schema import validate

    errors = validate("index", index)
    if errors:
        raise ReleaseError("index.json niezgodny ze schematem:\n  " + "\n  ".join(errors))
    index_key = contract()["legatto_release_layout"]["index"]
    index_path = os.path.join(workdir, "new", index_key)
    index_bytes = write_document(index_path, index)
    signer = Signer(namespace("index"))
    sig = signer.sign(index_path, namespace("index"))

    append_log(store, workdir, events + [("index.published", {"index_sequence": index["sequence"],
                                                               "index_sha256": sha256_bytes(index_bytes),
                                                               "signer": signer.principal})],
               now, must_exist=index_existed)
    store.put(os.path.basename(sig), sig, content_type(sig), immutable=False)
    store.put(index_key, index_path, content_type(index_key), immutable=False,
              if_match=index_etag, if_absent=not index_existed)
    published = http_get(store.public_url(index_key))
    if published is None or sha256_bytes(published) != sha256_bytes(index_bytes):
        info("UWAGA: %s pod adresem publicznym nie zwraca jeszcze nowej treści (cache?)" % store.public_url(index_key))
    info("opublikowano index.json sequence %d (ważny do %s)" % (index["sequence"], index["expires"]))


def append_log(store: Store, workdir: str, events: List[Tuple[str, Dict[str, Any]]], now: int,
               must_exist: bool = True) -> None:
    """Append events to the hash-chained transparency.log (compare-and-swap on its etag)."""
    log_key = contract()["legatto_release_layout"]["transparency_log"]
    log, log_etag = store.get(log_key)
    if log is None and must_exist:
        raise ReleaseError("%s nie istnieje, choć index.json istnieje — przerwano" % log_key)
    log = log or b""
    ts = fmt_ts(now)
    for event, fields in events:
        log = tlog_append(log, event, ts, fields)
    log_path = os.path.join(workdir, "new", log_key)
    write_bytes(log_path, log)
    store.put(log_key, log_path, content_type(log_key), immutable=False,
              if_match=log_etag, if_absent=log_etag is None)
