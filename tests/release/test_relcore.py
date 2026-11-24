"""Unit tests of release/lib/relcore.py: transparency log, stores, semver, allowed_signers.

The R2 store is exercised against a local fake S3 endpoint (http.server) that
implements PutObject/GetObject/HeadObject/CopyObject with If-None-Match /
If-Match, a bucket lock on releases/ (409 on overwrite) and requires an
AWS SigV4 Authorization header for region "auto" and service "s3" — the
request shape curl --aws-sigv4 sends to Cloudflare R2. The signature value
itself is not recomputed (that is curl's job, not ours).
"""

from __future__ import annotations

import hashlib
import http.server
import os
import sys
import tempfile
import threading
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "release", "lib"))
import relcore as rc  # noqa: E402

results = []


def check(name, cond, detail=""):
    results.append(bool(cond))
    print("%s %s%s" % ("PASS" if cond else "FAIL", name, (" — " + str(detail)) if detail and not cond else ""))


def raises(fn):
    try:
        fn()
    except rc.ReleaseError as e:
        return str(e)
    return None


class FakeS3(http.server.BaseHTTPRequestHandler):
    objects = {}
    meta = {}
    requests = []
    locked_prefix = "/legatto-updates/v1/releases/"

    def do_HEAD(self):
        FakeS3.requests.append(("HEAD", self.path, dict(self.headers)))
        if not self._auth_ok():
            self.send_response(403)
            self.end_headers()
            return
        obj = FakeS3.objects.get(self.path)
        if obj is None:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(obj)))
        if FakeS3.meta.get(self.path):
            self.send_header("x-amz-meta-sha256", FakeS3.meta[self.path])
        self.end_headers()

    def log_message(self, *args):
        pass

    def _auth_ok(self):
        auth = self.headers.get("Authorization", "")
        return auth.startswith("AWS4-HMAC-SHA256 Credential=AKIDTEST/") and "/auto/s3/aws4_request" in auth \
            and self.headers.get("x-amz-content-sha256") is not None

    def do_GET(self):
        FakeS3.requests.append(("GET", self.path, dict(self.headers)))
        if not self._auth_ok():
            self.send_response(403)
            self.end_headers()
            return
        obj = FakeS3.objects.get(self.path)
        if obj is None:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("ETag", '"%s"' % hashlib.md5(obj).hexdigest())
        self.send_header("Content-Length", str(len(obj)))
        self.end_headers()
        self.wfile.write(obj)

    def do_PUT(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        FakeS3.requests.append(("PUT", self.path, dict(self.headers)))
        if not self._auth_ok():
            self.send_response(403)
            self.end_headers()
            return
        current = FakeS3.objects.get(self.path)
        copy_source = self.headers.get("x-amz-copy-source")
        if copy_source is not None:
            inm, im = self.headers.get("cf-copy-destination-if-none-match"), None
        else:
            inm, im = self.headers.get("If-None-Match"), self.headers.get("If-Match")
        if current is not None and self.path.startswith(FakeS3.locked_prefix):
            self.send_response(409)  # ObjectLockedByBucketPolicy
            self.end_headers()
            return
        if (inm == "*" and current is not None) or \
                (im is not None and (current is None or im != '"%s"' % hashlib.md5(current).hexdigest())):
            self.send_response(412)
            self.end_headers()
            return
        if copy_source is not None:
            src = "/" + urllib.parse.unquote(copy_source).lstrip("/")
            if src not in FakeS3.objects or body:
                self.send_response(404 if src not in FakeS3.objects else 400)
                self.end_headers()
                return
            FakeS3.objects[self.path] = FakeS3.objects[src]
            FakeS3.meta[self.path] = FakeS3.meta.get(src)
        else:
            FakeS3.objects[self.path] = body
            FakeS3.meta[self.path] = self.headers.get("x-amz-meta-sha256")
        self.send_response(200)
        self.end_headers()


def test_tlog():
    log = b""
    for i in range(3):
        log = rc.tlog_append(log, "release.published", "2026-11-21T10:00:0%dZ" % i, {"version": "1.0.%d" % i})
    check("tlog: chain of 3 entries verifies", len(rc.tlog_parse(log)) == 3)
    lines = log.splitlines(keepends=True)
    check("tlog: modified entry detected", raises(lambda: rc.tlog_parse(lines[0].replace(b"1.0.0", b"9.9.9") + b"".join(lines[1:]))))
    check("tlog: removed entry detected", raises(lambda: rc.tlog_parse(lines[0] + lines[2])))
    check("tlog: reordered entries detected", raises(lambda: rc.tlog_parse(lines[1] + lines[0] + lines[2])))
    check("tlog: truncated tail still a valid prefix", len(rc.tlog_parse(lines[0] + lines[1])) == 2)


def test_semver():
    order = ["0.9.9", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0", "1.0.1", "1.10.0"]
    keys = [rc.semver_key(v) for v in order]
    check("semver: SemVer 2.0 precedence", keys == sorted(keys))
    check("semver: invalid version rejected", raises(lambda: rc.semver_key("1.0")) and raises(lambda: rc.semver_key("01.0.0")))


def test_allowed_signers(tmp):
    path = os.path.join(tmp, "allowed_signers")
    with open(path, "w") as f:
        f.write('# comment\n'
                'release-a@legatto.pl namespaces="legatto-release,legatto-promote,legatto-index,legatto-revoke" '
                'sk-ssh-ed25519@openssh.com AAAAKEYA\n'
                'canary@legatto.pl,canary2@legatto.pl valid-after="20260101",namespaces="legatto-canary" ssh-ed25519 AAAAKEYC\n'
                'plain@legatto.pl ssh-ed25519 AAAAKEYP\n')
    e = rc.parse_allowed_signers(path)
    check("allowed_signers: quoted namespaces with commas",
          e[0]["namespaces"] == ["legatto-release", "legatto-promote", "legatto-index", "legatto-revoke"]
          and e[0]["keytype"] == "sk-ssh-ed25519@openssh.com")
    check("allowed_signers: several options and principals",
          e[1]["principals"] == ["canary@legatto.pl", "canary2@legatto.pl"] and e[1]["namespaces"] == ["legatto-canary"])
    check("allowed_signers: no options = all namespaces", e[2]["namespaces"] is None and e[2]["key"] == "AAAAKEYP")


def test_file_store(tmp):
    root = os.path.join(tmp, "mirror")
    store = rc.Store("file://" + root)
    src = os.path.join(tmp, "a.bin")
    with open(src, "wb") as f:
        f.write(b"artifact")
    check("file store: immutable upload", store.put("releases/1.0.0/a.bin", src, "application/octet-stream", immutable=True) == "uploaded")
    check("file store: identical re-upload accepted", store.put("releases/1.0.0/a.bin", src, "x", immutable=True) == "unchanged")
    with open(src, "wb") as f:
        f.write(b"changed")
    check("file store: different content refused", raises(lambda: store.put("releases/1.0.0/a.bin", src, "x", immutable=True)))
    check("file store: path traversal refused", raises(lambda: store.get("../etc/passwd")))
    store.put("index.json", src, "application/json", immutable=False, if_absent=True)
    _, etag = store.get("index.json")
    check("file store: stale If-Match refused", raises(lambda: store.put("index.json", src, "x", immutable=False, if_match="0" * 64)))
    check("file store: matching If-Match accepted", store.put("index.json", src, "x", immutable=False, if_match=etag) == "uploaded")
    check("file store: if_absent on existing refused", raises(lambda: store.put("index.json", src, "x", immutable=False, if_absent=True)))
    with open(src, "wb") as f:
        f.write(b"artifact")
    sha, size = rc.sha256_file(src), os.path.getsize(src)
    check("file store: head = (size, sha256), None when absent",
          store.head("releases/1.0.0/a.bin") == (size, sha) and store.head("releases/9/a.bin") is None)
    check("file store: copy of a published object",
          store.copy("releases/1.0.0/a.bin", "releases/1.0.1/a.bin", sha, size) == "copied"
          and store.head("releases/1.0.1/a.bin") == (size, sha))
    check("file store: copy onto the identical object is a no-op",
          store.copy("releases/1.0.0/a.bin", "releases/1.0.1/a.bin", sha, size) == "unchanged")
    check("file store: copy refused when the source content differs",
          raises(lambda: store.copy("releases/1.0.0/a.bin", "releases/1.0.2/a.bin", "0" * 64, size)))


def test_r2_store(tmp):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeS3)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    env_backup = dict(os.environ)
    os.environ.update({"R2_ACCESS_KEY_ID": "AKIDTEST", "R2_SECRET_ACCESS_KEY": "secret-value-not-printed",
                       "R2_ENDPOINT": "http://127.0.0.1:%d" % server.server_address[1]})
    os.environ.pop("R2_ACCOUNT_ID", None)
    try:
        store = rc.Store("r2://legatto-updates/v1")
        src = os.path.join(tmp, "m.json")
        with open(src, "wb") as f:
            f.write(b'{"a":1}\n')
        check("r2: immutable PUT", store.put("releases/1.0.0/manifest.json", src, "application/json", immutable=True) == "uploaded")
        method, path, headers = FakeS3.requests[-1]
        check("r2: bucket/prefix/key path", path == "/legatto-updates/v1/releases/1.0.0/manifest.json", path)
        check("r2: If-None-Match and immutable Cache-Control sent",
              headers.get("If-None-Match") == "*" and "immutable" in headers.get("Cache-Control", "")
              and headers.get("Content-Type") == "application/json")
        check("r2: secret not in request headers", all("secret-value" not in str(v) for _, _, h in FakeS3.requests for v in h.values()))
        before = len(FakeS3.requests)
        check("r2: identical re-upload accepted without a PUT (HEAD, x-amz-meta-sha256)",
              store.put("releases/1.0.0/manifest.json", src, "application/json", immutable=True) == "unchanged"
              and [r[0] for r in FakeS3.requests[before:]] == ["HEAD"])
        sha, size = rc.sha256_file(src), os.path.getsize(src)
        check("r2: head reads size and x-amz-meta-sha256", store.head("releases/1.0.0/manifest.json") == (size, sha))
        before = len(FakeS3.requests)
        check("r2: server-side copy of a published object",
              store.copy("releases/1.0.0/manifest.json", "releases/1.0.1/manifest.json", sha, size) == "copied"
              and FakeS3.objects.get("/legatto-updates/v1/releases/1.0.1/manifest.json") == b'{"a":1}\n')
        copy_req = [h for m, _, h in FakeS3.requests[before:] if m == "PUT"]
        check("r2: copy sends x-amz-copy-source, no body, destination If-None-Match",
              len(copy_req) == 1 and copy_req[0].get("x-amz-copy-source") == "legatto-updates/v1/releases/1.0.0/manifest.json"
              and copy_req[0].get("cf-copy-destination-if-none-match") == "*"
              and copy_req[0].get("Content-Length", "0") == "0")
        check("r2: copy onto the identical object is a no-op",
              store.copy("releases/1.0.0/manifest.json", "releases/1.0.1/manifest.json", sha, size) == "unchanged")
        FakeS3.objects["/legatto-updates/v1/releases/1.0.2/x"] = b"other"
        check("r2: bucket lock (409) on other content refused",
              raises(lambda: store.copy("releases/1.0.0/manifest.json", "releases/1.0.2/x", sha, size)))
        with open(src, "wb") as f:
            f.write(b'{"a":2}\n')
        check("r2: different content refused", raises(lambda: store.put("releases/1.0.0/manifest.json", src, "x", immutable=True)))
        data, etag = store.get("releases/1.0.0/manifest.json")
        check("r2: GET returns content and ETag", data == b'{"a":1}\n' and etag and etag.startswith('"'))
        check("r2: missing object is None", store.get("nope.json") == (None, None))
        store.put("index.json", src, "application/json", immutable=False, if_absent=True)
        _, etag = store.get("index.json")
        check("r2: stale If-Match refused", raises(lambda: store.put("index.json", src, "x", immutable=False, if_match='"stale"')))
        check("r2: current If-Match accepted", store.put("index.json", src, "x", immutable=False, if_match=etag) == "uploaded")
        os.environ.pop("R2_ENDPOINT")
        check("r2: account id required without R2_ENDPOINT", raises(lambda: rc.Store("r2://legatto-updates/v1")))
    finally:
        os.environ.clear()
        os.environ.update(env_backup)
        server.shutdown()


def main():
    tmp = tempfile.mkdtemp(prefix="legatto-ci-relcore-")
    test_tlog()
    test_semver()
    test_allowed_signers(tmp)
    test_file_store(tmp)
    test_r2_store(tmp)
    failed = results.count(False)
    print("relcore: %d checks, %d failures" % (len(results), failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
