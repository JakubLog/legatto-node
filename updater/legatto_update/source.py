"""Where release documents come from: the update server (through the host
egress proxy) or a local directory with the same layout (bootstrap bundle,
local mirror of downloads)."""

import hashlib
import os
import shutil
import tempfile
import urllib.error
import urllib.parse
import urllib.request

USER_AGENT = "legatto-update/1"


class FetchError(Exception):
    """Transient: the server could not be reached or answered with an error."""


class SizeError(Exception):
    pass


def _check_rel(rel: str) -> str:
    parts = rel.split("/")
    if rel.startswith("/") or any(p in ("", ".", "..") for p in parts):
        raise ValueError("bad relative path %r" % rel)
    return rel


class HttpSource:
    def __init__(self, base_url: str, proxy):
        self.base = base_url.rstrip("/") + "/"
        handlers = [urllib.request.ProxyHandler({"http": proxy, "https": proxy} if proxy else {})]
        self.opener = urllib.request.build_opener(*handlers)

    def describe(self) -> str:
        return self.base

    def _open(self, rel: str):
        url = urllib.parse.urljoin(self.base, _check_rel(rel))
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Cache-Control": "no-cache"})
        try:
            return self.opener.open(req, timeout=60)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise FetchError("%s: HTTP %s" % (rel, exc.code)) from exc
        except (urllib.error.URLError, OSError) as exc:
            raise FetchError("%s: %s" % (rel, exc)) from exc

    def get(self, rel: str, limit: int):
        resp = self._open(rel)
        if resp is None:
            return None
        with resp:
            try:
                data = resp.read(limit + 1)
            except OSError as exc:
                raise FetchError("%s: %s" % (rel, exc)) from exc
        if len(data) > limit:
            raise SizeError("%s: larger than %d bytes" % (rel, limit))
        return data

    def download(self, rel: str, dest: str, size: int) -> str:
        """Stream to dest (atomic), at most `size` bytes; returns sha256."""
        resp = self._open(rel)
        if resp is None:
            raise FetchError("%s: not found" % rel)
        with resp:
            return _stream(resp, dest, size, rel)


class DirSource:
    def __init__(self, root: str):
        self.root = root

    def describe(self) -> str:
        return self.root

    def _path(self, rel: str) -> str:
        return os.path.join(self.root, *_check_rel(rel).split("/"))

    def get(self, rel: str, limit: int):
        path = self._path(rel)
        try:
            with open(path, "rb") as fh:
                data = fh.read(limit + 1)
        except FileNotFoundError:
            return None
        if len(data) > limit:
            raise SizeError("%s: larger than %d bytes" % (rel, limit))
        return data

    def download(self, rel: str, dest: str, size: int) -> str:
        path = self._path(rel)
        try:
            fh = open(path, "rb")
        except FileNotFoundError as exc:
            raise FetchError("%s: not found" % rel) from exc
        with fh:
            return _stream(fh, dest, size, rel)


def _stream(fh, dest: str, size: int, rel: str) -> str:
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    tmp_fd, tmp = tempfile.mkstemp(prefix=".dl-", dir=os.path.dirname(dest))
    h = hashlib.sha256()
    total = 0
    try:
        with os.fdopen(tmp_fd, "wb") as out:
            while True:
                try:
                    chunk = fh.read(1 << 20)
                except OSError as exc:
                    raise FetchError("%s: %s" % (rel, exc)) from exc
                if not chunk:
                    break
                total += len(chunk)
                if total > size:
                    raise SizeError("%s: larger than manifest size %d" % (rel, size))
                h.update(chunk)
                out.write(chunk)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, dest)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
    return h.hexdigest()


def copy_file(src: str, dest: str) -> None:
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    try:
        os.link(src, dest)
    except OSError:
        shutil.copy2(src, dest)
