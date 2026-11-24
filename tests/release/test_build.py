"""Builder tests (release/build.sh) on a fixture legatto-node checkout (docs/CONTRACT.md §6, area release).

1.0.0      full bundle: schema, canonical bytes, images = compose placeholders by
           digest, OCI archives, config.tar.gz, migrations, binaries, deb,
           SBOMs, Worker, notes, manifest.source = this node commit + app release;
reference  a second build of the same commit without the image cache (what CI
           does) equals the first one except the bytes of image archives;
1.0.1      a later commit with unchanged images reuses the cached archives:
           same sha256/size for every image (V2), egress-proxy digest and tag
           stable while egress/image is unchanged;
1.0.2      empty local cache, archives taken from a published release
           (file:// mirror with a signed index and manifest), sha256 checked;
refusals   dirty tree, existing output directory, unpinned app.lock.
Requires docker (buildx, containerd image store), syft, yq, git, ssh-keygen.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import fixture as fx  # noqa: E402
from fixture import rc  # noqa: E402

sys.path.insert(0, os.path.join(fx.NODE, "release", "lib"))
import schema  # noqa: E402

results = []


def check(name, cond, detail=""):
    results.append((bool(cond), name, detail))
    print("%s %s%s" % ("PASS" if cond else "FAIL", name, (" — " + str(detail)) if detail and not cond else ""), flush=True)
    return bool(cond)


def masked(m):
    """Manifest without the bytes of image archives (docker save is not byte-reproducible)."""
    m = json.loads(json.dumps(m))
    for a in m["artifacts"]:
        if a["kind"] == "oci-archive":
            a.pop("size")
            a.pop("sha256")
    return m


def manifest(directory):
    return json.load(open(os.path.join(directory, "manifest.json")))


def images_by_name(m):
    arts = {a["name"]: a for a in m["artifacts"]}
    return {i["name"]: dict(i, sha256=arts[i["artifact"]]["sha256"], size=arts[i["artifact"]]["size"]) for i in m["images"]}


def test_first(e):
    fx.add_release(e, "1.0.0", 1)
    res = fx.build(e, "1.0.0")
    out = os.path.join(e.out_root, "1.0.0")
    m = manifest(out)
    check("build: manifest matches manifest.schema.json", not schema.validate("manifest", m), schema.validate("manifest", m)[:3])
    check("build: manifest.json is canonical bytes", open(os.path.join(out, "manifest.json"), "rb").read() == rc.document_bytes(m))
    imgs = {i["name"]: i for i in m["images"]}
    check("build: images = compose placeholders", sorted(imgs) == ["app", "db", "egress-proxy", "functions", "migrator"], sorted(imgs))
    check("build: db image by registry digest", imgs["db"]["digest"] == e.db_digest)
    check("build: app images reproduce app.lock digests",
          all(imgs[n]["digest"] == e.lock["app"]["images"][n] for n in ("app", "functions", "migrator")))
    tree = fx.sh(["git", "rev-parse", "HEAD:egress/image"], cwd=e.node).stdout.decode().strip()
    check("build: egress-proxy tag from the egress/image tree",
          imgs["egress-proxy"]["ref"] == "ghcr.io/jakublog/legatto-node/egress-proxy:src-%s" % tree[:12], imgs["egress-proxy"]["ref"])
    ok = True
    for i in m["images"]:
        d = json.loads(fx.tar_members(os.path.join(out, i["artifact"]))["index.json"][1])["manifests"]
        ok &= len(d) == 1 and d[0]["digest"] == i["digest"] and d[0]["annotations"]["io.containerd.image.name"] == i["ref"]
    check("build: image archives are OCI with one named manifest", ok)
    cache = os.path.join(e.out_root, ".cache", "images")
    check("build: every image archive kept in the cache by digest",
          all(os.path.isfile(os.path.join(cache, i["digest"].split(":", 1)[1] + ".tar")) for i in m["images"]))
    try:
        rc.verify_bundle_files(out, m)
        check("build: every artifact matches size/sha256, nothing unlisted", True)
    except rc.ReleaseError as ex:
        check("build: every artifact matches size/sha256, nothing unlisted", False, str(ex))
    cfg = next(a for a in m["artifacts"] if a["kind"] == "config")
    members = fx.tar_members(os.path.join(out, cfg["name"]))
    compose = members["compose/docker-compose.legatto.yml"][1].decode()
    check("build: compose placeholders replaced by repo@digest",
          "%s@%s" % (e.db_ref.rsplit(":", 1)[0], e.db_digest) in compose and "@@" not in compose)
    check("build: executable bit kept in config.tar.gz", members["compose/volumes/api/entrypoint.sh"][0].mode == 0o755)
    check("build: dot-files not shipped", "compose/.env.example" not in members)
    files = {f["path"]: f for f in cfg["files"]}
    check("build: config files[] = archive files with sha256 and applier",
          set(files) == {n for n, (mi, _) in members.items() if mi.isfile()} and
          all(rc.sha256_bytes(members[p][1]) == f["sha256"] for p, f in files.items()) and
          files["caddy/sites.d/crm.caddy.tmpl"]["applier"] == "caddy-site" and
          files["systemd/legatto-stack.service"]["applier"] == "systemd-unit" and
          files["env/app.env.tmpl"]["applier"] == "env-template")
    check("build: canonical tar (uid 0, fixed mtime)",
          all(mi.uid == 0 and mi.gid == 0 and mi.mtime == members["compose"][0].mtime for mi, _ in members.values()))
    mig = fx.tar_members(os.path.join(out, "migrations.tar.gz"))
    check("build: migrations.tar.gz = migrations.files", sorted(mig) == ["20261121000000_init.sql"] and
          m["migrations"]["files"][0]["sha256"] == rc.sha256_bytes(mig["20261121000000_init.sql"][1]))
    kinds = {a["kind"] for a in m["artifacts"]}
    check("build: binary, deb, notes, sbom artifacts", {"binary", "deb", "notes", "sbom", "oci-archive", "config",
                                                        "sql-migrations"} <= kinds, kinds)
    expected_sboms = {"sbom-image-%s.cdx.json" % n for n in imgs} | {"sbom-binary-caddy.cdx.json",
                                                                    "sbom-deb-headscale.cdx.json"}
    if e.has_worker:
        expected_sboms.add("sbom-worker.cdx.json")
        w = next((a for a in m["artifacts"] if a["kind"] == "worker-bundle"), None)
        wfiles = fx.tar_members(os.path.join(out, w["name"])) if w else {}
        check("build: worker.tar.gz contains the entry file of manifest.worker",
              w is not None and any(d is not None and rc.sha256_bytes(d) == w["worker"]["entry_sha256"]
                                    for _, d in wfiles.values()) and "worker:selftest" in m["healthchecks"])
    sbom_subjects = {s["artifact"] for s in m["sbom"]}
    check("build: CycloneDX SBOM per image, binary, deb (and Worker)", sbom_subjects == expected_sboms, sorted(sbom_subjects))
    doc = json.load(open(os.path.join(out, "sbom-image-db.cdx.json")))
    check("build: SBOM is CycloneDX with release timestamp",
          doc.get("bomFormat") == "CycloneDX" and doc["metadata"]["timestamp"] == m["released_at"])
    notes = open(os.path.join(out, "notes.md"), encoding="utf-8").read()
    head = fx.sh(["git", "rev-parse", "HEAD"], cwd=e.node).stdout.decode().strip()
    check("build: notes.md = changelog + components", "Wydanie testowe 1.0.0" in notes and "Składniki" in notes
          and "legatto-node %s@%s" % (fx.NODE_REPO, head) in notes and "legatto-infra" not in notes)
    check("build: egress data from bundle/egress", "host" in m["egress"]["roles"])
    check("build: source pins exactly the node commit and the app release",
          sorted(m["source"]) == ["app", "node", "supabase_selfhosted"]
          and m["source"]["node"] == {"repo": fx.NODE_REPO, "commit": head}
          and m["source"]["app"]["release_sha256"] == e.lock["app"]["release_sha256"])
    check("build: no image reused on the first build", "użyte ponownie" not in res.stderr.decode(errors="replace"))
    return m


def test_reference(e, first):
    """A CI-like build: same commit, empty image cache, no published archives."""
    cache = os.path.join(e.out_root, ".cache", "images")
    shutil.move(cache, cache + ".aside")
    ref_dir = os.path.join(e.t, "reference-build")
    try:
        fx.build(e, "1.0.0", out=ref_dir, extra=["--no-reuse-published"])
    finally:
        shutil.rmtree(cache, ignore_errors=True)
        shutil.move(cache + ".aside", cache)
    ref = manifest(ref_dir)
    check("reference: second build of the commit without cache = same manifest except image archive bytes",
          masked(ref) == masked(first), [k for k in masked(ref) if masked(ref)[k] != masked(first).get(k)])


def test_reuse_cache(e, first):
    def drop_worker(env):
        shutil.rmtree(os.path.join(env.node, "worker"), ignore_errors=True)

    fx.add_release(e, "1.0.1", 2, extra_commit=drop_worker)
    res = fx.build(e, "1.0.1")
    m = manifest(os.path.join(e.out_root, "1.0.1"))
    old, new = images_by_name(first), images_by_name(m)
    check("reuse: egress-proxy digest and tag unchanged while egress/image is unchanged",
          new["egress-proxy"]["digest"] == old["egress-proxy"]["digest"] and new["egress-proxy"]["ref"] == old["egress-proxy"]["ref"])
    check("reuse: every unchanged image keeps the archive sha256 and size of the earlier release",
          all((new[n]["sha256"], new[n]["size"]) == (old[n]["sha256"], old[n]["size"]) for n in old),
          {n: (old[n]["sha256"][:12], new[n]["sha256"][:12]) for n in old})
    check("reuse: the builder reports the reused archives",
          res.stderr.decode(errors="replace").count("użyte ponownie") == len(old))
    check("reuse: released_at follows the new commit", m["released_at"] > first["released_at"])
    return m


def sign(e, key, path, ns):
    fx.sh([e.keygen, "-Y", "sign", "-f", key, "-n", ns, path])
    os.replace(path + ".sig", path + ".release-a.sig")


def test_reuse_published(e, previous):
    """Empty cache: archives come from a published release, checked against its signed manifest."""
    kd = os.path.join(e.t, "keys")
    os.makedirs(kd)
    key = os.path.join(kd, "release-a")
    fx.sh([e.keygen, "-q", "-t", "ed25519", "-N", "", "-C", "release-a", "-f", key])
    allowed = os.path.join(kd, "allowed_signers")
    fx.write(allowed, 'release-a@legatto.pl namespaces="legatto-release,legatto-index" %s\n'
             % " ".join(open(key + ".pub").read().split()[:2]))
    mirror = os.path.join(e.t, "mirror")
    src = os.path.join(e.out_root, previous["version"])
    rel_dir = os.path.join(mirror, "releases", previous["version"])
    shutil.copytree(src, rel_dir)
    sign(e, key, os.path.join(rel_dir, "manifest.json"), "legatto-release")
    index = {"schema": "legatto-index/1", "product": "legatto", "sequence": 1, "issued_at": rc.fmt_ts(e.epoch),
             "expires": rc.fmt_ts(e.epoch + 35 * 86400), "krl_sha256": None,
             "releases": [{"version": previous["version"], "sequence": previous["sequence"], "type": previous["type"],
                           "manifest_sha256": rc.sha256_file(os.path.join(rel_dir, "manifest.json")),
                           "attestation_sha256": None, "promotions": {"early": None, "stable": None}, "yanked": False}]}
    fx.write(os.path.join(mirror, "index.json"), rc.document_bytes(index))
    sign(e, key, os.path.join(mirror, "index.json"), "legatto-index")
    shutil.rmtree(os.path.join(e.out_root, ".cache", "images"))
    fx.add_release(e, "1.0.2", 3)
    env = {"LEGATTO_UPDATES_URL": "file://" + mirror, "LEGATTO_ALLOWED_SIGNERS": allowed}
    res = fx.build(e, "1.0.2", env=env)
    m = manifest(os.path.join(e.out_root, "1.0.2"))
    old, new = images_by_name(previous), images_by_name(m)
    check("published: archives of the published release reused (same sha256) with an empty cache",
          all(new[n]["sha256"] == old[n]["sha256"] for n in old), res.stderr.decode(errors="replace")[-600:])
    # a tampered published archive is refused (sha256 against the signed manifest), the image is rebuilt
    shutil.rmtree(os.path.join(e.out_root, ".cache"))
    db_art = os.path.join(rel_dir, old["db"]["artifact"])
    with open(db_art, "ab") as f:
        f.write(b"\0" * 1024)
    fx.add_release(e, "1.0.3", 4)
    res = fx.build(e, "1.0.3", env=env)
    m3 = manifest(os.path.join(e.out_root, "1.0.3"))
    check("published: a tampered archive on the hosting is not used",
          images_by_name(m3)["db"]["sha256"] != rc.sha256_file(db_art) and "sha256" in res.stderr.decode(errors="replace"))
    shutil.rmtree(os.path.join(e.t, "keys"))


def test_refusals(e):
    fx.write(os.path.join(e.node, "stray.txt"), "x")
    res = fx.build(e, "1.0.3", out=os.path.join(e.t, "dirty"), ok=False)
    check("build: refuses a dirty tree", res.returncode == 1 and b"niezatwierdzone" in res.stderr)
    os.unlink(os.path.join(e.node, "stray.txt"))
    res = fx.build(e, "1.0.3", ok=False)
    check("build: refuses to overwrite an existing bundle", res.returncode == 1 and b"istnieje" in res.stderr)
    res = fx.build(e, "9.9.9", out=os.path.join(e.t, "no-notes"), ok=False)
    check("build: refuses a version without release notes", res.returncode == 1 and b"9.9.9" in res.stderr)


def main():
    for tool in ("docker", "syft", "yq", "git"):
        if not shutil.which(tool):
            print("FAIL missing tool: %s" % tool)
            return 1
    t = tempfile.mkdtemp(prefix="legatto-test-build-")
    e = None
    try:
        e = fx.setup(t, with_worker=True)
        first = test_first(e)
        test_reference(e, first)
        second = test_reuse_cache(e, first)
        test_reuse_published(e, second)
        test_refusals(e)
    except Exception:
        traceback.print_exc()
        results.append((False, "builder test crashed", ""))
    finally:
        fx.teardown(e)
        if os.environ.get("LEGATTO_TEST_KEEP") == "1":
            print("kept: %s" % t)
        else:
            shutil.rmtree(t, ignore_errors=True)
    failed = [r for r in results if not r[0]]
    print("builder: %d checks, %d failures" % (len(results), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
