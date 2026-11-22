"""legatto-worker-deploy — deploys the legatto-forms Worker from a verified
release bundle to the office's own Cloudflare account (pull, Aneks 1).

Called by legatto-update after a green health check when the manifest has a
`worker-bundle` artifact (applier `worker`), and once by the worker_deployer
role at installation:

  legatto-worker-deploy --release-dir /opt/legatto/releases/<v> [--actor JSON]
  legatto-worker-deploy status

Steps: verify the artifact against the manifest, extract it, render the
non-secret deploy config, run `tools.mjs worker-deploy` in the app image
(network legatto-egress-publish, Pages/Workers token, pinned CA), then prove
the full path with `legatto-intake selftest --wait`. A failed self-test rolls
the Worker back to the previous version.

Exit codes: 0 deployed (or already current), 1 error, 2 usage, 3 locked,
4 precondition (Cloudflare not bootstrapped, no keys), 60 deployment failed
and rolled back in Cloudflare (the server-side release stays installed).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import tarfile
from pathlib import Path
from typing import Any

from . import common, ed25519
from .common import ContainerSpec, Credentials, Mount, fail, path

TOOL = "legatto-worker-deploy"
EXIT_ROLLED_BACK = 60
BUNDLE_FILES = ("worker.js", "tools.mjs", "bundle.json")
TOOLS_ENTRY = "/w/tools.mjs"
CONTAINER_CA = "/etc/legatto/ca/cloudflare-api.pem"  # contract: legatto_paths.cf_ca_bundle
TOKEN_TARGET = f"/run/credentials/{common.CRED_CF_PAGES}"
TURNSTILE_ACTION = "submit_case"
# Edge rate limits (per Cloudflare location, period 10 or 60 s); the hourly
# limits stay in intake.submit_public_case in the office database.
RATELIMITS = {
    "RL_IP": {"namespace_id": "1001", "limit": 2, "period": 60},
    "RL_GLOBAL": {"namespace_id": "1002", "limit": 30, "period": 60},
    "RL_SELFTEST": {"namespace_id": "1003", "limit": 2, "period": 60},
}
HEALTH_TIMEOUT_SECONDS = 120
SELFTEST_WAIT_SECONDS = 300


def _sha256_file(target: Path) -> str:
    digest = hashlib.sha256()
    with open(target, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def worker_artifact(release_dir: Path, manifest: dict[str, Any]) -> dict[str, Any] | None:
    for artifact in manifest.get("artifacts", []):
        if artifact.get("kind") == "worker-bundle":
            return artifact
    return None


def extract_bundle(release_dir: Path, manifest: dict[str, Any]) -> tuple[Path, dict[str, Any]] | None:
    """Verifies and unpacks the worker bundle to worker_state/bundles/<entry sha256>/."""
    artifact = worker_artifact(release_dir, manifest)
    if artifact is None:
        return None
    worker = artifact["worker"]
    archive = release_dir / "artifacts" / artifact["name"]
    if not archive.is_file() or _sha256_file(archive) != artifact["sha256"]:
        fail(f"worker bundle {archive} does not match the manifest", common.EXIT_ERROR)
    target = path(common.P_WORKER_STATE) / "bundles" / worker["entry_sha256"]
    if not (target / "bundle.json").is_file():
        staging = common.ensure_dir(target.with_name(f".{target.name}.tmp"), 0o755)
        with tarfile.open(archive, "r:gz") as tar:
            members = {m.name: m for m in tar.getmembers()}
            if sorted(members) != sorted(BUNDLE_FILES) or not all(m.isreg() for m in members.values()):
                fail("worker bundle must contain exactly worker.js, tools.mjs and bundle.json", common.EXIT_ERROR)
            for name in BUNDLE_FILES:
                source = tar.extractfile(members[name])
                assert source is not None
                common.write_atomic(staging / name, source.read(), 0o644)
        os.replace(staging, target)
    bundle = common.read_json(target / "bundle.json", {})
    if _sha256_file(target / "worker.js") != worker["entry_sha256"] or bundle.get("entry_sha256") != worker["entry_sha256"]:
        fail("worker.js does not match manifest worker.entry_sha256", common.EXIT_ERROR)
    if bundle.get("script_name") != worker["script_name"] or _sha256_file(target / "tools.mjs") != bundle.get("tools_sha256"):
        fail("bundle.json is inconsistent with the bundle", common.EXIT_ERROR)
    return target, bundle


def tools_dir() -> Path:
    """Bundle directory of the installed release (tools.mjs for the publisher)."""
    release = path(common.P_CURRENT)
    manifest = common.read_json(release / "manifest.json")
    if not isinstance(manifest, dict):
        fail(f"{release}/manifest.json is missing", common.EXIT_PRECONDITION)
    extracted = extract_bundle(release, manifest)
    if extracted is None:
        fail("the installed release has no worker bundle (tools.mjs)", common.EXIT_PRECONDITION)
    return extracted[0]


def _read_pub(target: Path, what: str) -> bytes:
    try:
        pub = base64.b64decode(target.read_text(encoding="ascii").strip(), validate=True)
    except (FileNotFoundError, ValueError):
        fail(f"{what} ({target}) is missing", common.EXIT_PRECONDITION)
    if len(pub) != 32:
        fail(f"{what} ({target}) is not a 32-byte key", common.EXIT_PRECONDITION)
    return pub


def deploy_config(manifest: dict[str, Any], bundle: dict[str, Any], cf: dict[str, Any], env: dict[str, str]) -> dict[str, Any]:
    form_key = common.read_json(path(common.P_INTAKE_ETC) / "keys" / "current.json")
    if not isinstance(form_key, dict) or "kid" not in form_key:
        fail("office form key is missing; run legatto-intake keygen", common.EXIT_PRECONDITION)
    selftest_pub = _read_pub(path(common.P_INTAKE_ETC) / "selftest.pub", "self-test public key")
    signer = common.read_json(path(common.P_WORKER_STATE) / "signer.json")
    if not isinstance(signer, dict) or "kid" not in signer:
        fail("Worker signer key is missing; run the cf_bootstrap role", common.EXIT_PRECONDITION)
    site = env["LEGATTO_HOST_SITE"]
    return {
        "account_id": cf["account_id"],
        "zone_id": cf["zone_id"],
        "site_host": site,
        "script_name": bundle["script_name"],
        "queue_name": cf["queue"]["name"],
        "compatibility_date": bundle["compatibility_date"],
        "entry": "worker.js",
        "entry_sha256": bundle["entry_sha256"],
        "release": manifest["version"],
        "ratelimits": RATELIMITS,
        "vars": {
            "OFFICE_X25519_PUB": form_key["x25519"],
            "OFFICE_KID": form_key["kid"],
            "SELFTEST_ED25519_PUB": base64.b64encode(selftest_pub).decode(),
            "SITE_ORIGIN": f"https://{site}",
            "TURNSTILE_HOSTNAMES": site,
            "TURNSTILE_ACTION": TURNSTILE_ACTION,
            "RELEASE": manifest["version"],
        },
        "expected_signer_kid": signer["kid"],
        "health_timeout_seconds": HEALTH_TIMEOUT_SECONDS,
    }


def tools_spec(image: common.Image, bundle_dir: Path, args: list[str], mounts: list[Mount], creds: Credentials) -> ContainerSpec:
    env = {"LEGATTO_CF_TOKEN_FILE": TOKEN_TARGET, "LEGATTO_CF_CA_FILE": CONTAINER_CA}
    env.update(common.proxy_env(common.PROXY_PUBLISH))
    return ContainerSpec(
        image=image,
        command=[TOOLS_ENTRY, *args],
        network=common.NET_EGRESS_PUBLISH,
        mounts=[
            Mount(bundle_dir, "/w"),
            Mount(creds.get(common.CRED_CF_PAGES), TOKEN_TARGET),
            Mount(path(common.P_CF_CA_BUNDLE), CONTAINER_CA),
            *mounts,
        ],
        env=env,
        name_prefix="legatto-cf-tools",
    )


def _stage(name: str, data: bytes) -> Path:
    """Input file for one container run in /run/legatto/credentials (tmpfs), owned by the container uid."""
    base = common.ensure_dir(path(common.P_RUN) / "credentials", 0o700)
    target = base / f"{TOOL}-{os.getpid()}-{name}"
    common.write_atomic(target, data, 0o400, common.CONTAINER_UID if os.geteuid() == 0 else None)
    return target


def _shred(target: Path) -> None:
    size = target.stat().st_size
    with open(target, "r+b") as handle:
        handle.write(os.urandom(size))
        handle.flush()
        os.fsync(handle.fileno())
    target.unlink()


def _selftest(wait_seconds: int) -> int:
    binary = os.environ.get("LEGATTO_INTAKE_BIN", "legatto-intake")  # contract: legatto_cli.intake
    result = subprocess.run([binary, "selftest", "--mode", "ping", "--wait", str(wait_seconds)],
                            capture_output=True, text=True, check=False, timeout=wait_seconds + 600)
    for line in result.stderr.splitlines()[-10:]:
        common.log(f"[selftest] {line}")
    return result.returncode


def _record(state: dict[str, Any], ok: bool) -> None:
    common.write_json_atomic(path(common.P_WORKER_STATE) / "state.json", state, 0o640)
    common.write_status("worker", ok, {
        "state": state["state"],
        "release": state.get("release"),
        "version_id": state.get("version_id"),
        "deployed_at": state.get("deployed_at"),
    })


def cmd_deploy(args: argparse.Namespace) -> int:
    common.require_root()
    actor = common.parse_actor(args.actor, TOOL)
    release_dir = Path(args.release_dir)
    manifest = common.read_json(release_dir / "manifest.json")
    if not isinstance(manifest, dict):
        fail(f"{release_dir}/manifest.json is missing", common.EXIT_PRECONDITION)
    with common.Lock("worker-deploy"):
        common.ensure_dir(path(common.P_WORKER_STATE), 0o750)
        extracted = extract_bundle(release_dir, manifest)
        if extracted is None:
            common.emit({"ok": True, "changed": False, "reason": "release has no worker bundle"})
            return common.EXIT_OK
        bundle_dir, bundle = extracted
        cf = common.cloudflare_config()
        env = common.office_env()
        config = deploy_config(manifest, bundle, cf, env)
        config_bytes = (json.dumps(config, sort_keys=True) + "\n").encode()
        config_sha = hashlib.sha256(config_bytes).hexdigest()
        state = common.read_json(path(common.P_WORKER_STATE) / "state.json", {}) or {}
        pending = path(common.P_WORKER_STATE) / "secrets-pending.json"
        if state.get("state") == "ok" and state.get("config_sha256") == config_sha and not pending.exists() and not args.force:
            common.emit({"ok": True, "changed": False, "version_id": state.get("version_id")})
            return common.EXIT_OK

        image, _ = common.release_image(release_dir)
        common.write_atomic(path(common.P_WORKER_STATE) / "deploy.json", config_bytes, 0o644)
        with Credentials(TOOL) as creds:
            config_file = _stage("deploy.json", config_bytes)
            mounts = [Mount(config_file, "/cfg/deploy.json")]
            tool_args = ["worker-deploy", "--config", "/cfg/deploy.json", "--bundle", "/w"]
            secrets_file = None
            if pending.exists():
                secrets_file = _stage("secrets.json", pending.read_bytes())
                mounts.append(Mount(secrets_file, "/cfg/secrets.json"))
                tool_args += ["--secrets", "/cfg/secrets.json"]
            try:
                code, out = common.run_container(tools_spec(image, bundle_dir, tool_args, mounts, creds), timeout=900)
                result = out or {}
                if code == 0 and not args.no_selftest and _selftest(args.selftest_timeout) != 0:
                    previous = result.get("previous_versions") or []
                    if previous:
                        versions_file = _stage("versions.json", json.dumps(previous).encode())
                        rb_code, _ = common.run_container(
                            tools_spec(image, bundle_dir, ["worker-rollback", "--config", "/cfg/deploy.json",
                                                           "--versions", "/cfg/versions.json"],
                                       [Mount(config_file, "/cfg/deploy.json"), Mount(versions_file, "/cfg/versions.json")],
                                       creds),
                            timeout=300)
                        code = EXIT_ROLLED_BACK if rb_code == 0 else common.EXIT_ERROR
                    else:
                        code = common.EXIT_ERROR
                    result["error"] = "selftest_failed"
            finally:
                for staged in path(common.P_RUN).joinpath("credentials").glob(f"{TOOL}-{os.getpid()}-*"):
                    staged.unlink(missing_ok=True)

        now = common.utc_now()
        if code == 0:
            if pending.exists():
                _shred(pending)  # the private Worker keys now live only in Cloudflare
            new_state = {"state": "ok", "release": manifest["version"], "version_id": result.get("version_id"),
                         "deployed_at": now, "entry_sha256": bundle["entry_sha256"], "config_sha256": config_sha}
            _record(new_state, True)
            common.audit("publish", "publish.worker_deployed", actor,
                         {"release": manifest["version"], "version_id": result.get("version_id"),
                          "entry_sha256": bundle["entry_sha256"]})
            common.emit({"ok": True, "changed": True, "version_id": result.get("version_id")})
            return common.EXIT_OK
        failed_state = dict(state)
        failed_state.update({"state": "failed", "failed_at": now, "failed_release": manifest["version"]})
        _record(failed_state, False)
        common.audit("publish", "publish.worker_failed", actor,
                     {"release": manifest["version"], "rolled_back": code == EXIT_ROLLED_BACK,
                      "error": str(result.get("error", f"exit {code}"))[:200]})
        common.emit({"ok": False, "rolled_back": code == EXIT_ROLLED_BACK, "error": result.get("error")})
        return EXIT_ROLLED_BACK if code == EXIT_ROLLED_BACK else common.EXIT_ERROR


def stage_worker_secrets(turnstile_secret: str) -> str:
    """New Worker signing key and IP hash key, pending until the next deploy.

    The private signing key never leaves the server except into the Worker
    secret; after a successful deploy the pending file is shredded. Returns
    the new signer kid; the public key goes to intake signers.d.
    """
    seed = ed25519.generate_seed()
    pub = ed25519.public_key(seed)
    kid = ed25519.key_id(pub).hex()
    secrets_obj = {
        "TURNSTILE_SECRET": turnstile_secret,
        "IP_HASH_KEY": base64.b64encode(os.urandom(32)).decode(),
        "SIGNING_KEY": base64.b64encode(seed).decode(),
    }
    state_dir = common.ensure_dir(path(common.P_WORKER_STATE), 0o750)
    common.write_json_atomic(state_dir / "secrets-pending.json", secrets_obj, 0o600)
    signers = common.ensure_dir(path(common.P_INTAKE_ETC) / "signers.d", 0o755)
    common.write_atomic(signers / f"{kid}.pub", base64.b64encode(pub) + b"\n", 0o644)
    common.write_json_atomic(state_dir / "signer.json", {"kid": kid, "created_at": common.utc_now()}, 0o644)
    return kid


def cmd_status(_args: argparse.Namespace) -> int:
    status = common.read_json(path(common.P_STATUS) / "worker.json")
    if status is None:
        fail("worker.json does not exist yet", common.EXIT_PRECONDITION)
    common.emit(status)
    return common.EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog=TOOL, description="Deploy the legatto-forms Worker from a release bundle.")
    parser.add_argument("--release-dir")
    parser.add_argument("--actor")
    parser.add_argument("--force", action="store_true", help="deploy even if the same config is already live")
    parser.add_argument("--no-selftest", action="store_true", help="skip the end-to-end self-test (installation only)")
    parser.add_argument("--selftest-timeout", type=int, default=SELFTEST_WAIT_SECONDS, metavar="SECONDS",
                        help="how long to wait for the self-test envelope to reach the processor")
    parser.add_argument("command", nargs="?", choices=("deploy", "status"), default="deploy")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return common.EXIT_USAGE if exc.code else common.EXIT_OK
    if args.command == "status":
        return common.main_wrapper(TOOL, lambda: cmd_status(args))
    if not args.release_dir:
        parser.print_usage()
        return common.EXIT_USAGE
    return common.main_wrapper(TOOL, lambda: cmd_deploy(args))
