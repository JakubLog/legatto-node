"""legatto-site-publish — builds the MP's public site on the office server and
uploads it to Cloudflare Pages (office account), without any office address
in the output.

  legatto-site-publish run [--actor JSON]     unit legatto-site-publisher.service (timer, 1 min)
  legatto-site-publish drift [--actor JSON]   compare Cloudflare with our own last deployments
  legatto-site-publish status

`run` takes at most one job per invocation; each step is its own container
(app image of the installed release, uid 65532, read-only rootfs):

  claim     legatto-int        DB role legatto_publisher       -> job id or nothing
  snapshot  legatto-int        public data + assets            -> work/snapshot
  build     --network none     static generator                 -> work/dist
  guard     host (Python)      zero-address scan (guard.py)
  deploy    legatto-egress-publish  Pages token, pinned CA      -> deployment id
  finish    legatto-int        job result

The Cloudflare token is only ever mounted into the deploy container, which has
no database access; the database password only into claim/snapshot/finish,
which have no route out. Every 15 minutes without a job, `run` also performs
the drift check.

Exit codes: 0 OK / nothing to do, 1 error, 2 usage, 3 locked,
4 precondition, 20 zero-address guard rejected the build.
"""

from __future__ import annotations

import argparse
import os
import re
import time
from pathlib import Path
from typing import Any

from . import common, guard, worker_deploy
from .common import ContainerSpec, Credentials, Mount, fail, path

TOOL = "legatto-site-publish"
EXIT_GUARD = 20
SITE_CLI = "/app/server/site.mjs"
CRED_TARGET = "/run/credentials"
WORK_TARGET = "/work"
DRIFT_INTERVAL_SECONDS = 15 * 60
PAGES_BRANCH = "main"
JOB_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _db_spec(image: common.Image, creds: Credentials, command: list[str], mounts: list[Mount]) -> ContainerSpec:
    return ContainerSpec(
        image=image,
        command=[SITE_CLI, *command],
        network=common.NET_INT,
        mounts=[Mount(creds.get(common.CRED_DB_PUBLISHER), f"{CRED_TARGET}/{common.CRED_DB_PUBLISHER}"), *mounts],
        env={
            "PGHOST": "db",
            "PGPORT": "5432",  # contract: legatto_ports.local.db
            "PGDATABASE": "postgres",
            "PGUSER": "legatto_publisher",
            "LEGATTO_DB_PASSWORD_FILE": f"{CRED_TARGET}/{common.CRED_DB_PUBLISHER}",
        },
        name_prefix="legatto-site",
        memory="1g",
        tmpfs_size="256m",
    )


def deny_hosts(env: dict[str, str]) -> list[str]:
    return [env["LEGATTO_HOST_VPN"], env["LEGATTO_HOST_CRM"], env["LEGATTO_HOST_ADMIN"], env["LEGATTO_HOST_STUDIO"],
            f"tn.{env['LEGATTO_OFFICE_DOMAIN']}", env["LEGATTO_PUBLIC_IPV4"], env["LEGATTO_TS_IP4"], env["LEGATTO_TS_IP6"]]


def site_config(env: dict[str, str], cf: dict[str, Any]) -> dict[str, Any]:
    form_key = common.read_json(path(common.P_INTAKE_ETC) / "keys" / "current.json")
    if not isinstance(form_key, dict):
        fail("office form key is missing; run legatto-intake keygen", common.EXIT_PRECONDITION)
    return {
        "v": 1,
        "origin": f"https://{env['LEGATTO_HOST_SITE']}",
        "turnstile_sitekey": cf["turnstile"]["sitekey"],
        "form_key": {"v": 1, "kid": form_key["kid"], "x25519": form_key["x25519"]},
    }


def _state() -> dict[str, Any]:
    return common.read_json(path(common.P_PUBLISH_STATE) / "state.json", {}) or {}


def _save(state: dict[str, Any], ok: bool) -> None:
    common.write_json_atomic(path(common.P_PUBLISH_STATE) / "state.json", state, 0o640)
    common.write_status("publish", ok, {
        "state": state.get("state", "none"),
        "last_ok_at": state.get("last_ok_at"),
        "deployment_id": state.get("deployment_id"),
    })


def _clean_work(work_root: Path) -> None:
    for job_dir in work_root.iterdir() if work_root.is_dir() else []:
        for entry in sorted(job_dir.rglob("*"), key=lambda p: len(p.parts), reverse=True):
            if entry.is_dir() and not entry.is_symlink():
                entry.rmdir()
            else:
                entry.unlink()
        job_dir.rmdir()


def _finish(image: common.Image, creds: Credentials, job: str, status: str, deployment_id: str | None, error: str | None) -> None:
    command = ["finish", "--job", job, "--status", status]
    if deployment_id:
        command += ["--deployment-id", deployment_id]
    if error:
        command += ["--error", error]
    code, _ = common.run_container(_db_spec(image, creds, command, []), timeout=120)
    if code != 0:
        common.log(f"finish for job {job} failed (exit {code})")


def publish_job(actor: dict[str, Any], image: common.Image, creds: Credentials, job: str, reason: str) -> int:
    env = common.office_env()
    cf = common.cloudflare_config()
    work_root = common.ensure_dir(path(common.P_PUBLISH_STATE) / "work", 0o700, common.CONTAINER_UID, common.CONTAINER_UID)
    _clean_work(work_root)
    work = common.ensure_dir(work_root / job, 0o700, common.CONTAINER_UID, common.CONTAINER_UID)
    for sub in ("snapshot", "dist"):
        common.ensure_dir(work / sub, 0o700, common.CONTAINER_UID, common.CONTAINER_UID)
    common.write_json_atomic(work / "site-config.json", site_config(env, cf), 0o400,
                             common.CONTAINER_UID if os.geteuid() == 0 else None)
    state = _state()

    def failed(code: str, exit_code: int = common.EXIT_ERROR) -> int:
        _finish(image, creds, job, "failed", None, code)
        state.update({"state": "failed", "failed_at": common.utc_now(), "error": code})
        _save(state, False)
        common.audit("publish", "publish.failed", actor, {"job": job, "reason": reason, "error": code})
        common.emit({"ok": False, "job": job, "error": code})
        return exit_code

    code, out = common.run_container(_db_spec(image, creds, ["snapshot", "--out", f"{WORK_TARGET}/snapshot",
                                                            "--storage-url", f"http://api-gw:{common.API_GW_PORT}"],
                                              [Mount(work / "snapshot", f"{WORK_TARGET}/snapshot", readonly=False)]),
                                     timeout=600)
    if code != 0 or out is None:
        return failed("snapshot")

    build_cmd = [SITE_CLI, "build", "--snapshot", f"{WORK_TARGET}/snapshot", "--site-config", f"{WORK_TARGET}/site-config.json",
                 "--out", f"{WORK_TARGET}/dist"]
    for host in deny_hosts(env):
        build_cmd += ["--deny-host", host]
    build = ContainerSpec(
        image=image, command=build_cmd, network="none",
        mounts=[Mount(work / "snapshot", f"{WORK_TARGET}/snapshot"),
                Mount(work / "site-config.json", f"{WORK_TARGET}/site-config.json"),
                Mount(work / "dist", f"{WORK_TARGET}/dist", readonly=False)],
        env={}, name_prefix="legatto-site-build", memory="2g", tmpfs_size="512m")
    code, out = common.run_container(build, timeout=1200)
    if code == EXIT_GUARD:
        return failed("zero_address_app", EXIT_GUARD)
    if code != 0 or out is None:
        return failed("build")

    findings = guard.scan(work / "dist", env)
    if findings:
        for finding in findings[:50]:
            common.log(f"zero-address guard: {finding.file}: {finding.rule}")
        state["guard"] = {"at": common.utc_now(), "rules": sorted({f.rule for f in findings})}
        return failed("zero_address", EXIT_GUARD)

    tools = worker_deploy.tools_dir()
    pages_file = work / "pages.json"
    common.write_json_atomic(pages_file, {"account_id": cf["account_id"], "project": cf["pages"]["project"],
                                          "branch": PAGES_BRANCH}, 0o400,
                             common.CONTAINER_UID if os.geteuid() == 0 else None)
    code, out = common.run_container(
        worker_deploy.tools_spec(image, tools, ["pages-deploy", "--config", "/cfg/pages.json", "--dir", f"{WORK_TARGET}/dist"],
                                 [Mount(pages_file, "/cfg/pages.json"), Mount(work / "dist", f"{WORK_TARGET}/dist")], creds),
        timeout=1800)
    deployment_id = (out or {}).get("deployment_id")
    if code != 0 or not isinstance(deployment_id, str):
        return failed("pages_deploy")

    _finish(image, creds, job, "ok", deployment_id, None)
    now = common.utc_now()
    state.update({"state": "ok", "last_ok_at": now, "deployment_id": deployment_id, "error": None})
    _save(state, True)
    common.audit("publish", "publish.deployed", actor, {"job": job, "reason": reason, "deployment_id": deployment_id,
                                                         "files": (out or {}).get("files")})
    _clean_work(work_root)
    common.emit({"ok": True, "job": job, "deployment_id": deployment_id})
    return common.EXIT_OK


def drift(actor: dict[str, Any], image: common.Image, creds: Credentials) -> dict[str, Any]:
    """Compares the live Worker version and the latest Pages deployment with our records.

    A difference means something deployed to the office Cloudflare account
    from outside this server (e.g. a hijacked account): audit publish.drift.
    """
    cf = common.cloudflare_config()
    tools = worker_deploy.tools_dir()
    report: dict[str, Any] = {"at": common.utc_now(), "worker": None, "pages": None}
    worker_state = common.read_json(path(common.P_WORKER_STATE) / "state.json", {}) or {}
    deploy_file = path(common.P_WORKER_STATE) / "deploy.json"
    if worker_state.get("state") == "ok" and deploy_file.is_file():
        code, out = common.run_container(
            worker_deploy.tools_spec(image, tools, ["worker-state", "--config", "/cfg/deploy.json"],
                                     [Mount(deploy_file, "/cfg/deploy.json")], creds), timeout=300)
        if code == 0 and out is not None:
            live = [v.get("version_id") for v in out.get("versions", []) if v.get("percentage") == 100]
            report["worker"] = "ok" if live == [worker_state.get("version_id")] else "drift"
    publish_state = _state()
    if publish_state.get("deployment_id"):
        pages_file = path(common.P_PUBLISH_STATE) / "pages.json"
        common.write_json_atomic(pages_file, {"account_id": cf["account_id"], "project": cf["pages"]["project"],
                                              "branch": PAGES_BRANCH}, 0o644)
        code, out = common.run_container(
            worker_deploy.tools_spec(image, tools, ["pages-state", "--config", "/cfg/pages.json"],
                                     [Mount(pages_file, "/cfg/pages.json")], creds), timeout=300)
        if code == 0 and out is not None:
            latest = (out.get("latest") or {}).get("id")
            report["pages"] = "ok" if latest == publish_state.get("deployment_id") else "drift"
    drifted = [name for name in ("worker", "pages") if report[name] == "drift"]
    if drifted:
        common.audit("publish", "publish.drift", actor, {"components": drifted})
        if "worker" in drifted:
            worker_state["state"] = "drift"
            common.write_json_atomic(path(common.P_WORKER_STATE) / "state.json", worker_state, 0o640)
            common.write_status("worker", False, {"state": "drift", "release": worker_state.get("release"),
                                                  "version_id": worker_state.get("version_id"),
                                                  "deployed_at": worker_state.get("deployed_at")})
        if "pages" in drifted:
            publish_state["state"] = "drift"
            _save(publish_state, False)
    publish_state = _state()
    publish_state["drift_checked_at"] = time.time()
    common.write_json_atomic(path(common.P_PUBLISH_STATE) / "state.json", publish_state, 0o640)
    return report


def cmd_run(args: argparse.Namespace) -> int:
    common.require_root()
    actor = common.parse_actor(args.actor, TOOL)
    with common.Lock("site-publish"):
        common.ensure_dir(path(common.P_PUBLISH_STATE), 0o750)
        image, _ = common.release_image(path(common.P_CURRENT))
        common.cloudflare_config()
        with Credentials(TOOL) as creds:
            code, out = common.run_container(_db_spec(image, creds, ["claim"], []), timeout=120)
            if code != 0 or out is None:
                fail(f"claim failed (exit {code})")
            job = out.get("job")
            if job is None:
                if time.time() - float(_state().get("drift_checked_at", 0)) >= DRIFT_INTERVAL_SECONDS:
                    common.emit({"ok": True, "job": None, "drift": drift(actor, image, creds)})
                else:
                    common.emit({"ok": True, "job": None})
                return common.EXIT_OK
            if not isinstance(job, str) or not JOB_RE.match(job):
                fail("claim returned an invalid job id")
            return publish_job(actor, image, creds, job, str(out.get("reason", "manual"))[:40])


def cmd_drift(args: argparse.Namespace) -> int:
    common.require_root()
    actor = common.parse_actor(args.actor, TOOL)
    with common.Lock("site-publish"):
        image, _ = common.release_image(path(common.P_CURRENT))
        with Credentials(TOOL) as creds:
            report = drift(actor, image, creds)
    common.emit({"ok": "drift" not in (report["worker"], report["pages"]), **report})
    return common.EXIT_OK


def cmd_status(_args: argparse.Namespace) -> int:
    status = common.read_json(path(common.P_STATUS) / "publish.json")
    if status is None:
        fail("publish.json does not exist yet", common.EXIT_PRECONDITION)
    common.emit(status)
    return common.EXIT_OK


def cmd_guard(args: argparse.Namespace) -> int:
    """Runs only the zero-address guard on a directory (operator diagnostics, verify.sh)."""
    findings = guard.scan(Path(args.dir), common.office_env())
    common.emit({"ok": not findings, "findings": [{"file": f.file, "rule": f.rule} for f in findings]})
    return common.EXIT_OK if not findings else EXIT_GUARD


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog=TOOL, description="Build and publish the public site to Cloudflare Pages.")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run")
    run.add_argument("--actor")
    run.set_defaults(func=cmd_run)
    drift_cmd = sub.add_parser("drift")
    drift_cmd.add_argument("--actor")
    drift_cmd.set_defaults(func=cmd_drift)
    status = sub.add_parser("status")
    status.add_argument("--json", action="store_true")
    status.set_defaults(func=cmd_status)
    guard_cmd = sub.add_parser("guard")
    guard_cmd.add_argument("--dir", required=True)
    guard_cmd.set_defaults(func=cmd_guard)
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return common.EXIT_USAGE if exc.code else common.EXIT_OK
    return common.main_wrapper(TOOL, lambda: args.func(args))

