"""legatto-cf-bootstrap — one-time setup of the office's own Cloudflare account
(D14/U5). Runs on the server, only from the cf_bootstrap role in a
break-glass window.

The office admin creates a short-lived bootstrap token (TTL 24 h) in the
office account; it is given on stdin and never written anywhere. With it the
tool creates (idempotently):

  * queues `forms` and `forms-dlq` (14 days retention) with HTTP pull consumers,
  * the Turnstile widget for the site host (action checked by the Worker),
  * the Pages project with the site host as custom domain,
  * three office tokens, each limited to the server's public IPv4:
      queues  -> Queues Write                                      (intake fetch)
      pages   -> Pages Write, Workers Scripts Write (account) +
                 Workers Routes Write (zone)                       (publisher, Worker deploy)
      dns     -> DNS Write + Zone Read on the office zone only      (lego DNS-01)
    written straight into /etc/credstore.encrypted (systemd-creds),
  * the Worker secrets (new Ed25519 signing key, IP hash key, Turnstile
    secret), pending for the next legatto-worker-deploy,
and finally deletes the bootstrap token. Nothing secret is printed: stdout is
one JSON object with ids only; cloudflare.json holds the same ids.

Exit codes: 0 OK, 1 error, 2 usage, 3 locked, 4 precondition,
40 Cloudflare API refused a step (message names the step, never a token).
"""

from __future__ import annotations

import argparse
import os
import re
import secrets
import sys
from typing import Any

from . import common, worker_deploy
from .cfapi import CfClient, CfError
from .common import fail, path

TOOL = "legatto-cf-bootstrap"
EXIT_CF = 40
QUEUE = "forms"
DLQ = "forms-dlq"
RETENTION_SECONDS = 1_209_600  # 14 days (Workers Paid maximum)
CONSUMER_SETTINGS = {"batch_size": 50, "max_retries": 100, "visibility_timeout_ms": 900_000, "retry_delay": 300}
WIDGET_NAME = "legatto-forms"
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{20,200}$")
PERMISSIONS = {
    "queues": {"account": ["Queues Write"], "zone": []},
    "pages": {"account": ["Pages Write", "Workers Scripts Write"], "zone": ["Workers Routes Write"]},
    "dns": {"account": [], "zone": ["DNS Write", "Zone Read"]},
}
CREDENTIAL_FOR = {"queues": common.CRED_CF_QUEUES, "pages": common.CRED_CF_PAGES, "dns": common.CRED_CF_DNS}


class Step:
    """Names the Cloudflare step in errors (exit 40) without echoing any value."""

    def __init__(self, name: str) -> None:
        self.name = name

    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type: object, exc: object, _tb: object) -> bool:
        if isinstance(exc, CfError):
            raise common.ToolError(f"Cloudflare step '{self.name}' failed: {exc}", EXIT_CF) from None
        return False


def _account(client: CfClient, wanted: str | None) -> str:
    with Step("list accounts"):
        accounts = client.list_all("/accounts")
    ids = [a["id"] for a in accounts]
    if wanted:
        if wanted not in ids:
            fail(f"account {wanted} is not visible to the bootstrap token", common.EXIT_PRECONDITION)
        return wanted
    if len(ids) != 1:
        fail(f"the bootstrap token sees {len(ids)} accounts; pass --account-id", common.EXIT_USAGE)
    return ids[0]


def _zone(client: CfClient, account: str, domain: str) -> str:
    with Step("find zone"):
        zones = client.call("GET", f"/zones?name={domain}&account.id={account}")
    if not zones:
        fail(f"zone {domain} is not in the office Cloudflare account", common.EXIT_PRECONDITION)
    return zones[0]["id"]


def _queue(client: CfClient, account: str, name: str, dead_letter: str | None) -> str:
    with Step(f"queue {name}"):
        existing = [q for q in client.list_all(f"/accounts/{account}/queues") if q.get("queue_name") == name]
        if existing:
            queue_id = existing[0]["queue_id"]
        else:
            created = client.call("POST", f"/accounts/{account}/queues",
                                  {"queue_name": name, "settings": {"message_retention_period": RETENTION_SECONDS}})
            queue_id = created["queue_id"]
        consumers = client.call("GET", f"/accounts/{account}/queues/{queue_id}/consumers") or []
        if not any(c.get("type") == "http_pull" for c in consumers):
            body: dict[str, Any] = {"type": "http_pull", "settings": CONSUMER_SETTINGS}
            if dead_letter:
                body["dead_letter_queue"] = dead_letter
            client.call("POST", f"/accounts/{account}/queues/{queue_id}/consumers", body)
    return queue_id


def _widget(client: CfClient, account: str, site: str, need_secret: bool) -> tuple[str, str | None]:
    with Step("turnstile widget"):
        widgets = [w for w in client.list_all(f"/accounts/{account}/challenges/widgets") if w.get("name") == WIDGET_NAME]
        if not widgets:
            created = client.call("POST", f"/accounts/{account}/challenges/widgets",
                                  {"name": WIDGET_NAME, "domains": [site], "mode": "managed", "region": "world"})
            return created["sitekey"], created["secret"]
        sitekey = widgets[0]["sitekey"]
        if sorted(widgets[0].get("domains", [])) != [site]:
            client.call("PUT", f"/accounts/{account}/challenges/widgets/{sitekey}",
                        {"name": WIDGET_NAME, "domains": [site], "mode": widgets[0].get("mode", "managed")})
        if not need_secret:
            return sitekey, None
        rotated = client.call("POST", f"/accounts/{account}/challenges/widgets/{sitekey}/rotate_secret",
                              {"invalidate_immediately": False})
        return sitekey, rotated["secret"]


def _pages(client: CfClient, account: str, project: str, site: str) -> str:
    with Step("pages project"):
        try:
            client.call("GET", f"/accounts/{account}/pages/projects/{project}")
        except CfError as err:
            if err.status != 404:
                raise
            client.call("POST", f"/accounts/{account}/pages/projects", {"name": project, "production_branch": "main"})
        domains = client.call("GET", f"/accounts/{account}/pages/projects/{project}/domains") or []
        if not any(d.get("name") == site for d in domains):
            client.call("POST", f"/accounts/{account}/pages/projects/{project}/domains", {"name": site})
    return project


def _permission_ids(client: CfClient, account: str) -> dict[str, str]:
    with Step("permission groups"):
        groups = client.call("GET", f"/accounts/{account}/tokens/permission_groups") or []
    return {g["name"]: g["id"] for g in groups if isinstance(g, dict) and "name" in g and "id" in g}


def _create_tokens(client: CfClient, account: str, zone: str, slug: str, ipv4: str) -> dict[str, str]:
    """Replaces the office tokens (old ones with the same name are deleted first)."""
    ids = _permission_ids(client, account)
    values: dict[str, str] = {}
    with Step("office tokens"):
        existing = client.list_all(f"/accounts/{account}/tokens")
        for purpose, scopes in PERMISSIONS.items():
            name = f"legatto-{slug}-{purpose}"
            for token in existing:
                if token.get("name") == name:
                    client.call("DELETE", f"/accounts/{account}/tokens/{token['id']}")
            policies = []
            for scope, resource in (("account", f"com.cloudflare.api.account.{account}"),
                                    ("zone", f"com.cloudflare.api.account.zone.{zone}")):
                if scopes[scope]:
                    missing = [n for n in scopes[scope] if n not in ids]
                    if missing:
                        fail(f"Cloudflare permission groups not found: {', '.join(missing)}", EXIT_CF)
                    policies.append({"effect": "allow", "resources": {resource: "*"},
                                     "permission_groups": [{"id": ids[n]} for n in scopes[scope]]})
            created = client.call("POST", f"/accounts/{account}/tokens", {
                "name": name,
                "policies": policies,
                "condition": {"request_ip": {"in": [f"{ipv4}/32"]}},
            })
            values[purpose] = created["value"]
    return values


def _revoke_bootstrap(client: CfClient, account: str) -> bool:
    for verify, delete in ((f"/accounts/{account}/tokens/verify", f"/accounts/{account}/tokens/{{id}}"),
                           ("/user/tokens/verify", "/user/tokens/{id}")):
        try:
            token_id = client.call("GET", verify)["id"]
        except CfError:
            continue
        try:
            client.call("DELETE", delete.format(id=token_id))
            return True
        except CfError as err:
            common.log(f"could not delete the bootstrap token ({err.status}); delete it in the dashboard")
            return False
    common.log("could not identify the bootstrap token; delete it in the dashboard")
    return False


def run(args: argparse.Namespace, token: str) -> dict[str, Any]:
    env = common.office_env()
    site = env["LEGATTO_HOST_SITE"]
    domain = env["LEGATTO_OFFICE_DOMAIN"]
    slug = env["LEGATTO_SLUG"]
    ipv4 = env["LEGATTO_PUBLIC_IPV4"]
    proxy = os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY") or f"http://127.0.0.1:{common.PROXY_PORT}"
    client = CfClient(token, str(path(common.P_CF_CA_BUNDLE)), proxy, os.environ.get("LEGATTO_CF_API_BASE", "https://api.cloudflare.com/client/v4"))
    previous = common.read_json(path(common.P_PUBLICSITE_ETC) / "cloudflare.json", {}) or {}

    account = _account(client, args.account_id or previous.get("account_id"))
    zone = _zone(client, account, domain)
    dlq_id = _queue(client, account, DLQ, None)
    queue_id = _queue(client, account, QUEUE, DLQ)
    signer_missing = not (path(common.P_WORKER_STATE) / "signer.json").is_file()
    stage_secrets = signer_missing or args.rotate_worker_keys
    sitekey, turnstile_secret = _widget(client, account, site, stage_secrets)
    project = previous.get("pages", {}).get("project") or args.pages_project or f"legatto-{slug}-{secrets.token_hex(3)}"
    _pages(client, account, project, site)

    created: list[str] = []
    if args.rotate_tokens or not all((path(common.P_CREDSTORE) / c).is_file() for c in CREDENTIAL_FOR.values()):
        values = _create_tokens(client, account, zone, slug, ipv4)
        for purpose, value in values.items():
            common.encrypt_credential(CREDENTIAL_FOR[purpose], value.encode())
            created.append(CREDENTIAL_FOR[purpose])
        values.clear()

    signer_kid = None
    if stage_secrets:
        assert turnstile_secret is not None
        signer_kid = worker_deploy.stage_worker_secrets(turnstile_secret)
        turnstile_secret = None

    config = {
        "v": 1,
        "account_id": account,
        "zone_id": zone,
        "zone_name": domain,
        "site_host": site,
        "queue": {"name": QUEUE, "id": queue_id},
        "dlq": {"name": DLQ, "id": dlq_id},
        "pages": {"project": project},
        "turnstile": {"sitekey": sitekey},
        "script_name": "legatto-forms",
        "token_ip": ipv4,
        "created_at": previous.get("created_at", common.utc_now()),
        "updated_at": common.utc_now(),
    }
    common.ensure_dir(path(common.P_PUBLICSITE_ETC), 0o755)
    common.write_json_atomic(path(common.P_PUBLICSITE_ETC) / "cloudflare.json", config, 0o644)
    revoked = _revoke_bootstrap(client, account) if not args.keep_bootstrap_token else False
    return {"ok": True, "account_id": account, "zone_id": zone, "queue_id": queue_id, "dlq_id": dlq_id,
            "pages_project": project, "turnstile_sitekey": sitekey, "credentials_created": created,
            "worker_signer_kid": signer_kid, "bootstrap_token_deleted": revoked}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog=TOOL, description="One-time Cloudflare setup of the office account (token on stdin).")
    parser.add_argument("--account-id", help="needed only when the bootstrap token sees several accounts")
    parser.add_argument("--pages-project", help="Pages project name for a new project (default legatto-<slug>-<random>)")
    parser.add_argument("--rotate-tokens", action="store_true", help="replace the three office tokens")
    parser.add_argument("--rotate-worker-keys", action="store_true", help="new Worker signing/IP-hash keys and Turnstile secret")
    parser.add_argument("--keep-bootstrap-token", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--actor")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return common.EXIT_USAGE if exc.code else common.EXIT_OK

    def body() -> int:
        common.require_root()
        common.parse_actor(args.actor, TOOL)
        if sys.stdin.isatty():
            fail("the bootstrap token is read from stdin (not a terminal)", common.EXIT_USAGE)
        token = sys.stdin.readline().strip()
        if not TOKEN_RE.match(token):
            fail("stdin does not hold a Cloudflare API token", common.EXIT_USAGE)
        with common.Lock("cf-bootstrap"):
            result = run(args, token)
        common.emit(result)
        return common.EXIT_OK

    return common.main_wrapper(TOOL, body)
