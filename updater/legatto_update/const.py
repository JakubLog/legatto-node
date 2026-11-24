"""Fixed values of the update chain.

Every value annotated with ``# contract: <key>`` mirrors
contract/contract.yml; the updater tests fail when they diverge. Targets of
the appliers are code, never manifest data.
"""

TOOL = "legatto-update"  # contract: legatto_cli.update
CONTRACT_VERSION = 1  # contract: legatto_contract_version

# --- paths ---------------------------------------------------------------
OPT = "/opt/legatto"  # contract: legatto_paths.opt
SBIN = "/opt/legatto/sbin"  # contract: legatto_paths.sbin
RELEASES = "/opt/legatto/releases"  # contract: legatto_paths.releases
CURRENT = "/opt/legatto/current"  # contract: legatto_paths.current
BIN = "/opt/legatto/bin"  # contract: legatto_paths.bin
BIN_CURRENT = "/opt/legatto/bin/current"  # contract: legatto_paths.bin_current
OFFICE_ENV = "/etc/legatto/office.env"  # contract: legatto_paths.office_env
UPDATE_TRUST = "/etc/legatto/update"  # contract: legatto_paths.update_trust
ALLOWED_SIGNERS = "/etc/legatto/update/allowed_signers"  # contract: legatto_paths.allowed_signers
POLICY = "/etc/legatto/update/policy.json"  # contract: legatto_paths.update_policy
KRL = "/etc/legatto/update/revoked.krl"  # contract: legatto_paths.krl
UPDATE_STATE = "/var/lib/legatto/update"  # contract: legatto_paths.update_state
UPDATE_PENDING = "/var/lib/legatto/update/pending"  # contract: legatto_paths.update_pending
UPDATE_ATTEST = "/var/lib/legatto/update/attest"  # contract: legatto_paths.update_attest
CANARY_KEY = "/etc/legatto/secrets/update-canary-ed25519"  # contract: legatto_paths.update_canary_key
STATUS_DIR = "/var/lib/legatto/status"  # contract: legatto_paths.status
CADDYFILE = "/etc/caddy/Caddyfile"  # contract: legatto_paths.caddyfile
CADDY_SITES = "/etc/caddy/sites.d"  # contract: legatto_paths.caddy_sites
RUN = "/run/legatto"  # contract: legatto_paths.run
SYSTEMD_DIR = "/etc/systemd/system"
LOCK = RUN + "/update.lock"

# Files inside UPDATE_STATE.
STATE_FILE = "state.json"
FIRST_SEEN_FILE = "first_seen.json"
ADMIN_FILE = "admin.json"
MIGRATIONS_FILE = "migrations.json"
DOWNLOADS = "downloads"
KRL_STORE = "krl"

# --- groups (file ownership of status and console-readable files) ---------
GROUP_STATUS = "legatto-status"  # contract: legatto_groups.status
GROUP_CONSOLE = "legatto-console"  # contract: legatto_groups.console

# --- network ---------------------------------------------------------------
EGRESS_PROXY = "http://127.0.0.1:4750"  # contract: legatto_egress_proxy_url_host

# --- release chain ---------------------------------------------------------
CHANNELS = ["canary", "early", "stable"]  # contract: legatto_channels
RELEASE_TYPES = ["security", "feature"]  # contract: legatto_release_types
NS_RELEASE = "legatto-release"  # contract: legatto_signature.namespaces.release
NS_PROMOTE = "legatto-promote"  # contract: legatto_signature.namespaces.promote
NS_INDEX = "legatto-index"  # contract: legatto_signature.namespaces.index
NS_REVOKE = "legatto-revoke"  # contract: legatto_signature.namespaces.revoke
NS_CANARY = "legatto-canary"  # contract: legatto_signature.namespaces.canary
RELEASE_PRINCIPALS = ["release-a@legatto.pl", "release-b@legatto.pl"]  # contract: legatto_signature.principals.release
CANARY_PRINCIPALS = ["canary@legatto.pl"]  # contract: legatto_signature.principals.canary
SIGNATURES_REQUIRED_DEFAULT = 1  # contract: legatto_signature.signatures_required_default
LAYOUT_INDEX = "index.json"  # contract: legatto_release_layout.index
LAYOUT_KRL = "revoked.krl"  # contract: legatto_release_layout.krl
SCHEMA_IDS = {  # contract: legatto_release_schemas
    "manifest": "legatto-release/1",
    "promotion": "legatto-promote/1",
    "attestation": "legatto-canary/1",
    "index": "legatto-index/1",
    "policy": "legatto-policy/1",
}
MIN_DELAY_HOURS = {  # contract: legatto_min_delay_hours
    "feature": {"early": 24, "stable": 48},
    "security": {"early": 2, "stable": 4},
}
ARTIFACT_KINDS = ["oci-archive", "edge-functions", "config", "sql-migrations", "binary", "deb",  # contract: legatto_artifact_kinds
                  "worker-bundle", "sbom", "notes"]
BINARY_ALLOWLIST = ["caddy", "lego", "smokescreen"]  # contract: legatto_binary_allowlist
DEB_ALLOWLIST = ["headscale", "tailscale"]  # contract: legatto_deb_allowlist
APPLIERS = ["sql-migrations", "deb", "binary", "env-template", "egress", "systemd-unit", "caddy-site",  # contract: legatto_appliers
            "functions", "compose", "worker"]
FEATURE_NAMES = ["ai", "mcp", "email", "getresponse", "push", "ics", "hibp"]  # contract: legatto_feature_names

# --- office.env keys (section 4.1) ----------------------------------------------
OFFICE_ENV_KEYS = ["LEGATTO_CONTRACT_VERSION", "LEGATTO_SLUG", "LEGATTO_ENV", "LEGATTO_OFFICE_TITLE",  # contract: legatto_office_env
                   "LEGATTO_OFFICE_DOMAIN", "LEGATTO_HOST_SITE", "LEGATTO_HOST_VPN", "LEGATTO_HOST_CRM",
                   "LEGATTO_HOST_ADMIN", "LEGATTO_TS_IP4", "LEGATTO_TS_IP6",
                   "LEGATTO_PUBLIC_IPV4", "LEGATTO_TZ"]

# --- compose / docker ---------------------------------------------------------
COMPOSE_PROJECT = "legatto"  # contract: legatto_compose_project
DB_CONTAINER = "supabase-db"  # contract: legatto_container_db
DOCKER_NETWORK_NAMES = ["legatto-host", "legatto-int", "legatto-egress-ext", "legatto-egress-app",
                        "legatto-egress-auth", "legatto-egress-fn", "legatto-egress-intake",
                        "legatto-egress-publish"]
# Compose layout agreed with the platform lane (bundle/compose).
COMPOSE_PROJECT_SUBDIR = "supabase"
COMPOSE_FILES = ["supabase/docker-compose.yml", "docker-compose.legatto.yml"]
# Read-only bind-mount sources a release may use: its own compose tree and
# the egress ACLs rendered by Ansible/legatto-egress.
COMPOSE_BIND_PREFIXES_RELEASE = ["supabase/volumes/"]
COMPOSE_BIND_PREFIXES_HOST = ["/etc/legatto/egress/"]
COMPOSE_SECRET_PREFIXES = ["/run/legatto/keys/"]
COMPOSE_CAP_ADD_ALLOWED: list = []
# Profiles whose services the compose validator must see (disabled stays off).
COMPOSE_PROFILE_DISABLED = "disabled"  # contract: legatto_compose_profile_disabled
COMPOSE_PROFILES_CHECKED = ["tools"]  # tools (migrator)
CADDY_SNIPPET_FILE = "common.caddy"

# --- systemd units and host tools --------------------------------------------
UNIT_CADDY = "legatto-caddy.service"  # contract: legatto_units.caddy
UNIT_STACK = "legatto-stack.service"  # contract: legatto_units.stack
UNIT_UPDATE_TIMER = "legatto-update.timer"  # contract: legatto_units.update
# approve --install-now starts this unit at once instead of waiting for the timer.
UNIT_UPDATE_SERVICE = UNIT_UPDATE_TIMER[:-len(".timer")] + ".service"
# Units a release may ship (applier systemd-unit) and the subset allowed to run as root.
UNIT_NAME_PATTERNS = [
    r"legatto-stack\.service",
    r"legatto-secrets-render\.(service|path)",
    r"legatto-cron@\.service",
    r"legatto-cron-[a-z0-9][a-z0-9-]{0,40}\.timer",
]
UNITS_ROOT_ALLOWED = ["legatto-stack.service", "legatto-secrets-render.service", "legatto-secrets-render.path"]
UNITS_DYNAMIC_USER_REQUIRED = ["legatto-cron@.service"]
EXEC_PREFIXES_ROOT = ["/opt/legatto/sbin/"]
EXEC_PREFIXES_NONROOT = ["/opt/legatto/sbin/", "/opt/legatto/bin/current/"]

CLI_AUDIT = "legatto-audit"  # contract: legatto_cli.audit
CLI_EGRESS = "legatto-egress"  # contract: legatto_cli.egress
CLI_WORKER_DEPLOY = "legatto-worker-deploy"  # contract: legatto_cli.worker_deploy
CLI_SECRETS = "legatto-secrets"  # contract: legatto_cli.secrets
CLI_STACK = "legatto-stack"  # contract: legatto_cli.stack

# compose extra_hosts: the only (service, name, address) pairs a release may
# declare (section 4.8). "${...}" values come from office.env.
EXTRA_HOSTS_ALLOWED = [
    ("auth", "host.docker.internal", "172.30.1.10"),  # legatto_ip_int_net.app (GoTrue hook)
    ("db", "${LEGATTO_HOST_CRM}", "${LEGATTO_TS_IP4}"),  # pg_net hairpin to the CRM
]
IP_INT_NET = {"app": "172.30.1.10"}  # contract: legatto_ip_int_net

# --- exit codes (section 4.6) ------------------------------------------------------
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_LOCKED = 3
EXIT_PRECONDITION = 4
EXIT_REJECTED = 10
EXIT_GATE = 11
EXIT_PREFLIGHT = 12
EXIT_ROLLED_BACK = 13
EXIT_ROLLBACK_FAILED = 14
EXIT_STALE = 15
EXIT_CLOCK_JUMP = 16

# Exit codes of the tools the updater calls.
EGRESS_WIDENING = 40
EGRESS_PINNED_REMOVED = 41
EGRESS_INVALID = 42
WORKER_FAILED = 60

# --- limits ------------------------------------------------------------------------
MAX_DOC_BYTES = 1 << 20
MAX_SIG_BYTES = 16 << 10
MAX_NOTES_BYTES = 64 << 10
MAX_FUNCTIONS_BYTES = 256 << 20
MAX_CONFIG_BYTES = 64 << 20
INDEX_RETRY_SECONDS = 15
CLOCK_SKEW_SECONDS = 300
HEALTH_POLL_SECONDS = 5
