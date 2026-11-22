"""Names, paths and limits shared with the rest of the server tools.

Every value below mirrors contract/contract.yml; the comment
`# contract: <key>` names its source and the console contract test fails
when the two disagree. Change contract.yml first, then this file.
"""

from __future__ import annotations

import os

CONTRACT_VERSION = 1  # contract: legatto_contract_version

# --- Paths -------------------------------------------------------------------
CONSOLE_APP = "/opt/legatto/console"  # contract: legatto_paths.console_app
SBIN = "/opt/legatto/sbin"  # contract: legatto_paths.sbin
CURRENT_RELEASE = "/opt/legatto/current"  # contract: legatto_paths.current
OFFICE_ENV = "/etc/legatto/office.env"  # contract: legatto_paths.office_env
STATUS_DIR = "/var/lib/legatto/status"  # contract: legatto_paths.status
UPDATE_PENDING = "/var/lib/legatto/update/pending"  # contract: legatto_paths.update_pending
REQUESTS = "/var/lib/legatto/requests"  # contract: legatto_paths.requests
REQUESTS_INCOMING = "/var/lib/legatto/requests/incoming"  # contract: legatto_paths.requests_incoming
REQUESTS_PROCESSING = "/var/lib/legatto/requests/processing"  # contract: legatto_paths.requests_processing
REQUESTS_RESULTS = "/var/lib/legatto/requests/results"  # contract: legatto_paths.requests_results
REQUESTS_ARCHIVE = "/var/lib/legatto/requests/archive"  # contract: legatto_paths.requests_archive
CONSOLE_STATE = "/var/lib/legatto/console"  # contract: legatto_paths.console_state
CONSOLE_USERS = "/var/lib/legatto/console/users.json"  # contract: legatto_paths.console_users
CONSOLE_SNAPSHOT = "/var/lib/legatto/console/snapshot.json"  # contract: legatto_paths.console_snapshot
CONSOLE_AUTH = "/var/lib/legatto/console-auth"  # contract: legatto_paths.console_auth
CONSOLE_TOTP_SEEDS = "/etc/legatto/secrets/console-totp"  # contract: legatto_paths.console_totp_seeds
RECOVERY_DIR = "/var/lib/legatto/recovery"  # contract: legatto_paths.recovery
BREAKGLASS_STATE = "/var/lib/legatto/breakglass"  # contract: legatto_paths.breakglass
TAILNET_STATE = "/var/lib/legatto/tailnet"  # contract: legatto_paths.tailnet
FEATURES = "/var/lib/legatto/office/features.json"  # contract: legatto_paths.features
INCIDENT_CONTACTS = "/var/lib/legatto/office/contacts.json"  # contract: legatto_paths.incident_contacts
AUDIT_LOG = "/var/log/legatto/audit.log"  # contract: legatto_paths.audit_log
RUN_DIR = "/run/legatto"  # contract: legatto_paths.run
CONSOLE_SOCKET = "/run/legatto/office-console.sock"  # contract: legatto_console_socket

# Derived (inside the contract directories above, owned by this lane).
BREAKGLASS_SUMMARIES = BREAKGLASS_STATE + "/summaries"
STAFF_FILE = TAILNET_STATE + "/staff.json"
EXEC_LOCK = RUN_DIR + "/console-exec.lock"
SETUP_CODE_FILE = CONSOLE_AUTH + "/setup-code.json"
TAILSCALE = "/usr/bin/tailscale"

# --- Users and groups --------------------------------------------------------
CONSOLE_USER = "legatto-console"  # contract: legatto_users.console.name
CONSOLE_GROUP = "legatto-console"  # contract: legatto_groups.console
STATUS_GROUP = "legatto-status"  # contract: legatto_groups.status
AUDIT_GROUP = "legatto-audit"  # contract: legatto_groups.audit

# --- Host CLIs (legatto_paths.sbin/<name>) -------------------------------------
CLI_AUDIT = "legatto-audit"  # contract: legatto_cli.audit
CLI_BREAKGLASS = "legatto-breakglass"  # contract: legatto_cli.breakglass
CLI_UPDATE = "legatto-update"  # contract: legatto_cli.update
CLI_STUDIO = "legatto-studio"  # contract: legatto_cli.studio
CLI_TAILNET = "legatto-tailnet"  # contract: legatto_cli.tailnet
CLI_EGRESS = "legatto-egress"  # contract: legatto_cli.egress
CLI_RECOVERY_PACK = "legatto-recovery-pack"  # contract: legatto_cli.recovery_pack
CLI_CONSOLE_EXEC = "legatto-console-exec"  # contract: legatto_cli.console_exec

# --- Spool -------------------------------------------------------------------
REQUEST_VERSION = 1  # contract: legatto_requests.version
REQUEST_MAX_BYTES = 8192  # contract: legatto_requests.max_bytes
REQUEST_MAX_AGE_SECONDS = 120  # contract: legatto_requests.max_age_seconds
SETUP_CODE_TTL_HOURS = 24  # contract: legatto_requests.setup_code_ttl_hours
EMERGENCY_LOGIN = "awaryjny"  # contract: legatto_requests.console_emergency_login
REQUEST_TYPES = (  # contract: legatto_requests.types
    "breakglass.enable",
    "breakglass.disable",
    "update.approve",
    "update.reject",
    "update.rollback",
    "update.autosecurity",
    "studio.enable",
    "studio.disable",
    "device.enroll",
    "device.revoke",
    "staff.set",
    "features.set",
    "recovery.generate",
    "console.user.add",
    "console.user.remove",
    "console.user.reset_totp",
    "console.user.password",
    "console.login",
    "contacts.set",
    "console.setup",
)
SENSITIVE_RESULT_TTL_SECONDS = 600  # CONTRACT §4.3: sensitive results are deleted after 10 minutes
ARCHIVE_RETENTION_DAYS = 30  # CONTRACT §4.3: archive retention

# --- Other limits ---------------------------------------------------------------
FEATURE_NAMES = ("ai", "mcp", "email", "getresponse", "push", "ics", "hibp")  # contract: legatto_feature_names
BREAKGLASS_HOURS_MIN = 1  # contract: legatto_breakglass.hours_min
BREAKGLASS_HOURS_MAX = 8  # contract: legatto_breakglass.hours_max
BREAKGLASS_REASON_MIN = 10  # contract: legatto_breakglass.reason_min_chars
BREAKGLASS_REASON_MAX = 500  # contract: legatto_breakglass.reason_max_chars
TAILNET_PREFIX_V4 = "100.64.0.0/10"  # contract: legatto_tailnet_prefix_v4
TAILNET_PREFIX_V6 = "fd7a:115c:a1e0::/48"  # contract: legatto_tailnet_prefix_v6
TAG_OFFICE_DEVICE = "tag:office-device"  # contract: legatto_tailnet_tags.office_device
TAG_SERVER = "tag:server"  # contract: legatto_tailnet_tags.server
STATUS_FILES = (  # contract: legatto_status_files
    "update", "breakglass", "backup", "restore-test", "intake", "publish", "worker", "egress", "audit", "tls",
    "health",
)
AUDIT_CATEGORY = "console"  # contract: legatto_audit.categories (console lane)
TIMEZONE = "Europe/Warsaw"  # contract: legatto_timezone

# Prefix for every absolute path above. Empty in production; the test suite
# points it at a temporary tree (like DESTDIR), never set by the systemd units.
PREFIX = os.environ.get("LEGATTO_CONSOLE_PREFIX", "")


def path(p: str) -> str:
    """Return the effective location of a contract path."""
    return PREFIX + p if PREFIX else p


def tool(name: str) -> str:
    """Absolute path of a host CLI installed by Ansible."""
    return path(SBIN + "/" + name)
