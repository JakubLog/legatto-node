"""Static policy checks of config files a release ships (section 4.8).

Pure functions over parsed data, used by the appliers' validators before any
change. Also runnable for the platform lane's tests:

    PYTHONPATH=updater python3 -m legatto_update.check compose --dir <release>/compose \
        --manifest manifest.json [--config-json compose-config.json] [--office-env office.env]

Also `unit FILE...`, `caddy-site FILE...` and `policy FILE`.
Exit 0 = OK, 10 = policy violation (JSON with errors on stdout), 2 = usage.
"""

import argparse
import json
import os
import re
import sys

from . import const

IMAGE_RE = re.compile(r"^(?P<repo>[a-z0-9.-]+(:[0-9]+)?/[a-z0-9._/-]+)@(?P<digest>sha256:[0-9a-f]{64})$")
FORBIDDEN_SECURITY_OPT = re.compile(r"(unconfined|label[:=]disable|systempaths=unconfined)")


def _repo(ref: str) -> str:
    return ref.rsplit(":", 1)[0] if ":" in ref.rsplit("/", 1)[-1] else ref


def _subst(value: str, office_env: dict) -> str:
    return re.sub(r"\$\{([A-Z0-9_]+)\}", lambda m: office_env.get(m.group(1), m.group(0)), value)


def _extra_hosts(raw) -> list:
    pairs = []
    if isinstance(raw, dict):
        for name, addrs in raw.items():
            for addr in addrs if isinstance(addrs, list) else [addrs]:
                pairs.append((name, str(addr)))
    elif isinstance(raw, list):
        for item in raw:
            sep = "=" if "=" in item else ":"
            name, _, addr = str(item).partition(sep)
            pairs.append((name, addr))
    return pairs


def _within(path: str, prefixes) -> bool:
    real = os.path.normpath(path)
    for prefix in prefixes:
        base = os.path.normpath(prefix)
        if real == base or real.startswith(base.rstrip("/") + "/"):
            return True
    return False


def check_compose_config(cfg: dict, manifest: dict, office_env: dict, compose_dir: str, host_p=lambda p: p) -> list:
    """Policy for `docker compose config --format json --no-interpolate` output."""
    errors = []
    digests = {img["digest"]: _repo(img["ref"]) for img in manifest["images"]}
    release_binds = [os.path.join(compose_dir, p) for p in const.COMPOSE_BIND_PREFIXES_RELEASE]
    host_binds = [host_p(p) for p in const.COMPOSE_BIND_PREFIXES_HOST]
    secret_dirs = [host_p(p) for p in const.COMPOSE_SECRET_PREFIXES]
    allowed_hosts = {(svc, _subst(name, office_env), _subst(addr, office_env))
                     for svc, name, addr in const.EXTRA_HOSTS_ALLOWED}
    allowed_hosts |= {(svc, name, addr) for svc, name, addr in const.EXTRA_HOSTS_ALLOWED}
    networks = cfg.get("networks") or {}
    for key, net in networks.items():
        name = (net or {}).get("name") or "%s_%s" % (const.COMPOSE_PROJECT, key)
        if name not in const.DOCKER_NETWORK_NAMES:
            errors.append("network %s: name %s not in contract" % (key, name))
    for key, vol in (cfg.get("volumes") or {}).items():
        vol = vol or {}
        if vol.get("driver_opts"):
            errors.append("volume %s: driver_opts not allowed" % key)
        if vol.get("driver") not in (None, "local"):
            errors.append("volume %s: driver not allowed" % key)
    for key, sec in (cfg.get("secrets") or {}).items():
        src = (sec or {}).get("file")
        if not src or not _within(src, secret_dirs):
            errors.append("secret %s: file outside %s" % (key, const.COMPOSE_SECRET_PREFIXES))
    for key, conf in (cfg.get("configs") or {}).items():
        src = (conf or {}).get("file")
        if not src or not _within(src, release_binds):
            errors.append("config %s: file outside the release compose tree" % key)
    services = cfg.get("services") or {}
    # `config --no-interpolate` ignores --profile: services only in profiles that
    # legatto-stack never activates (disabled) cannot start and are skipped, but
    # nothing that can start may depend on them.
    inactive = {n for n, svc in services.items()
                if svc.get("profiles") and not set(svc["profiles"]) & set(const.COMPOSE_PROFILES_CHECKED)}
    for name, svc in services.items():
        if name in inactive:
            continue
        deps = svc.get("depends_on") or {}
        for dep in (deps if isinstance(deps, (dict, list)) else []):
            if dep in inactive:
                errors.append("service %s: depends_on %s from profile %s" % (name, dep, const.COMPOSE_PROFILE_DISABLED))
    for name, svc in services.items():
        if name in inactive:
            continue
        where = "service %s" % name
        image = svc.get("image") or ""
        m = IMAGE_RE.match(image)
        if not m:
            errors.append("%s: image must be <repo>@sha256:<digest> (got %r)" % (where, image[:120]))
        elif m.group("digest") not in digests or digests[m.group("digest")] != m.group("repo"):
            errors.append("%s: image digest not in manifest.images" % where)
        if svc.get("build"):
            errors.append("%s: build not allowed" % where)
        if svc.get("privileged"):
            errors.append("%s: privileged" % where)
        if svc.get("network_mode") not in (None, "none"):
            errors.append("%s: network_mode %s" % (where, svc.get("network_mode")))
        for ns in ("pid", "ipc", "userns_mode", "uts", "cgroup"):
            if svc.get(ns) == "host":
                errors.append("%s: %s: host" % (where, ns))
        cap_add = svc.get("cap_add") or []
        extra_caps = [c for c in cap_add if c not in const.COMPOSE_CAP_ADD_ALLOWED]
        if extra_caps:
            errors.append("%s: cap_add %s" % (where, extra_caps))
        if svc.get("devices"):
            errors.append("%s: devices not allowed" % where)
        for opt in svc.get("security_opt") or []:
            if FORBIDDEN_SECURITY_OPT.search(str(opt)):
                errors.append("%s: security_opt %s" % (where, opt))
        for port in svc.get("ports") or []:
            if isinstance(port, dict):
                host_ip = port.get("host_ip")
                published = port.get("published")
            else:
                parts = str(port).split(":")
                host_ip = parts[0] if len(parts) == 3 else None
                published = parts[-2] if len(parts) >= 2 else None
            if published not in (None, "") and host_ip != "127.0.0.1":
                errors.append("%s: port %s not bound to 127.0.0.1" % (where, port))
        for vol in svc.get("volumes") or []:
            if not isinstance(vol, dict):
                errors.append("%s: volume in short syntax: %s" % (where, vol))
                continue
            vtype = vol.get("type")
            if vtype == "bind":
                src = vol.get("source") or ""
                if not (_within(src, release_binds) or _within(src, host_binds)):
                    errors.append("%s: bind mount %s outside allowlist" % (where, src))
                elif not vol.get("read_only"):
                    errors.append("%s: bind mount %s must be read-only" % (where, src))
            elif vtype not in ("volume", "tmpfs"):
                errors.append("%s: volume type %s" % (where, vtype))
        for host, addr in _extra_hosts(svc.get("extra_hosts")):
            if (name, host, addr) not in allowed_hosts:
                errors.append("%s: extra_hosts %s:%s not allowed" % (where, host, addr))
        svc_nets = svc.get("networks") or {}
        for net in (svc_nets if isinstance(svc_nets, (dict, list)) else []):
            if net not in networks:
                errors.append("%s: network %s undefined" % (where, net))
        if not svc_nets and svc.get("network_mode") is None:
            errors.append("%s: no explicit network (default network not in contract)" % where)
    return errors


# --- systemd units ---------------------------------------------------------------------------
EXEC_KEYS = ("ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost", "ExecReload",
             "ExecCondition")
SHELLS = ("sh", "bash", "dash", "zsh", "busybox", "env", "python3", "perl")


def parse_unit(text: str) -> list:
    """(section, key, value) triples; continuation lines joined."""
    out, section, pending = [], None, ""
    for raw in text.splitlines():
        line = pending + raw.strip()
        if line.endswith("\\"):
            pending = line[:-1] + " "
            continue
        pending = ""
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        key, sep, value = line.partition("=")
        if not sep:
            out.append((section, line, None))
            continue
        out.append((section, key.strip(), value.strip()))
    return out


def check_unit(name: str, text: str) -> list:
    errors = []
    if not any(re.fullmatch(p, name) for p in const.UNIT_NAME_PATTERNS):
        return ["%s: unit name not allowed" % name]
    entries = parse_unit(text)
    users = [v for s, k, v in entries if s == "Service" and k == "User"]
    dynamic = [v for s, k, v in entries if s == "Service" and k == "DynamicUser"]
    is_service = name.endswith(".service")
    runs_root = is_service and (not users or users[-1] in ("root", "0")) and not (
        dynamic and dynamic[-1].lower() in ("yes", "true", "1", "on"))
    if runs_root and name not in const.UNITS_ROOT_ALLOWED:
        errors.append("%s: runs as root (set User= to a non-root account)" % name)
    if name in const.UNITS_DYNAMIC_USER_REQUIRED and not (dynamic and dynamic[-1].lower() in ("yes", "true", "1", "on")):
        errors.append("%s: DynamicUser=yes required" % name)
    prefixes = const.EXEC_PREFIXES_ROOT if runs_root or name in const.UNITS_ROOT_ALLOWED else const.EXEC_PREFIXES_NONROOT
    for section, key, value in entries:
        if value is None:
            errors.append("%s: malformed line %r" % (name, key[:60]))
            continue
        if key in EXEC_KEYS and value:
            cmd = value
            while cmd[:1] in ("-", "@", ":", "+", "!", "|"):
                if cmd[0] in ("+", "!", "|"):
                    errors.append("%s: %s uses privileged prefix %r" % (name, key, cmd[0]))
                cmd = cmd[1:]
            exe = cmd.split()[0] if cmd.split() else ""
            if not any(exe.startswith(p) for p in prefixes) or ".." in exe:
                errors.append("%s: %s %s outside %s" % (name, key, exe, prefixes))
            if os.path.basename(exe) in SHELLS:
                errors.append("%s: %s runs a shell" % (name, key))
        if key == "PermissionsStartOnly":
            errors.append("%s: PermissionsStartOnly not allowed" % name)
        if key == "AmbientCapabilities" and value:
            errors.append("%s: AmbientCapabilities not allowed" % name)
        if key == "CapabilityBoundingSet" and value and not value.startswith("~"):
            errors.append("%s: CapabilityBoundingSet may only remove capabilities" % name)
        if key in ("User", "Group") and value in ("root", "0") and name not in const.UNITS_ROOT_ALLOWED:
            errors.append("%s: %s=root" % (name, key))
        if key in ("SupplementaryGroups",) and any(g in ("root", "docker", "sudo", "adm") for g in value.split()):
            errors.append("%s: SupplementaryGroups %s" % (name, value))
    return errors


# --- caddy sites ----------------------------------------------------------------------------
CADDY_FORBIDDEN = ("bind", "tls", "servers", "admin", "acme_ca", "acme_dns", "storage", "listen",
                   "auto_https", "http_port", "https_port", "default_bind", "pki")
CADDY_DIRECTIVE_RE = re.compile(r"^(@[A-Za-z0-9_-]+|[a-z][a-z0-9_]*)$")
SNIPPET_RE = re.compile(r"^[A-Za-z0-9_-]+$")


SNIPPET_DEF_RE = re.compile(r"^\([A-Za-z0-9_-]+\)$")


def check_caddy_site(name: str, text: str) -> list:
    """Site files are imported inside site blocks of the global Caddyfile: directives only;
    `import` only of named snippets (no files). The snippet file (const.CADDY_SNIPPET_FILE)
    is imported at the top level and may only define snippets `(name) { ... }`."""
    errors, depth = [], 0
    snippets_only = name == const.CADDY_SNIPPET_FILE
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        tokens = line.split()
        first = tokens[0]
        if first in CADDY_FORBIDDEN:
            errors.append("%s:%d: directive %s not allowed" % (name, lineno, first))
        if first == "import" and not (len(tokens) >= 2 and SNIPPET_RE.match(tokens[1])):
            errors.append("%s:%d: import of files not allowed (snippets only)" % (name, lineno))
        if depth == 0 and snippets_only:
            if not (SNIPPET_DEF_RE.match(first) and tokens[1:] == ["{"]):
                errors.append("%s:%d: only snippet definitions `(name) {` allowed at the top level"
                              % (name, lineno))
        elif depth == 0 and first not in ("}",) and not CADDY_DIRECTIVE_RE.match(first):
            errors.append("%s:%d: %r is not a directive (site addresses belong to the global Caddyfile)"
                          % (name, lineno, first))
        depth += line.count("{") - line.count("}")
        if depth < 0:
            errors.append("%s:%d: unbalanced braces" % (name, lineno))
            depth = 0
    if depth != 0:
        errors.append("%s: unbalanced braces" % name)
    return errors


# --- CLI for tests of other lanes --------------------------------------------------------------
def compose_config_argv(compose_dir: str) -> list:
    argv = ["docker", "compose", "-p", const.COMPOSE_PROJECT, "--project-directory",
            os.path.join(compose_dir, const.COMPOSE_PROJECT_SUBDIR)]
    for f in const.COMPOSE_FILES:
        argv += ["-f", os.path.join(compose_dir, f)]
    for profile in const.COMPOSE_PROFILES_CHECKED:
        argv += ["--profile", profile]
    return argv + ["config", "--format", "json", "--no-interpolate"]


def main(argv=None) -> int:
    import subprocess

    from .host import read_office_env

    parser = argparse.ArgumentParser(prog="python3 -m legatto_update.check")
    sub = parser.add_subparsers(dest="what", required=True)
    p = sub.add_parser("compose")
    p.add_argument("--dir", required=True, help="<release>/compose")
    p.add_argument("--manifest", required=True)
    p.add_argument("--config-json", help="output of docker compose config --format json --no-interpolate")
    p.add_argument("--office-env")
    p = sub.add_parser("unit")
    p.add_argument("files", nargs="+")
    p = sub.add_parser("caddy-site")
    p.add_argument("files", nargs="+")
    p = sub.add_parser("policy", help="validate a policy.json (used by the Ansible role before install)")
    p.add_argument("file")
    args = parser.parse_args(argv)
    errors = []
    if args.what == "policy":
        from . import schema
        try:
            with open(args.file, encoding="utf-8") as fh:
                errors = schema.validate("policy", json.load(fh))
        except ValueError as exc:
            errors = ["not JSON: %s" % exc]
    elif args.what == "compose":
        with open(args.manifest, encoding="utf-8") as fh:
            manifest = json.load(fh)
        office_env = read_office_env(args.office_env) if args.office_env else {}
        if args.config_json:
            with open(args.config_json, encoding="utf-8") as fh:
                cfg = json.load(fh)
        else:
            proc = subprocess.run(compose_config_argv(args.dir), capture_output=True, check=False)
            if proc.returncode != 0:
                print(json.dumps({"ok": False, "errors": ["docker compose config failed: %s"
                                                          % proc.stderr.decode("utf-8", "replace")[-400:]]}))
                return 10
            cfg = json.loads(proc.stdout.decode("utf-8"))
        errors = check_compose_config(cfg, manifest, office_env, os.path.abspath(args.dir))
    else:
        for path in args.files:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            fn = check_unit if args.what == "unit" else check_caddy_site
            errors += fn(os.path.basename(path), text)
    print(json.dumps({"ok": not errors, "errors": errors}, ensure_ascii=False))
    return 0 if not errors else 10


if __name__ == "__main__":
    sys.exit(main())
