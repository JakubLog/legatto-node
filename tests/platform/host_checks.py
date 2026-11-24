#!/usr/bin/env python3
"""Platform lane checks that run on the control machine (tests/platform/run.sh).

Input (environment): LEGATTO_TEST_WORK (work dir with contract.json, versions.json and
env/ rendered by legatto-secrets in the test container).

Covers: unchanged upstream copy (git tree hash), `docker compose config` of upstream +
override with rendered env files, consistency of the compose model with contract.yml,
the updater's compose/unit/caddy-site validators on the lane's files (good and bad
cases), `# contract:` constants in the host tools and the env templates.
The helpers (prepare_release, compose) are also used by the private deployment tooling.
"""

import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import unittest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
WORK = os.path.normpath(os.environ["LEGATTO_TEST_WORK"])
FIXTURES = os.path.join(REPO, "tests", "platform", "fixtures")
CONTRACT = json.load(open(os.path.join(WORK, "contract.json")))
VERSIONS = json.load(open(os.path.join(WORK, "versions.json")))
COMPOSE_SRC = os.path.join(REPO, "bundle", "compose")
COMPOSE = os.path.join(WORK, "release", "compose")
ENV_DIR = os.path.join(WORK, "env")
OFFICE_ENV = os.path.join(FIXTURES, "office.env")
OFFICE = dict(line.rstrip("\n").split("=", 1) for line in open(OFFICE_ENV, encoding="utf-8") if "=" in line)
TOOLS = {name: "sbin/" + name for name in ("legatto-secrets", "legatto-stack", "legatto-acme")}
PLACEHOLDER = re.compile(r'"@@LEGATTO_IMAGE:([a-z0-9-]+)@@"')


def test_image(name):
    return "registry.invalid/legatto/%s" % name, "sha256:" + hashlib.sha256(name.encode()).hexdigest()


def prepare_release():
    """Copy bundle/compose like release/build.sh does and substitute test digests."""
    if os.path.isdir(COMPOSE):
        shutil.rmtree(COMPOSE)
    shutil.copytree(COMPOSE_SRC, COMPOSE, symlinks=True)
    path = os.path.join(COMPOSE, "docker-compose.legatto.yml")
    text = open(path, encoding="utf-8").read()
    text = PLACEHOLDER.sub(lambda m: '"%s@%s"' % test_image(m.group(1)), text)
    open(path, "w", encoding="utf-8").write(text)
    manifest = {"images": [{"name": n, "ref": test_image(n)[0] + ":test", "digest": test_image(n)[1],
                            "platform": "linux/amd64", "artifact": None} for n in CONTRACT["legatto_image_names"]]}
    json.dump(manifest, open(os.path.join(WORK, "manifest.json"), "w"))


def compose(*args, profiles=(), env_dir=ENV_DIR, check=True):
    argv = ["docker", "compose", "-p", CONTRACT["legatto_compose_project"],
            "--project-directory", os.path.join(COMPOSE, "supabase"),
            "-f", os.path.join(COMPOSE, "supabase", "docker-compose.yml"),
            "-f", os.path.join(COMPOSE, "docker-compose.legatto.yml"),
            "--env-file", os.path.join(env_dir, "compose.env")]
    for p in profiles:
        argv += ["--profile", p]
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "DOCKER_HOST", "DOCKER_CONTEXT")}
    env["LEGATTO_RUN_ENV_DIR"] = env_dir
    proc = subprocess.run(argv + list(args), capture_output=True, text=True, env=env)
    if check and proc.returncode != 0:
        raise AssertionError("docker compose %s failed: %s" % (" ".join(args), proc.stderr[-2000:]))
    return proc


def git_tree_hash(path):
    """git tree object id of a directory (blobs 100644/100755, symlinks 120000)."""
    entries = []
    for name in os.listdir(path):
        full = os.path.join(path, name)
        if os.path.islink(full):
            data = os.readlink(full).encode()
            entries.append((name, b"120000", hashlib.sha1(b"blob %d\0" % len(data) + data).digest()))
        elif os.path.isdir(full):
            entries.append((name + "/", b"40000", bytes.fromhex(git_tree_hash(full))))
        else:
            data = open(full, "rb").read()
            mode = b"100755" if os.access(full, os.X_OK) else b"100644"
            entries.append((name, mode, hashlib.sha1(b"blob %d\0" % len(data) + data).digest()))
    body = b"".join(mode + b" " + name.rstrip("/").encode() + b"\0" + sha
                    for name, mode, sha in sorted(entries, key=lambda e: e[0].encode()))
    return hashlib.sha1(b"tree %d\0" % len(body) + body).hexdigest()


def updater_check(*args):
    env = dict(os.environ, PYTHONPATH=os.path.join(REPO, "updater"))
    return subprocess.run([sys.executable, "-m", "legatto_update.check"] + list(args), capture_output=True,
                          text=True, env=env, cwd=REPO)


def setUpModule():
    prepare_release()


class T1Upstream(unittest.TestCase):
    def test_unchanged_upstream_copy(self):
        src = VERSIONS.get("legatto_supabase_docker_source")
        self.assertIsNotNone(src, "versions.yml lacks legatto_supabase_docker_source")
        self.assertEqual(src["tag"], "self-hosted/v" + VERSIONS["legatto_supabase_selfhosted_version"])
        self.assertEqual(git_tree_hash(os.path.join(COMPOSE_SRC, "supabase")), src["tree"],
                         "bundle/compose/supabase differs from docker/ of %s" % src["tag"])

    def test_upstream_images_match_versions(self):
        text = open(os.path.join(COMPOSE_SRC, "supabase", "docker-compose.yml"), encoding="utf-8").read()
        upstream = dict(re.findall(r"^  ([a-z-]+):\n(?:    .*\n)*?    image: (\S+)", text, re.M))
        mapping = {"db": "db", "auth": "auth", "rest": "rest", "realtime": "realtime", "storage": "storage",
                   "api-gw": "api_gw", "functions": "edge_runtime"}
        for service, key in mapping.items():
            self.assertEqual("docker.io/" + upstream[service], VERSIONS["legatto_images"][key]["ref"], service)


class T2Compose(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compose("config", "--quiet")
        cls.default = json.loads(compose("config", "--format", "json").stdout)
        cls.full = json.loads(compose("config", "--format", "json", profiles=("tools",)).stdout)
        cls.everything = json.loads(compose("config", "--format", "json", profiles=("tools", "disabled")).stdout)

    def test_services_and_profiles(self):
        services = set(CONTRACT["legatto_compose_services"])
        self.assertEqual(set(self.default["services"]), services)
        self.assertEqual(set(self.full["services"]), services | {"migrator"})
        self.assertEqual(set(self.everything["services"]) - set(self.full["services"]),
                         {"imgproxy", "supavisor", "meta", "studio"})
        for name in ("imgproxy", "supavisor", "meta", "studio"):
            self.assertEqual(self.everything["services"][name]["profiles"],
                             [CONTRACT["legatto_compose_profile_disabled"]], name)
        self.assertEqual(self.full["name"], CONTRACT["legatto_compose_project"])
        self.assertEqual(self.full["services"]["db"]["container_name"], CONTRACT["legatto_container_db"])

    def test_no_published_ports_anywhere(self):
        for name, svc in self.everything["services"].items():
            self.assertFalse(svc.get("ports"), name)
            self.assertFalse(svc.get("privileged"), name)
            self.assertIsNone(svc.get("network_mode"), name)
            self.assertFalse(svc.get("cap_add"), name)
            self.assertNotIn(svc.get("pid"), ("host",), name)

    def test_images_by_digest(self):
        names = set(CONTRACT["legatto_image_names"])
        used = set(PLACEHOLDER.findall(open(os.path.join(COMPOSE_SRC, "docker-compose.legatto.yml")).read()))
        self.assertEqual(used, names, "every legatto_image_names entry used, nothing else")
        for name, svc in self.full["services"].items():
            self.assertRegex(svc["image"], r"^registry\.invalid/legatto/[a-z0-9-]+@sha256:[0-9a-f]{64}$", name)
            self.assertEqual(svc.get("pull_policy"), "never", name)

    def test_networks_match_contract(self):
        nets = self.full["networks"]
        by_name = {n["name"]: n for n in nets.values()}
        for key, spec in CONTRACT["legatto_docker_networks"].items():
            net = by_name.get(spec["name"])
            self.assertIsNotNone(net, spec["name"])
            self.assertEqual(bool(net.get("internal")), spec["internal"], key)
            self.assertEqual(net["driver_opts"]["com.docker.network.bridge.name"], spec["bridge"], key)
            ipam = net["ipam"]["config"][0]
            self.assertEqual(ipam["subnet"], spec["subnet"], key)
            for field in ("gateway", "ip_range"):
                self.assertEqual(ipam.get(field), spec.get(field), "%s.%s" % (key, field))
        self.assertEqual(set(by_name), {s["name"] for s in CONTRACT["legatto_docker_networks"].values()})

    def svc_ip(self, service, network_name):
        key = next(k for k, n in self.full["networks"].items() if n["name"] == network_name)
        return ((self.full["services"][service].get("networks") or {}).get(key) or {}).get("ipv4_address")

    def test_fixed_addresses(self):
        host = CONTRACT["legatto_docker_networks"]["host"]["name"]
        intn = CONTRACT["legatto_docker_networks"]["int"]["name"]
        ips = CONTRACT["legatto_ip_host_net"]
        self.assertEqual(self.svc_ip("db", host), ips["db"])
        self.assertEqual(self.svc_ip("app", host), ips["app"])
        self.assertEqual(self.svc_ip("api-gw", host), ips["api_gw"])
        self.assertEqual(self.svc_ip("app", intn), CONTRACT["legatto_ip_int_net"]["app"])
        on_host = sorted(s for s, v in self.full["services"].items()
                         if any(self.full["networks"][k]["name"] == host for k in (v.get("networks") or {})))
        self.assertEqual(on_host, ["api-gw", "app", "db"], "only db, app and api-gw on legatto-host")
        self.assertNotIn(ips["dns_blackhole"], json.dumps(self.full["services"]))

    def test_egress_proxies(self):
        ext = CONTRACT["legatto_docker_networks"]["egress_ext"]["name"]
        clients = {"app": "app", "auth": "auth", "functions": "functions"}
        for role, spec in CONTRACT["legatto_egress_container_proxies"].items():
            svc = self.full["services"][spec["service"]]
            role_net = CONTRACT["legatto_docker_networks"][spec["network"]]["name"]
            self.assertEqual(self.svc_ip(spec["service"], ext), spec["ext_ip"], role)
            nets = {self.full["networks"][k]["name"] for k in svc["networks"]}
            self.assertEqual(nets, {ext, role_net}, role)
            self.assertTrue(svc.get("read_only"), role)
            self.assertEqual(svc.get("cap_drop"), ["ALL"], role)
            self.assertEqual([(v["source"], v.get("read_only")) for v in svc["volumes"]],
                             [("/etc/legatto/egress/proxy/" + role, True)], role)
            if role in clients:
                client = self.full["services"][clients[role]]
                cnets = {self.full["networks"][k]["name"] for k in client["networks"]}
                self.assertIn(role_net, cnets)
                env = client["environment"]
                self.assertEqual(env["HTTPS_PROXY"], "http://%s:4750" % spec["service"], role)
                self.assertTrue(env["NO_PROXY"].startswith(CONTRACT["legatto_egress_proxy_env_no_proxy"]), role)
        on_ext = sorted(s for s, v in self.full["services"].items()
                        if any(self.full["networks"][k]["name"] == ext for k in (v.get("networks") or {})))
        self.assertEqual(on_ext, sorted(p["service"] for p in CONTRACT["legatto_egress_container_proxies"].values()))
        for name in ("db", "rest", "realtime", "storage", "api-gw", "migrator"):
            nets = {self.full["networks"][k]["name"] for k in self.full["services"][name].get("networks") or {}}
            self.assertFalse({n for n in nets if "egress" in n}, name + " must have no egress path")

    def test_binds_and_volumes(self):
        release = os.path.join(COMPOSE, "supabase", "volumes") + "/"
        for name, svc in self.full["services"].items():
            for vol in svc.get("volumes") or []:
                if vol["type"] == "bind":
                    self.assertTrue(vol["source"].startswith(release) or vol["source"].startswith(
                        "/etc/legatto/egress/proxy/"), (name, vol["source"]))
                    self.assertTrue(vol.get("read_only"), (name, vol["source"]))
        db_targets = {v["target"]: v for v in self.full["services"]["db"]["volumes"]}
        self.assertEqual(db_targets["/var/lib/postgresql/data"]["type"], "volume")
        self.assertEqual(db_targets["/etc/postgresql-custom"]["source"], "db-config")
        storage = {v["target"]: v for v in self.full["services"]["storage"]["volumes"]}
        self.assertEqual(storage["/var/lib/storage"]["type"], "volume")
        self.assertEqual(self.full["services"]["functions"].get("volumes") or [], [])
        self.assertEqual(self.full["secrets"]["pii_field_key"]["file"], CONTRACT["legatto_paths"]["pii_key"])
        self.assertEqual([s["source"] for s in self.full["services"]["app"]["secrets"]], ["pii_field_key"])

    def test_hardening(self):
        for name in ("app", "functions", "migrator"):
            svc = self.full["services"][name]
            self.assertEqual(svc.get("user"), "%d:%d" % ((CONTRACT["legatto_container_uid"],) * 2), name)
            self.assertTrue(svc.get("read_only"), name)
            self.assertEqual(svc.get("cap_drop"), ["ALL"], name)
        for name, svc in self.full["services"].items():
            self.assertIn("no-new-privileges:true", svc.get("security_opt") or [], name)
        fn_env = self.full["services"]["functions"]["environment"]
        self.assertNotIn("SUPABASE_DB_URL", fn_env)
        self.assertEqual(self.full["services"]["storage"]["environment"]["ENABLE_IMAGE_TRANSFORMATION"], "false")
        self.assertNotIn("IMGPROXY_URL", self.full["services"]["storage"]["environment"])
        self.assertNotIn("depends_on", self.full["services"]["api-gw"])

    def test_extra_hosts_and_hook(self):
        db_hosts = self.full["services"]["db"]["extra_hosts"]
        self.assertEqual(db_hosts, ["%s=%s" % (OFFICE["LEGATTO_HOST_CRM"], OFFICE["LEGATTO_TS_IP4"])])
        auth = self.full["services"]["auth"]
        self.assertEqual(auth["extra_hosts"], ["host.docker.internal=" + CONTRACT["legatto_ip_int_net"]["app"]])
        env = auth["environment"]
        self.assertEqual(env["GOTRUE_HOOK_SEND_EMAIL_URI"],
                         "http://host.docker.internal:%d/_internal/auth-hooks/send-email"
                         % CONTRACT["legatto_ports"]["local"]["app_internal"])
        self.assertIn("host.docker.internal", env["NO_PROXY"].split(","))
        self.assertEqual(env["API_EXTERNAL_URL"], "https://%s/auth/v1" % OFFICE["LEGATTO_HOST_CRM"])
        self.assertEqual(env["GOTRUE_DISABLE_SIGNUP"], "true")

    def test_env_values_survive_compose_dotenv(self):
        auth = self.full["services"]["auth"]["environment"]
        template = open(os.path.join(REPO, "bundle", "env", "auth.env.tmpl"), encoding="utf-8").read()
        literal = re.search(r"^GOTRUE_PASSWORD_REQUIRED_CHARACTERS=(.*)$", template, re.M).group(1)
        # `compose config` prints "$" as "$$"; the container receives a single "$".
        self.assertEqual(auth["GOTRUE_PASSWORD_REQUIRED_CHARACTERS"].replace("$$", "$"), literal)
        app = self.full["services"]["app"]["environment"]
        self.assertEqual(app["APP_TITLE"].replace("$$", "$"), OFFICE["LEGATTO_OFFICE_TITLE"])

    def test_no_unset_variables(self):
        proc = compose("config", "--quiet", profiles=("tools", "disabled"))
        self.assertNotIn("is not set", proc.stderr, proc.stderr)

    def test_updater_policy_accepts_and_rejects(self):
        raw = json.loads(compose("--profile", "tools", "config", "--format", "json", "--no-interpolate").stdout)
        manifest = os.path.join(WORK, "manifest.json")

        def verdict(cfg):
            path = os.path.join(WORK, "cfg-check.json")
            json.dump(cfg, open(path, "w"))
            proc = updater_check("compose", "--dir", COMPOSE, "--manifest", manifest, "--config-json", path,
                                 "--office-env", OFFICE_ENV)
            return proc.returncode, proc.stdout

        rc, out = verdict(raw)
        self.assertEqual(rc, 0, out)
        bad_cases = {
            "ports": lambda c: c["services"]["app"].__setitem__("ports", [{"target": 3000, "published": "3000",
                                                                            "protocol": "tcp", "mode": "ingress"}]),
            "privileged": lambda c: c["services"]["app"].__setitem__("privileged", True),
            "network_mode": lambda c: c["services"]["rest"].__setitem__("network_mode", "host"),
            "pid_host": lambda c: c["services"]["db"].__setitem__("pid", "host"),
            "cap_add": lambda c: c["services"]["auth"].__setitem__("cap_add", ["NET_ADMIN"]),
            "foreign_bind": lambda c: c["services"]["app"].__setitem__(
                "volumes", [{"type": "bind", "source": "/var/run/docker.sock", "target": "/s", "read_only": True}]),
            "tag_image": lambda c: c["services"]["app"].__setitem__("image", "ghcr.io/jakublog/legatto/app:latest"),
        }
        for case, mutate in bad_cases.items():
            cfg = copy.deepcopy(raw)
            mutate(cfg)
            rc, out = verdict(cfg)
            self.assertEqual(rc, 10, "%s accepted: %s" % (case, out))


class T3Files(unittest.TestCase):
    def test_updater_accepts_units_and_sites(self):
        units = sorted(os.path.join(REPO, "bundle", "systemd", n) for n in os.listdir(os.path.join(REPO, "bundle",
                                                                                                    "systemd")))
        proc = updater_check("unit", *units)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        sites = sorted(os.path.join(REPO, "bundle", "caddy", "sites.d", n)
                       for n in os.listdir(os.path.join(REPO, "bundle", "caddy", "sites.d")))
        proc = updater_check("caddy-site", *sites)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        bad = os.path.join(WORK, "crm.caddy")
        open(bad, "w").write("bind 0.0.0.0\nreverse_proxy 172.30.0.10:3000\n")
        self.assertEqual(updater_check("caddy-site", bad).returncode, 10)

    def test_units_contract(self):
        allowed_root = {"legatto-stack.service", "legatto-secrets-render.service"}
        sbin = CONTRACT["legatto_paths"]["sbin"] + "/"
        for name in os.listdir(os.path.join(REPO, "bundle", "systemd")):
            text = open(os.path.join(REPO, "bundle", "systemd", name), encoding="utf-8").read()
            for exe in re.findall(r"^Exec\w+=[-@+!]*(\S+)", text, re.M):
                self.assertTrue(exe.startswith(sbin), (name, exe))
                self.assertIn(os.path.basename(exe), CONTRACT["legatto_cli"].values(), (name, exe))
            if name.endswith(".service") and name not in allowed_root:
                self.assertRegex(text, r"(?m)^DynamicUser=yes$", name)
            self.assertNotRegex(text, r"(?m)^Exec\w+=[+!]", name)
        self.assertIn(CONTRACT["legatto_paths"]["features"],
                      open(os.path.join(REPO, "bundle", "systemd", "legatto-secrets-render.path")).read())

    def test_contract_constants_in_tools(self):
        def lookup(dotted):
            node = CONTRACT
            for part in dotted.split("."):
                node = node[part]
            return node

        checked = 0
        for tool, rel in TOOLS.items():
            lines = open(os.path.join(REPO, rel), encoding="utf-8").read().splitlines()
            for i, line in enumerate(lines):
                m = re.match(r"\s*# contract: ([a-z_.]+)\s*$", line)
                if not m or i + 1 >= len(lines):
                    continue
                v = re.match(r'\s*[A-Z_]+ = (".*?"|\(.*\)|\{.*\}|\d+)\s*$', lines[i + 1])
                if not v:
                    continue
                value = eval(v.group(1), {})  # literal from our own source
                expected = lookup(m.group(1))
                if isinstance(expected, dict) and "name" in expected and isinstance(value, str):
                    expected = expected["name"]
                if isinstance(value, tuple):
                    value = list(value)
                self.assertEqual(value, expected, "%s: %s" % (tool, m.group(1)))
                checked += 1
        self.assertGreater(checked, 25)

    def test_templates_validate(self):
        tool = os.path.join(REPO, TOOLS["legatto-secrets"])
        proc = subprocess.run([sys.executable, tool, "render", "--check", "--json", "--templates",
                               os.path.join(REPO, "bundle", "env")], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        office_keys = set(CONTRACT["legatto_office_env"])
        for name in os.listdir(os.path.join(REPO, "bundle", "env")):
            text = open(os.path.join(REPO, "bundle", "env", name), encoding="utf-8").read()
            for ph in re.findall(r"\$\{(LEGATTO_[A-Z0-9_]+)\}", text):
                self.assertIn(ph, office_keys, name)
        for name in ("compose.env", "app.env", "auth.env", "functions.env", "migrator.env"):
            text = open(os.path.join(ENV_DIR, name), encoding="utf-8").read()
            self.assertNotIn("${", text, name)

    def test_sites_have_no_listeners(self):
        for name in os.listdir(os.path.join(REPO, "bundle", "caddy", "sites.d")):
            text = open(os.path.join(REPO, "bundle", "caddy", "sites.d", name), encoding="utf-8").read()
            self.assertNotRegex(text, r"(?m)^\s*(bind|tls|https?://)\b", name)


if __name__ == "__main__":
    # Fixtures are read with short open(...).read() calls.
    unittest.main(verbosity=2, warnings="ignore")
