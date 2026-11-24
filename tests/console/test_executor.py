"""legatto-console-exec: spool rules, TOTP anti-replay, every request type, pruning, setup and emergency account."""

import json
import os
import subprocess
import unittest
from pathlib import Path

import harness
from harness import OFFICE_IP, STAFF_IP, TreeCase
from legatto_console import contract, crypto, executor, store


def listing(path):
    return sorted(os.listdir(path))


class SpoolRules(TreeCase):
    def test_valid_request_result_archive_audit(self):
        req = self.tree.request("breakglass.disable", {})
        res = self.tree.run(req)
        self.assertEqual(res["status"], "ok", res)
        self.assertEqual((res["v"], res["id"], res["type"], res["sensitive"]), (1, req["id"], "breakglass.disable", False))
        self.assertIsInstance(res["audit_seq"], int)
        results = self.tree.p(contract.REQUESTS_RESULTS)
        st = os.stat(os.path.join(results, req["id"] + ".json"))
        self.assertEqual((st.st_uid, st.st_gid, st.st_mode & 0o777), (0, self.tree.gid, 0o640))
        self.assertEqual(listing(self.tree.p(contract.REQUESTS_INCOMING)), [])
        self.assertEqual(listing(self.tree.p(contract.REQUESTS_PROCESSING)), [])
        archived = store.read_json(os.path.join(self.tree.p(contract.REQUESTS_ARCHIVE), req["id"] + ".json"))
        self.assertNotIn("auth", archived)
        self.assertEqual(archived["executor"]["status"], "ok")
        self.assertEqual(archived["executor"]["node"], "biuro-laptop")
        entry = [e for e in self.tree.audit_entries() if e["event"] == "console.request"][-1]
        self.assertEqual(entry["actor"], {"kind": "office-admin", "id": "szef", "ip": OFFICE_IP, "node": "biuro-laptop"})
        self.assertEqual(entry["node"], "biuro-laptop")
        self.assertEqual(entry["params"]["status"], "ok")
        self.assertNotIn("auth", json.dumps(entry))
        call = [c for c in self.tree.calls(contract.CLI_BREAKGLASS) if c["argv"][0] == "disable"][-1]
        self.assertEqual(call["argv"][:2], ["disable", "--actor"])
        self.assertEqual(json.loads(call["argv"][2])["id"], "szef")

    def test_stale_and_future_timestamps(self):
        for delta in (-121, 121, -3600):
            with self.subTest(delta=delta):
                self.tree.forget_step("szef")
                res = self.tree.run(self.tree.request("breakglass.disable", {}, ts=self.tree.now() + delta))
                self.assertEqual((res["status"], res["code"]), ("rejected", "stale"))
        self.tree.forget_step("szef")
        res = self.tree.run(self.tree.request("breakglass.disable", {}, ts=self.tree.now() - 100))
        self.assertEqual(res["status"], "ok")

    def test_duplicate_id_rejected_without_touching_the_first_result(self):
        req = self.tree.request("breakglass.disable", {})
        first = self.tree.run(req)
        archive_before = listing(self.tree.p(contract.REQUESTS_ARCHIVE))
        self.tree.forget_step("szef")
        again = dict(req, auth={"method": "local-totp", "totp": self.tree.totp("szef")})
        self.tree.drop(again)
        self.assertEqual(self.tree.ex.process(once=True), executor.EXIT_REJECTED)
        self.assertEqual(self.tree.result(req["id"]), first)
        self.assertEqual(listing(self.tree.p(contract.REQUESTS_ARCHIVE)), archive_before)
        self.assertEqual(self.tree.audit_entries()[-1]["params"]["code"], "duplicate_id")
        self.assertEqual(len([c for c in self.tree.calls(contract.CLI_BREAKGLASS) if c["argv"][0] == "disable"]), 1)

    def test_id_mismatch_and_bad_names(self):
        req = self.tree.request("breakglass.disable", {})
        other = crypto.new_ulid()
        self.tree.drop(req, name=other + ".json")
        self.tree.ex.process(once=True)
        self.assertEqual(self.tree.result(other)["code"], "bad_id")
        self.tree.drop(self.tree.request("breakglass.disable", {}), name="evil name.json")
        self.tree.drop(b"{}", name="not-an-ulid.json")
        self.tree.ex.process(once=True)
        self.assertEqual(listing(self.tree.p(contract.REQUESTS_INCOMING)), [])
        self.assertTrue(any(n.startswith("invalid-") for n in listing(self.tree.p(contract.REQUESTS_ARCHIVE))))
        self.assertEqual(listing(self.tree.p(contract.REQUESTS_PROCESSING)), [])
        self.assertEqual(self.tree.calls(contract.CLI_BREAKGLASS), [])

    def test_size_json_owner_link_checks(self):
        cases = []
        big = self.tree.request("breakglass.enable", {"hours": 2, "reason": "x" * 500})
        big["params"]["padding"] = "y" * 8192
        cases.append((big, "too_large", None))
        rid = crypto.new_ulid()
        cases.append((b"{not json", "bad_json", rid))
        cases.append((self.tree.request("breakglass.disable", {}), "bad_owner", 0))
        for payload, code, extra in cases:
            with self.subTest(code=code):
                if code == "bad_json":
                    self.tree.drop(payload, name=extra + ".json")
                    target = extra
                elif code == "bad_owner":
                    self.tree.drop(payload, owner=extra)
                    target = payload["id"]
                else:
                    self.tree.drop(payload)
                    target = payload["id"]
                self.tree.ex.process(once=True)
                self.assertEqual(self.tree.result(target)["code"], code)
        # symlink to a root-only file and a hard link are refused
        secret = self.tree.p("/etc/shadow-test")
        with open(secret, "w") as handle:
            handle.write('{"v":1}')
        link_id = crypto.new_ulid()
        os.symlink(secret, os.path.join(self.tree.p(contract.REQUESTS_INCOMING), link_id + ".json"))
        hard_id = crypto.new_ulid()
        hard_src = self.tree.drop(self.tree.request("breakglass.disable", {}, rid=hard_id))
        os.link(hard_src, self.tree.p("/hardlink-copy"))
        self.tree.ex.process(once=True)
        self.assertEqual(self.tree.result(link_id)["code"], "bad_file")
        self.assertEqual(self.tree.result(hard_id)["code"], "bad_file")
        self.assertEqual(self.tree.calls(contract.CLI_BREAKGLASS), [])

    def test_unknown_or_disabled_user(self):
        res = self.tree.run(self.tree.request("breakglass.disable", {}, user="nikt", totp="123456"))
        self.assertEqual(res["code"], "unknown_user")
        doc = self.tree.ex.users_doc()
        doc["users"]["anna"]["enabled"] = False
        self.tree.ex.save_users(doc)
        res = self.tree.run(self.tree.request("breakglass.disable", {}, user="anna"))
        self.assertEqual(res["code"], "unknown_user")
        entry = self.tree.audit_entries()[-2]
        self.assertEqual(entry["actor"]["kind"], "system")  # unknown login is not trusted as actor

    def test_interrupted_and_abandoned_files(self):
        rid = crypto.new_ulid()
        with open(os.path.join(self.tree.p(contract.REQUESTS_PROCESSING), rid + ".json"), "w") as handle:
            handle.write("{}")
        tmp = os.path.join(self.tree.p(contract.REQUESTS_INCOMING), crypto.new_ulid() + ".json.tmp")
        with open(tmp, "w") as handle:
            handle.write("{}")
        os.utime(tmp, (1, 1))
        self.tree.ex.process()
        self.assertEqual(self.tree.result(rid)["code"], "interrupted")
        self.assertFalse(os.path.exists(tmp))
        self.assertEqual(listing(self.tree.p(contract.REQUESTS_PROCESSING)), [])

    def test_layout_is_enforced(self):
        incoming = self.tree.p(contract.REQUESTS_INCOMING)
        os.chmod(incoming, 0o777)
        with self.assertRaises(executor.Fatal) as ctx:
            self.tree.ex.process()
        self.assertEqual(ctx.exception.code, executor.EXIT_PRECOND)
        os.chmod(incoming, 0o730)
        os.chown(self.tree.p(contract.REQUESTS_ARCHIVE), self.tree.uid, 0)
        self.assertIn(contract.REQUESTS_ARCHIVE, " ".join(executor.layout_problems()))
        os.chown(self.tree.p(contract.REQUESTS_ARCHIVE), 0, 0)
        self.assertEqual(executor.layout_problems(), [])


class ConsoleUserPermissions(TreeCase):
    """What the unprivileged panel user can and cannot do in the spool (CONTRACT §4.3)."""

    def as_console(self, code):
        script = "import os,sys\n" + code
        return subprocess.run(["setpriv", "--reuid", contract.CONSOLE_USER, "--regid", contract.CONSOLE_GROUP,
                               "--init-groups", "python3", "-I", "-c", script], capture_output=True, text=True,
                              check=False)

    def test_spool_permissions(self):
        rid = crypto.new_ulid()
        res = self.tree.run(self.tree.request("breakglass.disable", {}))
        p = self.tree.p
        probe = f"""
def can(fn):
    try:
        fn(); return "yes"
    except OSError:
        return "no"
inc = {p(contract.REQUESTS_INCOMING)!r}
out = {{
 "write_incoming": can(lambda: open(os.path.join(inc, "{rid}.json.tmp"), "x").close()),
 "rename_incoming": can(lambda: os.rename(os.path.join(inc, "{rid}.json.tmp"), os.path.join(inc, "{rid}.json"))),
 "list_incoming": can(lambda: os.listdir(inc)),
 "read_results": can(lambda: open(os.path.join({p(contract.REQUESTS_RESULTS)!r}, "{res['id']}.json")).read()),
 "write_results": can(lambda: open(os.path.join({p(contract.REQUESTS_RESULTS)!r}, "x.json"), "x").close()),
 "list_processing": can(lambda: os.listdir({p(contract.REQUESTS_PROCESSING)!r})),
 "list_archive": can(lambda: os.listdir({p(contract.REQUESTS_ARCHIVE)!r})),
 "list_auth": can(lambda: os.listdir({p(contract.CONSOLE_AUTH)!r})),
 "read_seed": can(lambda: open(os.path.join({p(contract.CONSOLE_TOTP_SEEDS)!r}, "szef")).read()),
 "read_users": can(lambda: open({p(contract.CONSOLE_USERS)!r}).read()),
 "write_users": can(lambda: open({p(contract.CONSOLE_USERS)!r}, "a").close()),
}}
print(" ".join(f"{{k}}={{v}}" for k, v in sorted(out.items())))
"""
        proc = self.as_console(probe)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        result = dict(item.split("=") for item in proc.stdout.split())
        self.assertEqual(result, {
            "write_incoming": "yes", "rename_incoming": "yes", "list_incoming": "no", "read_results": "yes",
            "write_results": "no", "list_processing": "no", "list_archive": "no", "list_auth": "no",
            "read_seed": "no", "read_users": "yes", "write_users": "no"})
        # the file the panel user created is processed (owner check passes) and rejected only for its content
        self.tree.ex.process(once=True)
        self.assertEqual(self.tree.result(rid)["code"], "bad_json")


class Totp(TreeCase):
    def test_anti_replay_and_lockout(self):
        code = self.tree.totp("szef")
        self.assertEqual(self.tree.run(self.tree.request("breakglass.disable", {}, totp=code))["status"], "ok")
        replay = self.tree.run(self.tree.request("breakglass.disable", {}, totp=code))
        self.assertEqual(replay["code"], "totp_replay")
        older = self.tree.run(self.tree.request("breakglass.disable", {}, totp=self.tree.totp("szef", -1)))
        self.assertEqual(older["code"], "totp_replay")
        newer = self.tree.run(self.tree.request("breakglass.disable", {}, totp=self.tree.totp("szef", 1)))
        self.assertEqual(newer["status"], "ok")
        step_file = os.path.join(self.tree.p(contract.CONSOLE_AUTH), "szef.step")
        self.assertEqual(int(Path(step_file).read_text()), crypto.totp_step(self.tree.now()) + 1)
        self.assertEqual(os.stat(step_file).st_mode & 0o777, 0o600)

    def test_wrong_codes_lock_the_account_for_a_while(self):
        good = self.tree.totp("szef")
        wrong = "000000" if good != "000000" else "111111"
        for _ in range(executor.TOTP_FAIL_LIMIT):
            self.assertEqual(self.tree.run(self.tree.request("breakglass.disable", {}, totp=wrong))["code"], "bad_totp")
        self.assertEqual(self.tree.run(self.tree.request("breakglass.disable", {}, totp=good))["code"], "totp_locked")
        self.tree.clock_offset = executor.TOTP_FAIL_WINDOW + 1
        self.assertEqual(self.tree.run(self.tree.request("breakglass.disable", {}))["status"], "ok")

    def test_login_success_and_failure_are_audited(self):
        res = self.tree.run(self.tree.request("console.login", {}))
        self.assertEqual((res["status"], res["data"]["must_change"]), ("ok", False))
        self.assertEqual(self.tree.audit_entries()[-1]["event"], "console.login")
        bad = "999999" if self.tree.totp("szef") != "999999" else "888888"
        res = self.tree.run(self.tree.request("console.login", {}, totp=bad))
        self.assertEqual(res["status"], "rejected")
        self.assertEqual(self.tree.audit_entries()[-1]["event"], "console.login_failed")
        entries = json.dumps(self.tree.audit_entries())
        self.assertNotIn(bad, entries)
        self.assertNotIn('"auth"', entries)


class Handlers(TreeCase):
    def call(self, rtype, params, **kw):
        self.tree.forget_step(kw.get("user", "szef"))
        return self.tree.run(self.tree.request(rtype, params, **kw))

    def last_argv(self, tool):
        return self.tree.calls(tool)[-1]["argv"]

    def test_breakglass(self):
        self.tree.fake(contract.CLI_BREAKGLASS, {"enable": {"rc": 0, "stdout": {
            "window_id": "w1", "started_at": "2026-11-21T10:00:00Z", "expires_at": "2026-11-21T12:00:00Z",
            "policy_asserted": True}}, "disable": {"rc": 20, "stdout": None}})
        res = self.call("breakglass.enable", {"hours": 2, "reason": "Aktualizacja systemu"})
        self.assertEqual((res["status"], res["data"]["window_id"]), ("ok", "w1"))
        self.assertIn("21.11.2026 13:00", res["message"])
        argv = self.last_argv(contract.CLI_BREAKGLASS)
        self.assertEqual(argv[:5], ["enable", "--hours", "2", "--reason", "Aktualizacja systemu"])
        self.assertEqual(argv[-1], "--json")
        audit = [e for e in self.tree.audit_entries() if e["event"] == "console.request"][-1]
        self.assertEqual(audit["params"]["reason"], "Aktualizacja systemu")
        res = self.call("breakglass.disable", {"reason": "Koniec"})
        self.assertEqual(res["code"], "not_active")
        self.assertEqual(self.last_argv(contract.CLI_BREAKGLASS)[:3], ["disable", "--reason", "Koniec"])

    def test_update_family(self):
        sha = "a" * 64
        self.tree.fake(contract.CLI_UPDATE, {
            "approve": {"rc": 0, "stdout": {"ok": True, "code": "approved", "message": "Zatwierdzono 1.5.0.", "data": {}}},
            "reject": {"rc": 10, "stdout": {"ok": False, "code": "not_pending", "message": "Brak.", "data": {}}},
            "rollback": {"rc": 13, "stdout": None},
            "autosecurity": {"rc": 4, "stdout": {"ok": False, "code": "policy_forbids", "message": "Polityka.",
                                                  "data": {}}}})
        res = self.call("update.approve", {"release": "1.5.0", "manifest_sha256": sha,
                                           "not_before": "2026-11-22T22:00:00Z"})
        self.assertEqual((res["status"], res["message"]), ("ok", "Zatwierdzono 1.5.0."))
        self.assertEqual(self.last_argv(contract.CLI_UPDATE)[:7], ["approve", "--release", "1.5.0", "--manifest-sha256",
                                                                   sha, "--not-before", "2026-11-22T22:00:00Z"])
        self.assertEqual(self.call("update.reject", {"release": "1.5.0", "manifest_sha256": sha})["code"],
                         "not_pending")
        self.assertEqual(self.call("update.rollback", {"to": "1.4.0"})["code"], "rollback_reverted")
        self.assertEqual(self.last_argv(contract.CLI_UPDATE)[:3], ["rollback", "--to", "1.4.0"])
        res = self.call("update.autosecurity", {"enabled": True})
        self.assertEqual((res["status"], res["code"]), ("rejected", "policy_forbids"))
        self.assertEqual(self.last_argv(contract.CLI_UPDATE)[:3], ["autosecurity", "--enabled", "true"])

    def test_update_approve_install_now(self):
        sha = "b" * 64
        self.tree.fake(contract.CLI_UPDATE, {"approve": {"rc": 0, "stdout": {"ok": True, "code": "approved",
                                                                              "data": {"install_now": True}}}})
        res = self.call("update.approve", {"release": "1.6.0", "manifest_sha256": sha, "install_now": True})
        self.assertEqual((res["status"], res["code"]), ("ok", "approved"))
        self.assertIn("bez czekania na okno nocne", res["message"])
        self.assertIn("opóźnieniu kanału", res["message"])
        argv = self.last_argv(contract.CLI_UPDATE)
        self.assertEqual(argv[:6], ["approve", "--release", "1.6.0", "--manifest-sha256", sha, "--install-now"])
        self.assertNotIn("--not-before", argv)
        self.assertTrue(self.tree.audit_entries()[-1]["params"]["install_now"])
        # install_now false is the default path: no flag, the install waits for the night window
        self.call("update.approve", {"release": "1.6.0", "manifest_sha256": sha, "install_now": False})
        self.assertNotIn("--install-now", self.last_argv(contract.CLI_UPDATE))
        calls = len(self.tree.calls(contract.CLI_UPDATE))
        res = self.call("update.approve", {"release": "1.6.0", "manifest_sha256": sha, "install_now": True,
                                           "not_before": "2026-11-22T22:00:00Z"})
        self.assertEqual((res["status"], res["code"]), ("rejected", "bad_params"))
        res = self.call("update.approve", {"release": "1.6.0", "manifest_sha256": sha, "install_now": "true"})
        self.assertEqual((res["status"], res["code"]), ("rejected", "bad_params"))
        self.assertEqual(len(self.tree.calls(contract.CLI_UPDATE)), calls)

    def test_devices_and_staff(self):
        self.tree.fake(contract.CLI_TAILNET, {
            "enroll": {"rc": 0, "stdout": {"kind": "staff", "user": "anna.nowak", "tags": [], "key": "hskey-abc",
                                           "expires_at": "2026-11-21T10:30:00Z",
                                           "login_server": "https://vpn.example.pl"}},
            "revoke": {"rc": 0, "stdout": {"node_id": "7", "name": "anna-telefon"}},
            "staff-set": {"rc": 0, "stdout": {}},
            "nodes": {"rc": 0, "stdout": {"nodes": [
                {"id": "1", "name": "srv", "user": "server", "tags": ["tag:server"], "ip4": "100.64.0.1",
                 "ip6": "fd7a:115c:a1e0::1", "online": True, "last_seen": None, "expiry": None},
                {"id": "7", "name": "anna-telefon", "user": "anna.nowak", "tags": [], "ip4": "100.64.0.7",
                 "ip6": "fd7a:115c:a1e0::7", "online": False, "last_seen": "2026-11-21T09:00:00Z", "expiry": None}]}}})
        res = self.call("device.enroll", {"kind": "staff", "login": "anna.nowak"})
        self.assertEqual((res["status"], res["sensitive"], res["data"]["key"]), ("ok", True, "hskey-abc"))
        self.assertEqual(self.last_argv(contract.CLI_TAILNET)[:5], ["enroll", "--kind", "staff", "--login", "anna.nowak"])
        self.assertNotIn("hskey-abc", json.dumps(self.tree.audit_entries()))
        archived = store.read_json(os.path.join(self.tree.p(contract.REQUESTS_ARCHIVE), res["id"] + ".json"))
        self.assertNotIn("hskey-abc", json.dumps(archived))
        res = self.call("staff.set", {"staff": ["anna.nowak", "jan.kowalski"]})
        self.assertEqual(res["status"], "ok")
        argv = [c["argv"] for c in self.tree.calls(contract.CLI_TAILNET) if c["argv"][0] == "staff-set"][-1]
        self.assertEqual(argv[0], "staff-set")
        self.assertFalse(os.path.exists(argv[2]))  # temporary file removed
        self.tree.ex.refresh_snapshot()
        self.assertEqual(self.call("device.revoke", {"node_id": "1"})["code"], "server_node")
        res = self.call("device.revoke", {"node_id": "7"})
        self.assertEqual((res["status"], res["data"]["name"]), ("ok", "anna-telefon"))
        self.tree.fake(contract.CLI_TAILNET, {"enroll": {"rc": 24, "stdout": None}})
        self.assertEqual(self.call("device.enroll", {"kind": "staff", "login": "obcy"})["code"], "unknown_login")

    def test_features(self):
        res = self.call("features.set", {"feature": "ics", "enabled": True, "ics_hosts": ["kalendarz.example.pl"]})
        self.assertEqual(res["status"], "ok")
        doc = store.read_json(self.tree.p(contract.FEATURES))
        self.assertTrue(doc["features"]["ics"])
        self.assertEqual(doc["ics_hosts"], ["kalendarz.example.pl"])
        self.assertEqual(set(doc), {"v", "updated_at", "features", "ics_hosts"})
        st = os.stat(self.tree.p(contract.FEATURES))
        self.assertEqual((st.st_gid, st.st_mode & 0o777), (self.tree.gid, 0o640))
        self.assertEqual(self.last_argv(contract.CLI_EGRESS)[:2], ["apply", "--actor"])
        before = Path(self.tree.p(contract.FEATURES)).read_bytes()
        self.tree.fake(contract.CLI_EGRESS, {"apply": {"rc": 42, "stdout": None}})
        res = self.call("features.set", {"feature": "ai", "enabled": True})
        self.assertEqual(res["code"], "egress_invalid")
        self.assertEqual(Path(self.tree.p(contract.FEATURES)).read_bytes(), before)  # rolled back

    def test_recovery_pack_and_pruning(self):
        res = self.call("recovery.generate", {})
        self.assertEqual((res["status"], res["sensitive"]), ("ok", True))
        recovery = self.tree.p(contract.RECOVERY_DIR)
        self.assertTrue(os.path.exists(os.path.join(recovery, res["data"]["file"])))
        self.assertNotIn(res["data"]["password"], json.dumps(self.tree.audit_entries()))
        plain = self.call("breakglass.disable", {})
        self.tree.ex.prune()
        self.assertIsNotNone(self.tree.result(res["id"]))
        self.tree.clock_offset = contract.SENSITIVE_RESULT_TTL_SECONDS - 30
        self.tree.ex.prune()
        self.assertIsNotNone(self.tree.result(res["id"]))
        self.tree.clock_offset = contract.SENSITIVE_RESULT_TTL_SECONDS + 1
        self.tree.ex.prune()
        self.assertIsNone(self.tree.result(res["id"]))
        self.assertEqual(os.listdir(recovery), [])
        self.assertIsNotNone(self.tree.result(plain["id"]))  # non-sensitive results stay
        self.tree.clock_offset = contract.ARCHIVE_RETENTION_DAYS * 86400 + 1
        archive = self.tree.p(contract.REQUESTS_ARCHIVE)
        for name in os.listdir(archive):
            os.utime(os.path.join(archive, name), (self.tree.now() - contract.ARCHIVE_RETENTION_DAYS * 86400 - 2,) * 2)
        self.tree.ex.prune()
        self.assertIsNone(self.tree.result(plain["id"]))
        self.assertEqual(os.listdir(archive), [])

    def test_recovery_pack_outside_its_directory_is_refused(self):
        self.tree.fake(contract.CLI_RECOVERY_PACK, {"generate": {"rc": 0, "stdout": {
            "file": "/etc/shadow", "password": "x", "sha256": "0" * 64, "bytes": 1}}})
        self.assertEqual(self.call("recovery.generate", {})["code"], "tool_output")

    def test_tool_failures_map_to_codes(self):
        for rc, status, code in ((2, "rejected", "bad_args"), (3, "error", "busy"), (4, "error", "precondition"),
                                 (1, "error", "tool_failed")):
            with self.subTest(rc=rc):
                self.tree.fake(contract.CLI_BREAKGLASS, {"disable": {"rc": rc, "stdout": None}})
                res = self.call("breakglass.disable", {})
                self.assertEqual((res["status"], res["code"]), (status, code))
        os.unlink(contract.tool(contract.CLI_BREAKGLASS))
        self.assertEqual(self.call("breakglass.disable", {})["code"], "tool_missing")

    def test_contacts(self):
        person = {"name": "Anna Nowak", "email": "anna@example.pl", "phone": "+48 600 100 200"}
        res = self.call("contacts.set", {"primary": person, "iod": person, "notes": "Wyznaczony IOD"})
        self.assertEqual(res["status"], "ok")
        doc = store.read_json(self.tree.p(contract.INCIDENT_CONTACTS))
        self.assertEqual((doc["v"], doc["primary"], doc["secondary"]), (1, person, None))
        audit = json.dumps(self.tree.audit_entries())
        self.assertNotIn("anna@example.pl", audit)
        self.assertIn("console.contacts.set", audit)

    def test_console_accounts(self):
        res = self.call("console.user.add", {"login": "jan.kowalski", "display_name": "Jan Kowalski"})
        self.assertEqual((res["status"], res["sensitive"]), ("ok", True))
        initial = res["data"]["initial_password"]
        user = self.tree.ex.users_doc()["users"]["jan.kowalski"]
        self.assertTrue(user["must_change"])
        self.assertTrue(crypto.scrypt_verify(initial, user["password"]))
        seed = os.path.join(self.tree.p(contract.CONSOLE_TOTP_SEEDS), "jan.kowalski")
        self.assertEqual(os.stat(seed).st_mode & 0o777, 0o400)
        self.assertIn("secret=" + res["data"]["totp_secret"], res["data"]["otpauth_uri"])
        self.assertEqual(self.call("console.user.add", {"login": "jan.kowalski", "display_name": "Jan"})["code"],
                         "exists")
        # the new user changes the password himself: must_change cleared
        new_hash = crypto.scrypt_hash("nowe-dlugie-haslo")
        res = self.call("console.user.password", {"login": "jan.kowalski", "scrypt": new_hash}, user="jan.kowalski")
        self.assertEqual(res["status"], "ok")
        self.assertFalse(self.tree.ex.users_doc()["users"]["jan.kowalski"]["must_change"])
        # an admin sets a temporary password for somebody else: must_change set again
        self.call("console.user.password", {"login": "jan.kowalski", "scrypt": new_hash})
        self.assertTrue(self.tree.ex.users_doc()["users"]["jan.kowalski"]["must_change"])
        weak = crypto.scrypt_hash("x", n=2 ** 12)
        self.assertEqual(self.call("console.user.password", {"login": "anna", "scrypt": weak})["code"], "weak_hash")
        old_seed = Path(seed).read_text()
        res = self.call("console.user.reset_totp", {"login": "jan.kowalski"})
        self.assertEqual(res["status"], "ok")
        self.assertNotEqual(Path(seed).read_text(), old_seed)
        self.assertEqual(self.call("console.user.remove", {"login": "szef"})["code"], "self_remove")
        self.assertEqual(self.call("console.user.remove", {"login": "jan.kowalski"})["status"], "ok")
        self.assertFalse(os.path.exists(seed))
        self.assertEqual(self.call("console.user.remove", {"login": "anna"})["status"], "ok")
        # szef is the last active regular account now
        self.tree.add_user("drugi")
        doc = self.tree.ex.users_doc()
        doc["users"]["drugi"]["enabled"] = False
        self.tree.ex.save_users(doc)
        self.tree.ex.emergency_credentials({"kind": "system", "id": "legatto-recovery-pack"})
        res = self.call("console.user.remove", {"login": "szef"}, user=contract.EMERGENCY_LOGIN)
        self.assertEqual(res["code"], "last_active")
        for rtype in ("console.user.remove", "console.user.reset_totp"):
            self.assertEqual(self.call(rtype, {"login": contract.EMERGENCY_LOGIN})["code"], "reserved_login")
        events = [e["event"] for e in self.tree.audit_entries()]
        for event in ("console.user.add", "console.user.password", "console.user.reset_totp", "console.user.remove",
                      "console.user.emergency_rotate"):
            self.assertIn(event, events)


class SetupAndEmergency(unittest.TestCase):
    def setUp(self):
        if not harness.IS_ROOT:
            self.skipTest("needs root")
        self.tree = harness.ServerTree()

    def tearDown(self):
        self.tree.cleanup()

    def setup_request(self, code, ip=OFFICE_IP, login="szef"):
        params = {"login": login, "display_name": "Szef Biura", "scrypt": crypto.scrypt_hash("haslo szefa biura")}
        return self.tree.request("console.setup", params, user=login, ip=ip,
                                 auth={"method": "setup-code", "code": code})

    def test_first_account_with_one_time_code(self):
        issued = self.tree.ex.setup_code({"kind": "vendor", "id": "v-jan"})
        record = store.read_json(self.tree.p(executor.contract.SETUP_CODE_FILE))
        self.assertNotIn(issued["code"], json.dumps(record))
        self.assertEqual(self.tree.audit_entries()[-1]["event"], "console.user.setup_code")
        self.assertNotIn(issued["code"], json.dumps(self.tree.audit_entries()))
        # not from an office device (vendor in a break-glass window, staff phone)
        res = self.tree.run(self.setup_request(issued["code"], ip=STAFF_IP))
        self.assertEqual(res["code"], "not_office_device")
        res = self.tree.run(self.setup_request(crypto.new_setup_code()))
        self.assertEqual(res["code"], "bad_setup_code")
        res = self.tree.run(self.setup_request(issued["code"]))
        self.assertEqual((res["status"], res["sensitive"]), ("ok", True))
        self.assertTrue(res["data"]["otpauth_uri"].startswith("otpauth://totp/"))
        self.assertFalse(os.path.exists(self.tree.p(executor.contract.SETUP_CODE_FILE)))
        self.assertEqual(self.tree.audit_entries()[-1]["event"], "console.user.setup")
        # the code is single use and a configured panel refuses new codes
        res = self.tree.run(self.setup_request(issued["code"], login="drugi"))
        self.assertEqual(res["code"], "already_configured")
        with self.assertRaises(executor.Fatal):
            self.tree.ex.setup_code({"kind": "vendor", "id": "v-jan"})
        self.assertEqual(self.tree.run(self.tree.request("console.login", {}))["status"], "ok")

    def test_setup_code_expiry_and_brute_force(self):
        issued = self.tree.ex.setup_code({"kind": "vendor", "id": "v-jan"})
        for attempt in range(executor.SETUP_FAIL_LIMIT):
            res = self.tree.run(self.setup_request(crypto.new_setup_code()))
        self.assertEqual(res["code"], "setup_code_destroyed")
        self.assertEqual(self.tree.run(self.setup_request(issued["code"]))["code"], "no_setup_code")
        issued = self.tree.ex.setup_code({"kind": "vendor", "id": "v-jan"})
        self.tree.clock_offset = contract.SETUP_CODE_TTL_HOURS * 3600 + 1
        self.assertEqual(self.tree.run(self.setup_request(issued["code"]))["code"], "setup_code_expired")

    def test_emergency_account_does_not_block_setup_and_rotates(self):
        first = self.tree.ex.emergency_credentials({"kind": "system", "id": "legatto-recovery-pack"})
        self.assertEqual(first["login"], contract.EMERGENCY_LOGIN)
        issued = self.tree.ex.setup_code({"kind": "vendor", "id": "v-jan"})  # emergency account is not "active"
        self.assertTrue(issued["code"])
        second = self.tree.ex.emergency_credentials({"kind": "system", "id": "legatto-recovery-pack"})
        self.assertNotEqual(first["password"], second["password"])
        self.assertNotEqual(first["totp_secret"], second["totp_secret"])
        user = self.tree.ex.users_doc()["users"][contract.EMERGENCY_LOGIN]
        self.assertEqual(user["kind"], "emergency")
        self.assertFalse(crypto.scrypt_verify(first["password"], user["password"]))
        self.assertTrue(crypto.scrypt_verify(second["password"], user["password"]))
        self.assertNotIn(second["password"], json.dumps(self.tree.audit_entries()))
        res = self.tree.run(self.setup_request(issued["code"], login=contract.EMERGENCY_LOGIN))
        self.assertEqual(res["code"], "reserved_login")

    def test_cli(self):
        env = dict(os.environ, LEGATTO_CONSOLE_PREFIX=self.tree.root)
        cli = os.path.join(harness.CONSOLE_SRC, "bin", "legatto-console-exec")
        proc = subprocess.run([cli, "setup-code", "--json", "--actor", '{"kind":"vendor","id":"v-jan"}'],
                              capture_output=True, text=True, env=env, check=False)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertRegex(json.loads(proc.stdout)["code"], r"^[0-9A-Z]{4}(-[0-9A-Z]{4}){3}$")
        proc = subprocess.run([cli, "emergency-credentials"], capture_output=True, text=True, env=env, check=False)
        self.assertEqual(proc.returncode, executor.EXIT_ARGS)
        self.assertEqual(proc.stdout, "")
        proc = subprocess.run([cli, "process"], capture_output=True, text=True, env=env, check=False)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        proc = subprocess.run([cli, "bogus"], capture_output=True, text=True, env=env, check=False)
        self.assertEqual(proc.returncode, executor.EXIT_ARGS)
        proc = subprocess.run(["setpriv", "--reuid", contract.CONSOLE_USER, "--regid", contract.CONSOLE_GROUP,
                               "--init-groups", cli, "prune"], capture_output=True, text=True, env=env, check=False)
        self.assertEqual(proc.returncode, executor.EXIT_PRECOND)


if __name__ == "__main__":
    unittest.main()
