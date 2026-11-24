"""legatto-breakglass state machine with fake headscale/nft/tailscale (CONTRACT §6 net)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import unittest

from harness import ToolTestCase

OFFICE = json.dumps({"kind": "office-admin", "id": "szef-biura", "node": "biuro-laptop"})
REASON = "Aktualizacja konfiguracji po awarii dysku"
START = "2026-11-21T10:00:00Z"


class BreakglassTest(ToolTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.now = START
        self.assert_ok(self.run_tool("legatto-policy", "apply", "--timeout", "5"))

    def enable(self, hours: str = "1", reason: str = REASON, actor: str = OFFICE):
        return self.run_tool("legatto-breakglass", "enable", "--hours", hours, "--reason", reason, "--actor", actor,
                             "--json")

    def sets(self) -> dict:
        return self.fake()["sets"]

    def loaded_variant(self) -> str:
        return "breakglass" if "group:vendor\"], \"dst\": [\"ssh\"]" in self.fake()["loaded_policy"] else "normal"

    def test_enable_opens_window(self) -> None:
        proc = self.enable()
        self.assert_ok(proc)
        out = json.loads(proc.stdout)
        self.assertTrue(out["policy_asserted"])
        self.assertEqual(out["expires_at"], "2026-11-21T11:00:00Z")
        state = self.read("var/lib/legatto/breakglass/state.json")
        self.assertTrue(state["active"])
        self.assertEqual(state["actor"]["id"], "szef-biura")
        self.assertEqual(self.sets()["bg4"], {"100.64.0.4": 3600})
        self.assertEqual(self.sets()["bg6"], {"fd7a:115c:a1e0::4": 3600})
        self.assertEqual(self.sets()["vendor4"], {"100.64.0.4": None})
        self.assertEqual(self.loaded_variant(), "breakglass")
        self.assertIn("breakglass.enable", self.events())
        status = self.read("var/lib/legatto/status/breakglass.json")
        self.assertEqual((status["active"], status["window_id"], status["reason"]), (True, out["window_id"], REASON))
        self.assertEqual(self.audit_entries()[0]["params"]["reason"], REASON)

    def test_enable_twice_exit_20(self) -> None:
        self.assert_ok(self.enable())
        self.assertEqual(self.enable().returncode, 20)

    def test_disable_without_window_exit_20(self) -> None:
        proc = self.run_tool("legatto-breakglass", "disable", "--actor", OFFICE)
        self.assertEqual(proc.returncode, 20)

    def test_argument_validation(self) -> None:
        self.assertEqual(self.enable(hours="9").returncode, 2)
        self.assertEqual(self.enable(hours="0").returncode, 2)
        self.assertEqual(self.enable(reason="za krótko").returncode, 2)
        self.assertEqual(self.enable(reason="x" * 501).returncode, 2)
        self.assertEqual(self.enable(reason="tekst z\nnową linią i czymś").returncode, 2)
        self.assertEqual(self.enable(actor="{}").returncode, 2)
        self.assertFalse(os.path.exists(self.path("var/lib/legatto/breakglass/state.json")))

    def test_restart_during_window_restores_sets_without_extension(self) -> None:
        self.assert_ok(self.enable(hours="2"))
        self.set_fake({"sets": {"vendor4": {}, "vendor6": {}, "bg4": {}, "bg6": {}}})  # reboot: empty sets
        self.now = "2026-11-21T10:30:00Z"
        self.assert_ok(self.run_tool("legatto-breakglass", "reconcile", "--sets-only"))
        self.assertEqual(self.sets()["bg4"], {"100.64.0.4": 5400})
        self.assertEqual(self.sets()["vendor4"], {"100.64.0.4": None})
        state = self.read("var/lib/legatto/breakglass/state.json")
        self.assertEqual(state["expires_at"], "2026-11-21T12:00:00Z")

    def test_vendor_sets_persisted_for_every_load(self) -> None:
        self.assert_ok(self.run_tool("legatto-breakglass", "reconcile", "--sets-only"))
        persisted = self.text("var/lib/legatto/breakglass/nft/vendors.nft")
        self.assertIn("set vendor4 { type ipv4_addr; elements = { 100.64.0.4 } }", persisted)
        self.assertIn("set vendor6 { type ipv6_addr; elements = { fd7a:115c:a1e0::4 } }", persisted)
        self.assertNotIn("bg4", persisted)  # never persist an open window

    def test_sets_only_uses_cache_when_headscale_is_down(self) -> None:
        self.assert_ok(self.enable())
        self.set_fake({"headscale_down": True, "sets": {"vendor4": {}, "vendor6": {}, "bg4": {}, "bg6": {}}})
        self.assert_ok(self.run_tool("legatto-breakglass", "reconcile", "--sets-only"))
        self.assertEqual(self.sets()["vendor4"], {"100.64.0.4": None})
        self.assertEqual(self.sets()["bg4"], {"100.64.0.4": 3600})

    def test_expiry_closes_window_and_cuts_sessions(self) -> None:
        self.assert_ok(self.enable())
        # a vendor session and some activity inside the window
        self.set_fake({"sessions": ["v-jan", "ubuntu"]})
        # the test container is throw-away: give it the vendor account in legatto-ops
        subprocess.run(["groupadd", "-f", "legatto-ops"], check=True)
        if subprocess.run(["id", "v-jan"], capture_output=True).returncode != 0:
            subprocess.run(["useradd", "-M", "-G", "legatto-ops", "v-jan"], check=True)
        for event, params in (("ssh.login", {"user": "v-jan", "ip": "100.64.0.4", "key_fp": "SHA256:x"}),
                              ("sudo.command", {"user": "v-jan", "runas": "root", "command": "/usr/bin/id"})):
            self.assert_ok(self.run_tool("legatto-audit", "append", "--cat", event.split(".")[0], "--event", event,
                                         "--actor", json.dumps({"kind": "vendor", "id": "v-jan"}),
                                         "--params", json.dumps(params)))
        self.now = "2026-11-21T11:00:00Z"
        proc = self.run_tool("legatto-breakglass", "reconcile", "--json")
        self.assert_ok(proc)
        self.assertEqual(json.loads(proc.stdout)["action"], "expired")
        state = self.read("var/lib/legatto/breakglass/state.json")
        self.assertFalse(state["active"])
        self.assertEqual(state["close_reason"], "expired")
        self.assertEqual(self.sets()["bg4"], {})
        self.assertEqual(self.sets()["vendor4"], {"100.64.0.4": None})
        self.assertEqual(self.loaded_variant(), "normal")
        conntrack = self.fake()["conntrack"]
        self.assertIn(["-D", "-s", "100.64.0.4"], conntrack)
        self.assertIn(["-D", "-f", "ipv6", "-s", "fd7a:115c:a1e0::4"], conntrack)
        self.assertEqual(self.fake().get("terminated"), ["v-jan"])
        self.assertIn("breakglass.expire", self.events())
        summary = self.read(f"var/lib/legatto/breakglass/summaries/{state['window_id']}.json")
        self.assertEqual(summary["ssh"]["logins"][0]["user"], "v-jan")
        self.assertEqual(summary["sudo"]["count"], 1)
        self.assertTrue(summary["audit"]["chain_ok"])
        self.assertFalse(self.read("var/lib/legatto/status/breakglass.json")["active"])
        self.assert_ok(self.run_tool("legatto-audit", "verify"))

    def test_disable_closes_window(self) -> None:
        self.assert_ok(self.enable())
        proc = self.run_tool("legatto-breakglass", "disable", "--reason", "koniec prac", "--actor", OFFICE, "--json")
        self.assert_ok(proc)
        out = json.loads(proc.stdout)
        self.assertEqual(out["close_reason"], "disabled")
        self.assertTrue(os.path.exists(out["summary_path"]))
        self.assertEqual(self.sets()["bg4"], {})
        self.assertEqual(self.loaded_variant(), "normal")
        self.assertEqual(self.events()[-1], "breakglass.disable")
        summary = json.loads(self.run_tool("legatto-breakglass", "summary", "--window", out["window_id"],
                                           "--json").stdout)
        self.assertEqual(summary["close_reason"], "disabled")

    def shorten(self, minutes: str, actor: str = OFFICE):
        return self.run_tool("legatto-breakglass", "shorten", "--minutes", minutes, "--reason", "verify.sh",
                             "--actor", actor, "--json")

    def test_shorten_moves_the_end_and_the_kernel_timeout(self) -> None:
        out_enable = json.loads(self.enable(hours="2").stdout)
        self.now = "2026-11-21T10:10:00Z"
        proc = self.shorten("3")
        self.assert_ok(proc)
        out = json.loads(proc.stdout)
        self.assertEqual((out["changed"], out["expires_at_before"], out["expires_at"], out["window_seconds"]),
                         (True, "2026-11-21T12:00:00Z", "2026-11-21T10:13:00Z", 180))
        state = self.read("var/lib/legatto/breakglass/state.json")
        self.assertEqual((state["active"], state["expires_at"]), (True, "2026-11-21T10:13:00Z"))
        self.assertEqual(self.sets()["bg4"], {"100.64.0.4": 180})
        self.assertEqual(self.sets()["bg6"], {"fd7a:115c:a1e0::4": 180})
        self.assertEqual(self.read("var/lib/legatto/status/breakglass.json")["expires_at"], "2026-11-21T10:13:00Z")
        entry = self.audit_entries()[-1]
        self.assertEqual(entry["event"], "breakglass.shorten")
        self.assertEqual(entry["params"], {"window_id": out_enable["window_id"], "minutes": 3, "reason": "verify.sh",
                                           "expires_at_before": "2026-11-21T12:00:00Z",
                                           "expires_at": "2026-11-21T10:13:00Z"})
        self.assertEqual(self.loaded_variant(), "breakglass")  # still open, no session cut
        self.now = "2026-11-21T10:12:59Z"
        self.assertEqual(json.loads(self.run_tool("legatto-breakglass", "reconcile", "--json").stdout)["action"],
                         "sets")
        self.now = "2026-11-21T10:13:00Z"
        proc = self.run_tool("legatto-breakglass", "reconcile", "--json")
        self.assert_ok(proc)
        self.assertEqual(json.loads(proc.stdout)["action"], "expired")
        self.assertEqual(self.sets()["bg4"], {})
        self.assertEqual(self.loaded_variant(), "normal")
        self.assertEqual(self.events()[-1], "breakglass.expire")
        self.assert_ok(self.run_tool("legatto-audit", "verify"))

    def test_shorten_never_extends(self) -> None:
        self.assert_ok(self.enable(hours="1"))
        self.now = "2026-11-21T10:58:00Z"
        events = self.events()
        proc = self.shorten("5")
        self.assert_ok(proc)
        out = json.loads(proc.stdout)
        self.assertEqual((out["changed"], out["expires_at"], out["window_seconds"]),
                         (False, "2026-11-21T11:00:00Z", 120))
        self.assertEqual(self.read("var/lib/legatto/breakglass/state.json")["expires_at"], "2026-11-21T11:00:00Z")
        self.assertEqual(self.events(), events)  # nothing changed, nothing audited

    def test_shorten_arguments_and_state(self) -> None:
        self.assertEqual(self.shorten("3").returncode, 20)  # no window
        self.assert_ok(self.enable())
        for minutes in ("1", "0", "-5", "481", "x"):
            with self.subTest(minutes=minutes):
                self.assertEqual(self.shorten(minutes).returncode, 2)
        self.assertEqual(self.shorten("3", actor="{}").returncode, 2)
        proc = self.run_tool("legatto-breakglass", "shorten", "--minutes", "3", "--reason", "linia\ndruga",
                             "--actor", OFFICE)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(self.read("var/lib/legatto/breakglass/state.json")["expires_at"], "2026-11-21T11:00:00Z")
        self.now = "2026-11-21T11:00:00Z"  # expired but not yet reconciled
        self.assertEqual(self.shorten("3").returncode, 20)

    def test_failed_assertion_exit_21_and_error_entry(self) -> None:
        self.set_fake({"netmap_broken": True})
        proc = self.run_tool("legatto-breakglass", "enable", "--hours", "1", "--reason", REASON, "--actor", OFFICE,
                             "--json", timeout=200)
        self.assertEqual(proc.returncode, 21)
        self.assertFalse(json.loads(proc.stdout)["policy_asserted"])
        self.assertIn("breakglass.error", self.events())
        self.assertTrue(self.read("var/lib/legatto/breakglass/state.json")["active"])
        self.assertFalse(self.read("var/lib/legatto/status/breakglass.json")["ok"])

    def test_policy_rejected_closes_window(self) -> None:
        self.set_fake({"policy_check_fail": True})
        proc = self.enable()
        self.assertEqual(proc.returncode, 21)
        self.assertFalse(self.read("var/lib/legatto/breakglass/state.json")["active"])
        self.assertEqual(self.sets()["bg4"], {})
        events = self.events()
        self.assertIn("breakglass.enable", events)
        self.assertIn("breakglass.error", events)
        self.assertIn("breakglass.disable", events)

    def test_audit_failure_blocks_enable(self) -> None:
        with open(self.path("var/log/legatto/audit.log"), "w") as fh:
            fh.write('{"torn":')
        self.assertEqual(self.enable().returncode, 1)
        self.assertFalse(os.path.exists(self.path("var/lib/legatto/breakglass/state.json")))
        self.assertEqual(self.fake().get("sets", {}).get("bg4", {}), {})

    def test_drift_repaired(self) -> None:
        shutil.copy(self.path("etc/legatto/policy/breakglass.hujson"), self.path("etc/headscale/policy.hujson"))
        self.set_fake({"loaded_policy": self.text("etc/legatto/policy/breakglass.hujson"),
                       "sets": {"vendor4": {}, "vendor6": {}, "bg4": {"100.64.0.4": 600}, "bg6": {}}})
        proc = self.run_tool("legatto-breakglass", "reconcile", "--json")
        self.assert_ok(proc)
        self.assertEqual(len(json.loads(proc.stdout)["drift"]), 2)
        self.assertEqual(self.loaded_variant(), "normal")
        self.assertEqual(self.sets()["bg4"], {})
        self.assertIn("breakglass.drift", self.events())

    def test_new_vendor_node_joins_open_window(self) -> None:
        self.assert_ok(self.enable())
        nodes = self.fake()["nodes"]
        nodes.append({"id": 5, "name": "n5", "given_name": "n5", "user": {"id": "2", "name": "v-jan"},
                      "ip_addresses": ["100.64.0.5", "fd7a:115c:a1e0::5"], "tags": [], "online": True})
        self.set_fake({"nodes": nodes})
        self.now = "2026-11-21T10:10:00Z"
        self.assert_ok(self.run_tool("legatto-breakglass", "reconcile"))
        self.assertEqual(self.sets()["bg4"], {"100.64.0.4": 3000, "100.64.0.5": 3000})

    def test_admin_http_counted_for_vendor_only(self) -> None:
        self.assert_ok(self.enable())
        access = [
            {"logger": "http.log.access.admin", "status": 200,
             "request": {"client_ip": "fd7a:115c:a1e0::4", "uri": "/aktualizacje?x=1", "host": "admin.app.x"}},
            {"logger": "http.log.access.admin", "status": 200,
             "request": {"client_ip": "fd7a:115c:a1e0::3", "uri": "/", "host": "admin.app.x"}},
            {"logger": "http.log.access.crm", "status": 200,
             "request": {"client_ip": "100.64.0.4", "uri": "/", "host": "app.x"}},
        ]
        self.set_fake({"journal": [{"MESSAGE": json.dumps(a)} for a in access]})
        self.assert_ok(self.run_tool("legatto-breakglass", "reconcile"))
        entry = [e for e in self.audit_entries() if e["event"] == "admin.http"][0]
        self.assertEqual(entry["params"]["requests"], 1)
        self.assertEqual(entry["params"]["paths"], {"/aktualizacje": 1})

    def test_bootstrap_actor_window(self) -> None:
        actor = json.dumps({"kind": "bootstrap", "id": "v-jan"})
        proc = self.enable(hours="6", reason="bootstrap: pierwsza instalacja", actor=actor)
        self.assert_ok(proc)
        self.assertEqual(self.sets()["bg4"], {"100.64.0.4": 21600})


if __name__ == "__main__":
    unittest.main()
