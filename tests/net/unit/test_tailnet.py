"""legatto-tailnet with a fake headscale: enroll, revoke, staff-set, vendors, nodes."""

from __future__ import annotations

import json
import os
import unittest

from harness import ToolTestCase

OFFICE = json.dumps({"kind": "office-admin", "id": "szef-biura"})
ANSIBLE = json.dumps({"kind": "vendor", "id": "v-jan"})


class TailnetTest(ToolTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.assert_ok(self.run_tool("legatto-policy", "apply", "--timeout", "5"))

    def staff_file(self, staff: list) -> str:
        path = os.path.join(self.tmp, "staff-request.json")
        with open(path, "w") as fh:
            json.dump({"v": 1, "staff": staff}, fh)
        return path

    def test_enroll_staff(self) -> None:
        proc = self.run_tool("legatto-tailnet", "enroll", "--kind", "staff", "--login", "anna", "--actor", OFFICE,
                             "--json")
        self.assert_ok(proc)
        out = json.loads(proc.stdout)
        self.assertEqual((out["kind"], out["user"], out["tags"]), ("staff", "anna", []))
        self.assertTrue(out["key"].startswith("fakekey"))
        self.assertEqual(out["login_server"], "https://vpn.example.test")
        self.assertRegex(out["expires_at"], r"Z$")
        create = [c for c in self.calls("headscale") if c["argv"][:2] == ["preauthkeys", "create"]][0]["argv"]
        self.assertIn("30m", create)
        self.assertEqual(create[create.index("--user") + 1], "1")
        entry = self.audit_entries()[-1]
        self.assertEqual(entry["event"], "device.enroll")
        self.assertNotIn(out["key"], json.dumps(entry))

    def test_enroll_unknown_staff_exit_24(self) -> None:
        proc = self.run_tool("legatto-tailnet", "enroll", "--kind", "staff", "--login", "ewa", "--actor", OFFICE)
        self.assertEqual(proc.returncode, 24)

    def test_enroll_office_device(self) -> None:
        proc = self.run_tool("legatto-tailnet", "enroll", "--kind", "office-device", "--actor", OFFICE, "--json")
        self.assert_ok(proc)
        out = json.loads(proc.stdout)
        self.assertEqual((out["user"], out["tags"]), (None, ["tag:office-device"]))
        create = [c for c in self.calls("headscale") if c["argv"][:2] == ["preauthkeys", "create"]][0]["argv"]
        self.assertIn("tag:office-device", create)

    def test_revoke(self) -> None:
        self.assertEqual(self.run_tool("legatto-tailnet", "revoke", "--node-id", "1", "--actor", OFFICE).returncode,
                         2)
        self.assertEqual(self.run_tool("legatto-tailnet", "revoke", "--node-id", "77", "--actor", OFFICE).returncode,
                         24)
        proc = self.run_tool("legatto-tailnet", "revoke", "--node-id", "2", "--actor", OFFICE, "--json")
        self.assert_ok(proc)
        self.assertEqual(json.loads(proc.stdout)["node_id"], "2")
        self.assertNotIn(2, [n["id"] for n in self.fake()["nodes"]])
        self.assertIn(["-D", "-s", "100.64.0.2"], self.fake()["conntrack"])
        self.assertEqual(self.events()[-1], "device.revoke")

    def test_staff_set_adds_and_removes(self) -> None:
        proc = self.run_tool("legatto-tailnet", "staff-set", "--file", self.staff_file(["ewa", "jan.kowalski"]),
                             "--actor", OFFICE, "--json")
        self.assert_ok(proc)
        out = json.loads(proc.stdout)
        self.assertEqual((out["added"], out["removed"], out["nodes_deleted"]),
                         (["ewa", "jan.kowalski"], ["anna"], ["2"]))
        users = [u["name"] for u in self.fake()["users"]]
        self.assertEqual(sorted(users), ["ewa", "jan.kowalski", "v-jan"])
        self.assertEqual(self.read("var/lib/legatto/tailnet/staff.json")["staff"], ["ewa", "jan.kowalski"])
        installed = self.text("etc/headscale/policy.hujson")
        self.assertIn('"group:staff": ["ewa@", "jan.kowalski@"]', installed)
        self.assertIn("device.staff_set", self.events())

    def test_staff_set_rejects_bad_input(self) -> None:
        for staff in (["Anna"], ["v-jan"], ["ok", 3]):
            with self.subTest(staff=staff):
                proc = self.run_tool("legatto-tailnet", "staff-set", "--file", self.staff_file(staff),
                                     "--actor", OFFICE)
                self.assertEqual(proc.returncode, 2)
        proc = self.run_tool("legatto-tailnet", "staff-set", "--file", self.staff_file(["ewa"]))
        self.assertEqual(proc.returncode, 2)  # --actor is mandatory

    def test_vendors_set_and_key(self) -> None:
        path = os.path.join(self.tmp, "vendors.json")
        with open(path, "w") as fh:
            json.dump({"v": 1, "vendors": ["v-ola"]}, fh)
        proc = self.run_tool("legatto-tailnet", "vendors-set", "--file", path, "--actor", ANSIBLE, "--json")
        self.assert_ok(proc)
        out = json.loads(proc.stdout)
        self.assertEqual((out["created"], out["removed"], out["nodes_deleted"]), (["v-ola"], ["v-jan"], ["4"]))
        key = self.run_tool("legatto-tailnet", "vendor-key", "--login", "v-ola", "--actor", ANSIBLE, "--json")
        self.assert_ok(key)
        self.assertEqual(json.loads(key.stdout)["kind"], "vendor")
        self.assertEqual(self.run_tool("legatto-tailnet", "vendor-key", "--login", "v-jan", "--actor", ANSIBLE)
                         .returncode, 24)

    def test_nodes_format(self) -> None:
        proc = self.run_tool("legatto-tailnet", "nodes", "--json")
        self.assert_ok(proc)
        nodes = json.loads(proc.stdout)["nodes"]
        self.assertEqual([n["id"] for n in nodes], ["1", "2", "3", "4"])
        self.assertEqual(set(nodes[0]), {"id", "name", "user", "tags", "ip4", "ip6", "online", "last_seen",
                                         "expiry"})
        self.assertEqual((nodes[2]["ip4"], nodes[2]["ip6"]), ("100.64.0.3", "fd7a:115c:a1e0::3"))
        self.assertIsNone(nodes[1]["expiry"])


if __name__ == "__main__":
    unittest.main()
