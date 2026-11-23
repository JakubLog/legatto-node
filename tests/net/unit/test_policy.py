"""legatto-policy: render on golden inputs, structural guards, apply + assert (with fakes)."""

from __future__ import annotations

import json
import os
import shutil
import unittest

from harness import REPO, ToolTestCase

GOLDEN = os.path.join(REPO, "tests", "net", "golden")


class PolicyRenderTest(ToolTestCase):
    def render(self, *extra: str) -> tuple:
        out = os.path.join(self.tmp, "out")
        os.makedirs(out, exist_ok=True)
        proc = self.run_tool("legatto-policy", "render", "--json", "--out", out, *extra)
        return proc, out

    def test_golden_files(self) -> None:
        """Golden inputs: staff with a dotted login, two vendors, an active window."""
        self.write("var/lib/legatto/tailnet/staff.json", {"v": 1, "staff": ["jan.kowalski", "anna"]})
        static = self.read("etc/legatto/policy/static.json")
        static["vendors"] = ["v-ola", "v-jan"]
        self.write("etc/legatto/policy/static.json", static)
        self.write("var/lib/legatto/breakglass/state.json", {
            "v": 1, "active": True, "window_id": "20261121T100000Z-a1b2c3",
            "started_at": "2026-11-21T10:00:00Z", "expires_at": "2026-11-21T14:00:00Z"})
        self.now = "2026-11-21T11:00:00Z"
        proc, out = self.render()
        self.assert_ok(proc)
        for variant in ("normal", "breakglass"):
            with self.subTest(variant=variant):
                with open(os.path.join(out, f"{variant}.hujson")) as fh:
                    rendered = fh.read()
                with open(os.path.join(GOLDEN, f"{variant}.hujson")) as fh:
                    self.assertEqual(rendered, fh.read())

    def test_empty_staff_and_vendors_render(self) -> None:
        self.write("var/lib/legatto/tailnet/staff.json", {"v": 1, "staff": []})
        static = self.read("etc/legatto/policy/static.json")
        static["vendors"] = []
        self.write("etc/legatto/policy/static.json", static)
        proc, out = self.render()
        self.assert_ok(proc)
        self.assertIn('"group:staff": []', self.text(os.path.join(out, "normal.hujson")))

    def test_missing_staff_file_is_empty_staff(self) -> None:
        os.unlink(self.path("var/lib/legatto/tailnet/staff.json"))
        self.assert_ok(self.render()[0])

    def test_invalid_inputs_rejected(self) -> None:
        cases = {
            "staff login": ("var/lib/legatto/tailnet/staff.json", {"v": 1, "staff": ["Anna Kowalska"]}),
            "staff vendor prefix": ("var/lib/legatto/tailnet/staff.json", {"v": 1, "staff": ["v-jan"]}),
            "ts_ip4 outside tailnet": ("etc/legatto/policy/static.json", dict(
                self.read("etc/legatto/policy/static.json"), ts_ip4="10.0.0.1")),
            "vendor login": ("etc/legatto/policy/static.json", dict(
                self.read("etc/legatto/policy/static.json"), vendors=["jan"])),
        }
        for label, (rel, doc) in cases.items():
            with self.subTest(case=label):
                backup = self.read(rel)
                self.write(rel, doc)
                self.assertEqual(self.render()[0].returncode, 4)
                self.write(rel, backup)

    def test_template_guards(self) -> None:
        template = self.path("etc/legatto/policy/acl.hujson.j2")
        original = self.text(template)
        cases = {
            "server as source": original.replace('{"src": [{{ groups.staff | tojson }}]',
                                                 '{"src": ["tag:server"]', 1),
            "wildcard": original.replace('"dst": ["crm"]', '"dst": ["*"]', 1),
            "vendor in normal": original.replace("{%- if breakglass %}", "{%- if true %}", 1),
            "tests block": original.replace('"ssh": [],', '"ssh": [], "tests": [],', 1),
            "undefined variable": original.replace("ts_ip4 ~", "ts_ipv4 ~", 1),
        }
        for label, text in cases.items():
            with self.subTest(case=label):
                self.assertNotEqual(text, original)
                with open(template, "w") as fh:
                    fh.write(text)
                proc = self.render()[0]
                self.assertNotEqual(proc.returncode, 0, proc.stderr)
        with open(template, "w") as fh:
            fh.write(original)
        self.assert_ok(self.render()[0])

    def test_sandbox_blocks_attribute_escape(self) -> None:
        with open(self.path("etc/legatto/policy/acl.hujson.j2"), "w") as fh:
            fh.write("{{ ''.__class__.__mro__[1].__subclasses__() }}")
        self.assertNotEqual(self.render()[0].returncode, 0)


class PolicyApplyTest(ToolTestCase):
    def test_apply_normal_installs_and_asserts(self) -> None:
        proc = self.run_tool("legatto-policy", "apply", "--json", "--timeout", "5")
        self.assert_ok(proc)
        result = json.loads(proc.stdout)
        self.assertEqual((result["variant"], result["changed"], result["asserted"]), ("normal", True, True))
        installed = self.text("etc/headscale/policy.hujson")
        self.assertEqual(installed, self.text("etc/legatto/policy/normal.hujson"))
        self.assertEqual(self.fake()["reloads"], 1)
        again = json.loads(self.run_tool("legatto-policy", "apply", "--json", "--timeout", "5").stdout)
        self.assertFalse(again["changed"])
        self.assertEqual(self.fake()["reloads"], 1)

    def test_check_rejection_exit_22_keeps_old_policy(self) -> None:
        self.assert_ok(self.run_tool("legatto-policy", "apply", "--timeout", "5"))
        before = self.text("etc/headscale/policy.hujson")
        self.write("var/lib/legatto/tailnet/staff.json", {"v": 1, "staff": ["anna", "ewa"]})
        self.set_fake({"policy_check_fail": True})
        self.assertEqual(self.run_tool("legatto-policy", "apply", "--timeout", "5").returncode, 22)
        self.assertEqual(self.text("etc/headscale/policy.hujson"), before)

    def test_assert_detects_vendor_access_in_normal(self) -> None:
        self.assert_ok(self.run_tool("legatto-policy", "apply", "--timeout", "5"))
        shutil.copy(self.path("etc/legatto/policy/breakglass.hujson"), self.path("etc/headscale/policy.hujson"))
        self.run_tool("legatto-policy", "render")  # no effect on the loaded policy
        self.set_fake({"loaded_policy": self.text("etc/legatto/policy/breakglass.hujson")})
        proc = self.run_tool("legatto-policy", "assert", "--expect", "normal", "--timeout", "1")
        self.assertEqual(proc.returncode, 23)
        self.assertIn("vendor", proc.stderr)
        self.assert_ok(self.run_tool("legatto-policy", "assert", "--expect", "breakglass", "--timeout", "1"))

    def test_assert_detects_missing_vendor_rule_in_breakglass(self) -> None:
        self.assert_ok(self.run_tool("legatto-policy", "apply", "--timeout", "5"))
        proc = self.run_tool("legatto-policy", "assert", "--expect", "breakglass", "--timeout", "1")
        self.assertEqual(proc.returncode, 23)

    def test_assert_detects_alias_family_expansion(self) -> None:
        """Regression (headscale #2180): crm must not expand to the server's IPv6."""
        self.assert_ok(self.run_tool("legatto-policy", "apply", "--timeout", "5"))
        policy = self.text("etc/headscale/policy.hujson")
        self.set_fake({"loaded_policy": policy.replace('"crm": "100.64.0.1/32"', '"crm": "fd7a:115c:a1e0::1/128"')})
        proc = self.run_tool("legatto-policy", "assert", "--expect", "normal", "--timeout", "1")
        self.assertEqual(proc.returncode, 23)
        self.assertIn("staff", proc.stderr)

    def test_assert_accepts_aggregated_sources(self) -> None:
        """Headscale 0.29.7 merges node addresses into prefixes (seen on a real server)."""
        rule = {"SrcIPs": ["100.64.0.2/31", "fd7a:115c:a1e0::2/127"],
                "DstPorts": [{"IP": "100.64.0.1", "Ports": {"First": 443, "Last": 443}}]}
        self.assert_ok(self.run_tool("legatto-policy", "apply", "--timeout", "5"))
        # 100.64.0.2 = staff, 100.64.0.3 = office device: both may reach crm
        self.set_fake({"netmap_override": [rule]})
        self.assert_ok(self.run_tool("legatto-policy", "assert", "--expect", "normal", "--timeout", "1"))
        # a prefix that also covers the vendor (100.64.0.4) is caught
        rule["SrcIPs"] = ["100.64.0.0/29"]
        self.set_fake({"netmap_override": [rule]})
        proc = self.run_tool("legatto-policy", "assert", "--expect", "normal", "--timeout", "1")
        self.assertEqual(proc.returncode, 23)
        self.assertIn("vendor", proc.stderr)
        # a wildcard-like source is caught even without a matching node
        rule["SrcIPs"] = ["100.64.0.0/10"]
        self.set_fake({"netmap_override": [rule]})
        self.assertEqual(self.run_tool("legatto-policy", "assert", "--expect", "normal", "--timeout", "1")
                         .returncode, 23)


if __name__ == "__main__":
    unittest.main()
