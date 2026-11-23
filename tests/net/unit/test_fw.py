"""legatto-fw-apply/confirm/rollback with a fake nft and systemd-run."""

from __future__ import annotations

import json
import os
import unittest

from harness import ToolTestCase

RULES = "table inet legatto\ndelete table inet legatto\ntable inet legatto {\n}\n"


class FirewallToolTest(ToolTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.new = os.path.join(self.tmp, "nftables.conf.new")
        with open(self.new, "w") as fh:
            fh.write(RULES)
        self.set_fake({"loaded": "table inet legatto {\n  chain input {\n  }\n}\n"})

    def pending(self) -> str:
        return self.path("run/legatto/fw/pending.json")

    def test_apply_arms_rollback_and_loads(self) -> None:
        proc = self.run_tool("legatto-fw-apply", self.new, "--json")
        self.assert_ok(proc)
        run = self.calls("systemd-run")[0]["argv"]
        self.assertIn("--unit=legatto-fw-rollback", run)
        self.assertIn("--on-active=120", run)
        self.assertTrue(run[-1].endswith("legatto-fw-rollback"))
        self.assertEqual(self.fake()["loaded"], RULES)
        self.assertTrue(os.path.exists(self.pending()))
        rollback = self.text("run/legatto/fw/rollback.nft")
        self.assertTrue(rollback.startswith("table inet legatto\ndelete table inet legatto\n"))
        self.assertIn("chain input", rollback)
        # sets refilled after the load
        self.assertTrue(any(c["argv"] == ["-f", "-"] for c in self.calls("nft")))
        self.assertFalse(os.path.exists(self.path("etc/nftables.conf")))
        self.assertIn("fw.apply", self.events())

    def test_confirm_installs_and_disarms(self) -> None:
        self.assert_ok(self.run_tool("legatto-fw-apply", self.new))
        self.assert_ok(self.run_tool("legatto-fw-confirm", self.new))
        self.assertEqual(self.text("etc/nftables.conf"), RULES)
        self.assertFalse(os.path.exists(self.pending()))
        self.assertIn(["stop", "legatto-fw-rollback.timer"], [c["argv"] for c in self.calls("systemctl")])
        self.assertEqual(self.run_tool("legatto-fw-rollback", "--json").stdout.strip(),
                         json.dumps({"reason": "nothing pending", "rolled_back": False}, sort_keys=True))
        self.assertEqual(self.events()[-1], "fw.confirm")

    def test_rollback_restores_previous_table(self) -> None:
        self.assert_ok(self.run_tool("legatto-fw-apply", self.new))
        proc = self.run_tool("legatto-fw-rollback", "--json")
        self.assert_ok(proc)
        self.assertTrue(json.loads(proc.stdout)["rolled_back"])
        self.assertIn("chain input", self.fake()["loaded"])
        self.assertFalse(os.path.exists(self.pending()))
        self.assertEqual(self.run_tool("legatto-fw-confirm", self.new).returncode, 4)
        self.assertEqual(self.events()[-1], "fw.rollback")

    def test_confirm_other_file_refused(self) -> None:
        self.assert_ok(self.run_tool("legatto-fw-apply", self.new))
        other = os.path.join(self.tmp, "other.conf")
        with open(other, "w") as fh:
            fh.write(RULES + "# changed\n")
        self.assertEqual(self.run_tool("legatto-fw-confirm", other).returncode, 4)
        self.assertFalse(os.path.exists(self.path("etc/nftables.conf")))

    def test_nft_check_failure_exit_25(self) -> None:
        self.set_fake({"nft_check_fail": True})
        self.assertEqual(self.run_tool("legatto-fw-apply", self.new).returncode, 25)
        self.assertEqual(self.calls("systemd-run"), [])
        self.assertFalse(os.path.exists(self.pending()))

    def test_usage(self) -> None:
        self.assertEqual(self.run_tool("legatto-fw-apply").returncode, 2)
        self.assertEqual(self.run_tool("legatto-fw-rollback", "x").returncode, 2)


if __name__ == "__main__":
    unittest.main()
