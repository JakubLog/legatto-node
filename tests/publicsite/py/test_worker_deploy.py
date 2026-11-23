"""legatto-worker-deploy: bundle verification against the manifest, first
deployment with pending secrets (then shredded), idempotence, exit 60."""

from __future__ import annotations

import json
import os

from fixture import Harness

from legatto_publicsite import worker_deploy


class WorkerDeployTest(Harness):
    def setUp(self) -> None:
        super().setUp()
        # As left by legatto-cf-bootstrap: pending Worker secrets + signer kid.
        os.environ["LEGATTO_ROOT"] = str(self.root)
        try:
            self.signer_kid = worker_deploy.stage_worker_secrets("turnstile-secret-value")
        finally:
            del os.environ["LEGATTO_ROOT"]

    def deploy(self, version: str, *extra: str) -> tuple[int, dict, str]:
        release = self.root / "opt/legatto/releases" / version
        return self.tool("legatto-worker-deploy", "--release-dir", str(release), "--selftest-timeout", "5", *extra)

    def test_first_deploy_uses_and_then_shreds_the_pending_secrets(self) -> None:
        self.install_release("1.4.0")
        pending = self.root / "var/lib/legatto/worker/secrets-pending.json"
        self.assertTrue(pending.exists())
        self.assertTrue((self.root / f"etc/legatto/intake/signers.d/{self.signer_kid}.pub").exists())
        code, out, err = self.deploy("1.4.0", "--no-selftest")
        self.assertEqual(code, 0, err)
        self.assertTrue(out["changed"])
        self.assertFalse(pending.exists(), "private Worker keys must not stay on disk")
        cf = self.fake_json("cf.json")
        self.assertEqual(cf["deploys"], [{"release": "1.4.0", "secrets": True}])
        call = [c for c in self.jsonl("docker.jsonl") if c["command"][:2] == ["/w/tools.mjs", "worker-deploy"]][0]
        self.assertEqual(call["network"], "legatto-egress-publish")
        self.assertTrue(call["readonly"]["/cfg/secrets.json"])
        self.assertTrue(call["readonly"]["/w"])
        config = json.loads((self.root / "var/lib/legatto/worker/deploy.json").read_text())
        self.assertEqual(config["vars"]["SITE_ORIGIN"], "https://posel-kowalski.pl")
        self.assertEqual(config["expected_signer_kid"], self.signer_kid)
        self.assertNotIn("turnstile-secret-value", json.dumps(config) + json.dumps(out) + err)
        self.assertEqual(list((self.root / "run/legatto/credentials").iterdir()), [])
        status = self.status("worker")
        self.assertEqual((status["state"], status["release"], status["ok"]), ("ok", "1.4.0", True))
        self.assertEqual(self.jsonl("audit.jsonl")[-1]["event"], "publish.worker_deployed")
        # Same release again: no-op.
        code, out, _ = self.deploy("1.4.0", "--no-selftest")
        self.assertEqual((code, out["changed"]), (0, False))

    def test_later_release_keeps_secrets_and_selftest_failure_rolls_back(self) -> None:
        self.install_release("1.4.0")
        self.assertEqual(self.deploy("1.4.0", "--no-selftest")[0], 0)
        self.install_release("1.5.0", worker_js=b"export default { v: 2 }")
        self.flag("selftest_lost")  # Worker accepts the self-test but nothing reaches intake
        code, out, err = self.deploy("1.5.0")
        self.assertEqual(code, 60, err)
        cf = self.fake_json("cf.json")
        self.assertEqual(cf["deploys"][-1], {"release": "1.5.0", "secrets": False})
        self.assertEqual(cf["rollbacks"], 1)
        self.assertEqual(cf["worker_versions"][0]["version_id"], f"{1:032x}")
        self.assertEqual(self.status("worker")["state"], "failed")
        self.assertEqual(self.jsonl("audit.jsonl")[-1]["event"], "publish.worker_failed")

    def test_selftest_travels_through_the_intake_path(self) -> None:
        self.install_release("1.4.0")
        code, out, err = self.deploy("1.4.0")
        self.assertEqual(code, 0, err)
        # The fake Worker signed the self-test with the key uploaded as its secret;
        # the host gate accepted it against signers.d and the processor reported it.
        self.assertEqual(self.fake_json("pending_markers.json"), [])
        units = [c for c in self.jsonl("systemctl.jsonl") if c[:2] == ["start", "legatto-intake-fetch.service"]]
        self.assertGreaterEqual(len(units), 1)
        self.assertEqual(self.status("intake")["quarantined"], 0)

    def test_tampered_bundle_is_refused(self) -> None:
        release = self.install_release("1.4.0")
        archive = release / "artifacts/worker.tar.gz"
        archive.write_bytes(archive.read_bytes() + b"\0")
        code, out, err = self.deploy("1.4.0", "--no-selftest")
        self.assertEqual(code, 1)
        self.assertIn("does not match the manifest", err)
        self.assertIsNone(self.fake_json("cf.json"))

    def test_without_cloudflare_bootstrap_exit_4(self) -> None:
        self.install_release("1.4.0")
        (self.root / "etc/legatto/publicsite/cloudflare.json").unlink()
        self.assertEqual(self.deploy("1.4.0")[0], 4)

    def test_release_without_worker_bundle_is_a_noop(self) -> None:
        code, out, _ = self.tool("legatto-worker-deploy", "--release-dir", str(self.root / "opt/legatto/releases/1.4.0"))
        self.assertEqual((code, out["changed"]), (0, False))
