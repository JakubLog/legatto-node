"""Site publisher: zero-address guard ("strażnik zero adresu") and the
claim -> snapshot -> build -> guard -> deploy -> finish pipeline."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from fixture import OFFICE_ENV, Harness

from legatto_publicsite import guard

JOB = "0f8fad5b-d9cb-469f-a165-70867728950e"


def site(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp(prefix="legatto-dist-"))
    for name, content in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    return root


CLEAN = {
    "index.html": "<!doctype html><title>Jan Kowalski</title><a href=\"https://posel-kowalski.pl/kontakt\">Kontakt</a>"
                  "<p>Biuro: ul. Długa 1, tel. 22 100 64 00, 100.64 tys. zł; wersja 100.63.255.255</p>",
    "assets/app.js": "fetch('/api/submit',{method:'POST'});const w='webapp.posel-kowalski.pl';",
    "data/form-key.json": "{\"v\":1,\"kid\":\"0123456789abcdef\"}",
    "_headers": "/*\n  Content-Security-Policy: default-src 'self'; connect-src 'self'\n",
}


class GuardTest(unittest.TestCase):
    def rules(self, extra: dict[str, str]) -> set[str]:
        return {f.rule for f in guard.scan(site({**CLEAN, **extra}), OFFICE_ENV)}

    def test_clean_site_passes(self) -> None:
        self.assertEqual(guard.scan(site(CLEAN), OFFICE_ENV), [])

    def test_every_office_address_is_caught(self) -> None:
        leaks = {
            "host-vpn": "connect to vpn.posel-kowalski.pl",
            "host-crm": "<a href=\"https://app.posel-kowalski.pl/biuro\">",
            "host-admin": "ADMIN.APP.POSEL-KOWALSKI.PL",
            "host-studio": "studio.app.posel-kowalski.pl",
            "host-magicdns": "srv.tn.posel-kowalski.pl",
            "ip-public": "origin 198.51.100.23:443",
            "ip-tailnet4": "http://100.64.0.1/",
            "ip-tailnet6": "[fd7a:115c:a1e0:0000:0000:0000:0000:0001]",
            "tailnet-v4": "peer 100.101.102.103",
            "tailnet-v6": "fd7a:115c:a1e0:ab12::9",
            "supabase-rest": "fetch('/rest/v1/cases')",
            "supabase-name": "createClient from @supabase/supabase-js",
            "jwt": "apikey " + ".".join(["eyJ" + "hbGciOiJub25lIn0", "eyJ" + "yb2xlIjoiYW5vbiJ9", "c2lnbmF0dXJl"]),  # built at runtime: no JWT literal in the repo
        }
        for rule, text in leaks.items():
            with self.subTest(rule=rule):
                self.assertIn(rule, self.rules({"assets/leak.js": text}))

    def test_findings_never_echo_the_matched_text(self) -> None:
        findings = guard.scan(site({**CLEAN, "x.js": "app.posel-kowalski.pl"}), OFFICE_ENV)
        self.assertNotIn("posel-kowalski", json.dumps([f.__dict__ for f in findings]))

    def test_functions_and_symlinks_are_refused(self) -> None:
        self.assertIn("pages-functions", self.rules({"_worker.js": "export default {}"}))
        self.assertIn("pages-functions", self.rules({"functions/api.js": "x"}))
        root = site(CLEAN)
        os.symlink("/etc/hosts", root / "hosts.txt")
        self.assertIn("symlink", {f.rule for f in guard.scan(root, OFFICE_ENV)})

    def test_leak_in_a_file_name_is_caught(self) -> None:
        self.assertIn("host-crm", self.rules({"app.posel-kowalski.pl.html": "x"}))


class PublishTest(Harness):
    def run_publish(self) -> tuple[int, dict, str]:
        (self.state / "jobs.json").write_text(json.dumps([JOB]))
        return self.tool("legatto-site-publish", "run")

    def with_worker_bundle(self) -> None:
        self.install_release("1.4.0")

    def calls(self) -> list[dict]:
        return self.jsonl("docker.jsonl")

    def test_publish_pipeline_separates_database_build_and_cloudflare(self) -> None:
        self.with_worker_bundle()
        code, out, err = self.run_publish()
        self.assertEqual(code, 0, err)
        self.assertEqual(out["deployment_id"], "pages-1")
        steps = {tuple(c["command"][:2]): c for c in self.calls()}
        claim = steps[("/app/server/site.mjs", "claim")]
        build = steps[("/app/server/site.mjs", "build")]
        deploy = steps[("/w/tools.mjs", "pages-deploy")]
        self.assertEqual(claim["network"], "legatto-int")
        self.assertIn("/run/credentials/legatto-db-publisher", claim["mounts"])
        self.assertNotIn("/run/credentials/legatto-cf-pages-token", claim["mounts"])
        self.assertEqual(build["network"], "none")
        self.assertFalse(any(dst.startswith("/run/credentials") for dst in build["mounts"]))
        deny = [build["command"][i + 1] for i, a in enumerate(build["command"]) if a == "--deny-host"]
        self.assertEqual(set(deny), {"vpn.posel-kowalski.pl", "app.posel-kowalski.pl", "admin.app.posel-kowalski.pl",
                                     "studio.app.posel-kowalski.pl", "tn.posel-kowalski.pl", "198.51.100.23",
                                     "100.64.0.1", "fd7a:115c:a1e0::1"})
        self.assertEqual(deploy["network"], "legatto-egress-publish")
        self.assertEqual(deploy["env"]["HTTPS_PROXY"], "http://egress-publish:4750")
        self.assertIn("/run/credentials/legatto-cf-pages-token", deploy["mounts"])
        self.assertNotIn("/run/credentials/legatto-db-publisher", deploy["mounts"])
        self.assertTrue(deploy["readonly"]["/work/dist"])
        self.assertIn("data/form-key.json", self.fake_json("cf.json")["pages_files"])
        self.assertEqual(self.fake_json("finished.json"), [["--job", JOB, "--status", "ok", "--deployment-id", "pages-1"]])
        status = self.status("publish")
        self.assertEqual((status["state"], status["deployment_id"], status["ok"]), ("ok", "pages-1", True))
        self.assertEqual([a["event"] for a in self.jsonl("audit.jsonl")], ["publish.deployed"])

    def test_guard_blocks_a_build_that_contains_an_office_address(self) -> None:
        self.with_worker_bundle()
        (self.state / "site_js.txt").write_text("const crm = 'https://app.posel-kowalski.pl/rest/v1/';")
        code, out, err = self.run_publish()
        self.assertEqual(code, 20, err)
        self.assertEqual(out["error"], "zero_address")
        self.assertFalse(any(c["command"][:2] == ["/w/tools.mjs", "pages-deploy"] for c in self.calls()))
        self.assertIsNone(self.fake_json("cf.json", {"pages": None})["pages"])
        self.assertEqual(self.fake_json("finished.json"), [["--job", JOB, "--status", "failed", "--error", "zero_address"]])
        self.assertEqual(self.status("publish")["state"], "failed")
        audit = self.jsonl("audit.jsonl")
        self.assertEqual(audit[0]["event"], "publish.failed")
        self.assertNotIn("posel-kowalski", err + json.dumps(audit))

    def test_no_job_runs_the_drift_check(self) -> None:
        self.with_worker_bundle()
        code, out, err = self.run_publish()
        self.assertEqual(code, 0, err)
        cf = self.fake_json("cf.json")
        cf["pages"] = "pages-foreign"  # someone deployed from outside the server
        (self.state / "cf.json").write_text(json.dumps(cf))
        code, out, err = self.tool("legatto-site-publish", "run")
        self.assertEqual(code, 0, err)
        self.assertEqual(out["drift"]["pages"], "drift")
        self.assertIn("publish.drift", [a["event"] for a in self.jsonl("audit.jsonl")])
        self.assertEqual(self.status("publish")["state"], "drift")


if __name__ == "__main__":
    unittest.main()
