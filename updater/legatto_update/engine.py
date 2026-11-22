"""Commands of legatto-update (section 4.6)."""

import ipaddress
import json
import os
import shutil
import urllib.parse

from . import bundle, const, sshsig
from .apply import ApplyError, Appliers
from .audit import SYSTEM_ACTOR, Audit
from .chain import Chain, load_policy, rel_release
from .host import CommandError, fmt_ts, parse_ts, read_bytes, read_office_env, rmtree, semver_gt, sha256_file
from .source import DirSource, FetchError, HttpSource, SizeError
from .state import Store, TrustedClock
from .status import summary_candidates, write_status


class Precondition(Exception):
    pass


class Result:
    def __init__(self, code: int, key: str, message: str, data=None):
        self.code = code
        self.key = key
        self.message = message
        self.data = data or {}

    def as_json(self) -> dict:
        return {"ok": self.code == const.EXIT_OK, "code": self.key, "message": self.message, "data": self.data}


class Engine:
    def __init__(self, host, actor=None):
        self.host = host
        self.actor = actor or SYSTEM_ACTOR
        self.audit = Audit(host)
        self.store = Store(host)
        self.policy = None
        self.office_env = {}
        self.chain = None
        self.clock = None

    # --- setup / teardown ------------------------------------------------------------------
    def prepare(self) -> None:
        if not self.host.is_root():
            raise Precondition("legatto-update must run as root")
        try:
            self.policy = load_policy(self.host)
        except Exception as exc:  # PolicyError, OSError
            raise Precondition(str(exc)) from exc
        if not os.path.isfile(self.host.p(const.ALLOWED_SIGNERS)):
            raise Precondition("missing %s" % const.ALLOWED_SIGNERS)
        try:
            self.office_env = read_office_env(self.host.p(const.OFFICE_ENV))
        except (OSError, ValueError) as exc:
            raise Precondition("cannot read %s: %s" % (const.OFFICE_ENV, exc)) from exc
        self.store.load()
        self.clock = TrustedClock(self.host, self.store, self.policy["clock_jump_block_minutes"])
        trusted = self.clock.tick()
        self.chain = Chain(self.host, self.store, self.policy, self.office_env, self.audit, self.host.now(), trusted)
        if self.clock.jumped:
            self.chain.queue("clock_jump", {"delta_seconds": self.clock.jump_detail})

    def finish(self) -> None:
        self.store.save()
        write_status(self.host, self.store, self.policy, self.host.now())
        self.chain.flush_audit()

    def record(self, ev: dict, checked: bool) -> None:
        st = self.store.state
        flags = st["flags"]
        flags["stale"] = bool(ev["stale"])
        flags["rej"] = bool(ev["rejected"])
        st["sig"] = ev["sig"]
        st["candidates"] = summary_candidates(ev["candidates"])
        if checked:
            now = fmt_ts(self.host.now())
            last = st["last_check"]
            last["ts"] = now
            last["ok"] = bool(ev["index_ok"])
            if ev["index_ok"]:
                last["ok_ts"] = now
            if st.get("index"):
                last["index_sequence"] = st["index"]["sequence"]
                last["index_expires"] = st["index"]["expires"]

    def exit_for(self, ev: dict) -> int:
        if ev["sig"] == "bad" or ev["rejected"]:
            return const.EXIT_REJECTED
        if ev["stale"]:
            return const.EXIT_STALE
        if self.clock.jumped:
            return const.EXIT_CLOCK_JUMP
        return const.EXIT_OK

    def remote(self):
        """The update server, always through the host egress proxy. Only a test office
        (policy env=test) may use a mirror addressed by an IP literal (e.g. on the tailnet),
        which the proxy refuses; that mirror is reached directly."""
        url = self.policy["update_base_url"]
        proxy = self.host.proxy()
        host = urllib.parse.urlsplit(url).hostname or ""
        if self.policy["env"] == "test":
            try:
                ipaddress.ip_address(host)
                proxy = None
            except ValueError:
                pass
        return HttpSource(url, proxy)

    def refresh(self, remote, fetch: bool, bootstrap=False) -> dict:
        if fetch:
            try:
                self.chain.fetch(remote)
            except (FetchError, SizeError) as exc:
                st = self.store.state["last_check"]
                st["ts"] = fmt_ts(self.host.now())
                st["ok"] = False
                self.finish()
                raise
        ev = self.chain.evaluate(remote=remote, bootstrap=bootstrap)
        self.record(ev, checked=fetch)
        return ev

    # --- commands -----------------------------------------------------------------------------
    def cmd_fetch(self) -> Result:
        self.prepare()
        ev = self.refresh(self.remote(), fetch=True)
        self.finish()
        return Result(self.exit_for(ev), "fetched", "Pobrano i sprawdzono dokumenty wydań.", self._ev_data(ev))

    def cmd_verify(self, release=None) -> Result:
        self.prepare()
        ev = self.refresh(None, fetch=False)
        self.finish()
        if release is None:
            return Result(self.exit_for(ev), "verified", "Sprawdzono pobrane dokumenty.", self._ev_data(ev))
        for c in ev["candidates"]:
            if c["version"] == release:
                code = const.EXIT_REJECTED if c.get("alert") and not c["verify"]["ok"] else const.EXIT_OK
                return Result(code, c["verify"]["code"] or "verified",
                              "Wydanie %s: %s" % (release, c["state"]), {"candidate": _public(c)})
        return Result(const.EXIT_REJECTED, "not_candidate",
                      "Wydanie %s nie jest nowszym, zweryfikowanym wydaniem z indeksu." % release)

    def cmd_status(self) -> dict:
        path = os.path.join(self.host.p(const.STATUS_DIR), "update.json")
        data = read_bytes(path)
        if data is None:
            raise Precondition("no status yet")
        return json.loads(data.decode("utf-8"))

    def cmd_run(self) -> Result:
        self.prepare()
        ev = self.refresh(self.remote(), fetch=True)
        code = self.exit_for(ev)
        self._retry_worker()
        chosen = ev["chosen"]
        if chosen is None:
            self.finish()
            return Result(code, "waiting" if ev["candidates"] else "up_to_date", _waiting_message(ev),
                          self._ev_data(ev))
        if self.clock.blocked():
            self.finish()
            return Result(const.EXIT_CLOCK_JUMP, "clock_jump",
                          "Wykryto skok zegara; instalacja wstrzymana.", self._ev_data(ev))
        result = self.install(chosen, bootstrap=False)
        if result.code == const.EXIT_OK and code != const.EXIT_OK:
            result.code = code
        return result

    def cmd_bootstrap(self, bundle_dir: str) -> Result:
        self.prepare()
        if self.store.state.get("installed"):
            raise Precondition("a release is already installed; use run")
        if not os.path.isfile(os.path.join(bundle_dir, const.LAYOUT_INDEX)):
            raise Precondition("%s has no %s" % (bundle_dir, const.LAYOUT_INDEX))
        src = DirSource(bundle_dir)
        ev = self.refresh(src, fetch=True, bootstrap=True)
        chosen = ev["chosen"]
        if chosen is None:
            self.finish()
            code = self.exit_for(ev)
            return Result(code if code != const.EXIT_OK else const.EXIT_GATE, "nothing_installable",
                          "Paczka nie zawiera wydania, które można zainstalować na tym kanale.", self._ev_data(ev))
        return self.install(chosen, bootstrap=True)

    def _ev_data(self, ev: dict) -> dict:
        return {"sig": ev["sig"], "stale": ev["stale"], "errors": ev["sig_errors"][:10],
                "candidates": [{"version": c["version"], "state": c["state"], "code": c["verify"]["code"]}
                               for c in ev["candidates"]]}

    # --- install ------------------------------------------------------------------------------
    def install(self, cand: dict, bootstrap: bool) -> Result:
        manifest = cand["manifest"]
        version, sha = cand["version"], cand["manifest_sha256"]
        st = self.store.state
        previous = st.get("installed")
        app = Appliers(self.host, self.store, self.policy, self.office_env, self.actor)
        art_dir = self.chain.artifact_dir(version)
        need = 2 * sum(a["size"] for a in manifest["artifacts"])
        free = shutil.disk_usage(_existing_parent(self.host.p(const.RELEASES))).free
        if free < need:
            self.finish()
            return Result(const.EXIT_PREFLIGHT, "disk_space", "Za mało miejsca na dysku do instalacji %s." % version,
                          {"free": free, "need": need})
        params = {"version": version, "sequence": cand["sequence"], "type": cand["type"], "manifest_sha256": sha,
                  "from_version": previous["version"] if previous else None, "bootstrap": bootstrap}
        self.chain.flush_audit()
        self.audit.append("installing", params, self.actor)
        st["flags"]["installing"] = {"version": version, "ts": fmt_ts(self.host.now())}
        self.store.save()
        write_status(self.host, self.store, self.policy, self.host.now())

        stage = os.path.join(self.host.p(const.RELEASES), ".staging-%s" % version)
        bin_stage = os.path.join(self.host.p(const.BIN), ".staging-%s" % version)
        sigs = self._manifest_sigs(version)
        try:
            rmtree(stage)
            os.makedirs(os.path.dirname(stage), exist_ok=True)
            bundle.stage_release(self.host, manifest, read_bytes(os.path.join(self.chain.dl, rel_release(
                version, "manifest.json"))), sigs, art_dir, stage, self.office_env)
            for img in manifest["images"]:
                if img["artifact"] is None:
                    app.assert_images({"images": [img]})
            app.validate(manifest, stage, bin_stage, bootstrap)
        except (ApplyError, bundle.BundleError, CommandError, OSError, UnicodeDecodeError) as exc:
            rmtree(stage)
            rmtree(bin_stage)
            return self._rejected_at_stage(cand, params, exc)

        release = app.release_dir(version)
        current_target = os.path.realpath(self.host.p(const.CURRENT))
        if os.path.exists(release) and os.path.realpath(release) != current_target:
            rmtree(release)
        os.replace(stage, release)
        steps = []
        try:
            app.load_images(manifest, art_dir)
            app.maintenance()
            app.switch(manifest, version, bin_stage, steps)
            failing = app.health(manifest)
            if failing:
                raise ApplyError("health", "failing checks: %s" % ", ".join(failing))
        except (ApplyError, CommandError, OSError) as exc:
            return self._auto_rollback(app, cand, params, previous, exc, steps)

        installed = {"version": version, "sequence": cand["sequence"], "manifest_sha256": sha,
                     "installed_at": fmt_ts(self.host.now()), "type": cand["type"],
                     "migrations_to": manifest["migrations"]["to"], "bin_version": version}
        if previous:
            st["history"] = [previous] + [h for h in st["history"] if h["version"] != version]
        st["installed"] = installed
        st["flags"].update({"installing": None, "rb": None, "failed": None})
        st["failed_releases"].pop(sha, None)
        if st["flags"].get("vuln") and not semver_gt(st["flags"]["vuln"], version):
            st["flags"]["vuln"] = None
        st["candidates"] = [c for c in st["candidates"] if semver_gt(c["version"], version)]
        self.store.save()
        self.audit.append("installed", dict(params, signers=cand["signers"]["manifest"]), self.actor)
        self._prune(app)
        worker_msg = ""
        if any(a["kind"] == "worker-bundle" for a in manifest["artifacts"]):
            st["flags"]["worker_pending"] = sha
            worker_msg = self._deploy_worker(app, version)
        self.finish()
        return Result(const.EXIT_OK, "installed", "Zainstalowano wydanie %s.%s" % (version, worker_msg),
                      {"version": version, "manifest_sha256": sha})

    def _manifest_sigs(self, version: str) -> dict:
        rel = rel_release(version, "manifest.json")
        out = {}
        for sid in sshsig.signer_ids(self.host.p(const.ALLOWED_SIGNERS), const.NS_RELEASE):
            data = read_bytes(os.path.join(self.chain.dl, *("%s.%s.sig" % (rel, sid)).split("/")))
            if data is not None:
                out[sid] = data
        return out

    def _rejected_at_stage(self, cand, params, exc) -> Result:
        st = self.store.state
        st["flags"]["installing"] = None
        st["flags"]["rej"] = True
        st["failed_releases"][cand["manifest_sha256"]] = {"version": cand["version"], "ts": fmt_ts(self.host.now()),
                                                          "reason": "validation"}
        for c in st["candidates"]:
            if c["manifest_sha256"] == cand["manifest_sha256"]:
                c["state"] = "rejected"
                c["verify"] = {"ok": False, "code": "validation", "detail": str(exc)[:500]}
        self.store.save()
        self.audit.append("rejected", dict(params, code="validation", detail=str(exc)[:300]), self.actor)
        self.finish()
        return Result(const.EXIT_REJECTED, "validation", "Wydanie %s odrzucone przez walidator: %s"
                      % (cand["version"], str(exc)[:300]))

    def _auto_rollback(self, app, cand, params, previous, exc, steps) -> Result:
        st = self.store.state
        st["failed_releases"][cand["manifest_sha256"]] = {"version": cand["version"], "ts": fmt_ts(self.host.now()),
                                                          "reason": str(exc)[:300]}
        st["flags"]["installing"] = None
        detail = str(exc)[:300]
        if previous is None:
            st["flags"]["failed"] = {"version": cand["version"], "ts": fmt_ts(self.host.now()), "reason": detail}
            self.store.save()
            self.audit.append("rollback_failed", dict(params, reason=detail, steps=steps), self.actor)
            self.finish()
            return Result(const.EXIT_ROLLBACK_FAILED, "rollback_failed",
                          "Pierwsza instalacja %s nie powiodła się (brak wersji do przywrócenia): %s"
                          % (cand["version"], detail))
        ok, why = self._restore(app, previous)
        if ok:
            st["flags"]["rb"] = {"version": cand["version"], "to": previous["version"], "ts": fmt_ts(self.host.now()),
                                 "reason": detail}
            self.store.save()
            self.audit.append("rolled_back", dict(params, to=previous["version"], reason=detail, steps=steps,
                                                  automatic=True), self.actor)
            self.finish()
            return Result(const.EXIT_ROLLED_BACK, "rolled_back", "Instalacja %s nie powiodła się (%s); przywrócono %s."
                          % (cand["version"], detail, previous["version"]))
        st["flags"]["failed"] = {"version": cand["version"], "ts": fmt_ts(self.host.now()), "reason": why}
        self.store.save()
        self.audit.append("rollback_failed", dict(params, to=previous["version"], reason=detail, rollback=why,
                                                  steps=steps), self.actor)
        self.finish()
        return Result(const.EXIT_ROLLBACK_FAILED, "rollback_failed",
                      "Instalacja %s i powrót do %s nie powiodły się: %s" % (cand["version"], previous["version"], why))

    def _restore(self, app, target: dict):
        try:
            manifest = self._kept_manifest(target)
            app.restore(target["version"], target.get("bin_version"))
            failing = app.health(manifest)
        except (ApplyError, CommandError, OSError, Precondition) as exc:
            return False, str(exc)[:300]
        if failing:
            return False, "health: %s" % ", ".join(failing)
        return True, ""

    def _kept_manifest(self, target: dict) -> dict:
        """Manifest of a kept release, re-verified (signatures and sha256) before use."""
        release = os.path.join(self.host.p(const.RELEASES), target["version"])
        data = read_bytes(os.path.join(release, "manifest.json"))
        if data is None or sha256_file(os.path.join(release, "manifest.json")) != target["manifest_sha256"]:
            raise Precondition("release %s is not kept on disk or was modified" % target["version"])
        sigs = {}
        for sid in sshsig.signer_ids(self.host.p(const.ALLOWED_SIGNERS), const.NS_RELEASE):
            sig = read_bytes(os.path.join(release, "manifest.json.%s.sig" % sid))
            if sig is not None:
                sigs[sid] = sig
        res = self.chain.verifier.verify(data, sigs, const.NS_RELEASE, self.policy["signatures_required"],
                                         const.RELEASE_PRINCIPALS)
        if not res["ok"]:
            raise Precondition("release %s: signatures no longer valid (%s)" % (target["version"],
                                                                                  "; ".join(res["errors"])))
        return json.loads(data.decode("utf-8"))

    def _prune(self, app) -> None:
        st = self.store.state
        keep = max(2, self.policy["keep_releases"])
        st["history"] = st["history"][:keep - 1]
        kept = [st["installed"]] + st["history"]
        versions = {k["version"] for k in kept}
        bins = {k.get("bin_version") for k in kept}
        releases = self.host.p(const.RELEASES)
        for name in os.listdir(releases):
            if name.startswith(".staging-") or name in versions:
                continue
            manifest = read_bytes(os.path.join(releases, name, "manifest.json"))
            rmtree(os.path.join(releases, name))
            if manifest:
                self._remove_images(json.loads(manifest.decode("utf-8")), kept)
        bin_root = self.host.p(const.BIN)
        bin_current = self.host.p(const.BIN_CURRENT)
        active = os.path.basename(os.readlink(bin_current)) if os.path.islink(bin_current) else None
        if os.path.isdir(bin_root):
            for name in os.listdir(bin_root):
                path = os.path.join(bin_root, name)
                if name in bins or name == active or os.path.islink(path) or name.startswith(".staging-"):
                    continue
                rmtree(path)
        rmtree(os.path.join(self.chain.dl, "releases", st["installed"]["version"]))
        self.store.save()

    def _remove_images(self, manifest: dict, kept: list) -> None:
        keep_digests = set()
        for k in kept:
            data = read_bytes(os.path.join(self.host.p(const.RELEASES), k["version"], "manifest.json"))
            if data:
                keep_digests |= {i["digest"] for i in json.loads(data.decode("utf-8"))["images"]}
        for img in manifest.get("images", []):
            if img["digest"] not in keep_digests:
                ref = img["ref"].rsplit(":", 1)[0] if ":" in img["ref"].rsplit("/", 1)[-1] else img["ref"]
                self.host.run(["docker", "image", "rm", "%s@%s" % (ref, img["digest"])], check=False, timeout=120)

    def _deploy_worker(self, app, version: str) -> str:
        st = self.store.state
        release = app.release_dir(version)
        try:
            rc, _out, _err = app.worker(release)
        except CommandError as exc:
            rc = exc.rc
        if rc == 0:
            st["flags"]["worker_pending"] = None
            if st["flags"].get("failed", {}) and st["flags"]["failed"].get("worker"):
                st["flags"]["failed"] = None
            self.store.save()
            return ""
        if rc in (const.EXIT_PRECONDITION, 127):
            # Cloudflare not bootstrapped yet, or the worker deployer is not
            # installed yet (first installation): retried at the next run.
            self.store.save()
            return " Worker strony czeka na konfigurację Cloudflare."
        st["flags"]["failed"] = {"worker": True, "version": version, "ts": fmt_ts(self.host.now()),
                                 "reason": "legatto-worker-deploy exit %s" % rc}
        self.store.save()
        return " Wdrożenie Workera strony nie powiodło się (exit %s); ponowienie przy następnym sprawdzeniu." % rc

    def _retry_worker(self) -> None:
        st = self.store.state
        inst = st.get("installed")
        if inst and st["flags"].get("worker_pending") == inst["manifest_sha256"]:
            app = Appliers(self.host, self.store, self.policy, self.office_env, self.actor)
            self._deploy_worker(app, inst["version"])

    # --- admin decisions ---------------------------------------------------------------------
    def _find_pending(self, release: str, sha: str):
        for c in self.store.state.get("candidates") or []:
            if c["version"] == release and c["manifest_sha256"] == sha:
                return c
        return None

    def cmd_approve(self, release: str, sha: str, not_before) -> Result:
        self.prepare()
        cand = self._find_pending(release, sha)
        if cand is None or not cand["verify"]["ok"] and cand["verify"]["code"] not in ("declined", "install-failed"):
            self.finish()
            return Result(const.EXIT_REJECTED, "not_pending",
                          "Wydanie %s z tym skrótem nie czeka na decyzję albo nie przeszło weryfikacji." % release)
        if not_before is not None:
            parse_ts(not_before)
        now = fmt_ts(self.host.now())
        actor = {k: v for k, v in self.actor.items()}
        self.store.admin["approvals"][sha] = {"version": release, "ts": now, "not_before": not_before, "actor": actor}
        self.store.admin["rejections"].pop(sha, None)
        self.store.state["flags"]["rb"] = None
        self.store.save()
        self.audit.append("approved", {"version": release, "manifest_sha256": sha, "not_before": not_before},
                          self.actor)
        ev = self.refresh(None, fetch=False)
        self.finish()
        window = self.policy["install_window"]
        return Result(const.EXIT_OK, "approved", "Wydanie %s zatwierdzone; instalacja w oknie %s–%s."
                      % (release, window["start"], window["end"]), self._ev_data(ev))

    def cmd_reject(self, release: str, sha: str, reason: str) -> Result:
        self.prepare()
        if self._find_pending(release, sha) is None:
            self.finish()
            return Result(const.EXIT_REJECTED, "not_pending", "Wydanie %s z tym skrótem nie czeka na decyzję." % release)
        now = fmt_ts(self.host.now())
        self.store.admin["rejections"][sha] = {"version": release, "ts": now, "reason": reason or "",
                                               "actor": dict(self.actor)}
        self.store.admin["approvals"].pop(sha, None)
        self.store.save()
        self.audit.append("declined", {"version": release, "manifest_sha256": sha, "reason": reason or ""}, self.actor)
        ev = self.refresh(None, fetch=False)
        self.finish()
        return Result(const.EXIT_OK, "declined", "Wydanie %s odrzucone." % release, self._ev_data(ev))

    def cmd_autosecurity(self, enabled: bool) -> Result:
        self.prepare()
        if enabled and not self.policy["auto_security"]:
            self.finish()
            return Result(const.EXIT_PRECONDITION, "policy_disabled",
                          "Automatyczne poprawki bezpieczeństwa są wyłączone w polityce serwera.")
        self.store.admin["auto_security_optout"] = not enabled
        self.store.save()
        self.audit.append("autosecurity", {"enabled": enabled}, self.actor)
        ev = self.refresh(None, fetch=False)
        self.finish()
        return Result(const.EXIT_OK, "autosecurity_set", "Automatyczne poprawki bezpieczeństwa: %s."
                      % ("włączone" if enabled else "wyłączone"), self._ev_data(ev))

    def cmd_rollback(self, to) -> Result:
        self.prepare()
        st = self.store.state
        inst = st.get("installed")
        if not inst or not st["history"]:
            self.finish()
            return Result(const.EXIT_PRECONDITION, "no_previous", "Brak poprzedniej wersji do przywrócenia.")
        target = st["history"][0] if to is None else next((h for h in st["history"] if h["version"] == to), None)
        if target is None:
            self.finish()
            return Result(const.EXIT_PRECONDITION, "not_kept", "Wersja %s nie jest przechowywana na serwerze." % to)
        if target is not st["history"][0] and target.get("migrations_to") != inst.get("migrations_to"):
            self.finish()
            return Result(const.EXIT_PREFLIGHT, "schema",
                          "Powrót do %s wymaga odtworzenia bazy (break-glass); możliwy jest powrót o jedną wersję."
                          % target["version"])
        params = {"version": target["version"], "from_version": inst["version"],
                  "manifest_sha256": target["manifest_sha256"], "automatic": False}
        app = Appliers(self.host, self.store, self.policy, self.office_env, self.actor)
        self.chain.flush_audit()
        st["flags"]["installing"] = {"version": target["version"], "ts": fmt_ts(self.host.now())}
        self.store.save()
        ok, why = self._restore(app, target)
        st["flags"]["installing"] = None
        if not ok:
            back, why_back = self._restore(app, inst)
            if back:
                self.store.save()
                self.audit.append("rollback_failed", dict(params, reason=why, restored=inst["version"]), self.actor)
                self.finish()
                return Result(const.EXIT_ROLLED_BACK, "rollback_failed_restored",
                              "Powrót do %s nie powiódł się (%s); działa nadal %s." % (target["version"], why,
                                                                                        inst["version"]))
            st["flags"]["failed"] = {"version": target["version"], "ts": fmt_ts(self.host.now()), "reason": why_back}
            self.store.save()
            self.audit.append("rollback_failed", dict(params, reason=why, restore=why_back), self.actor)
            self.finish()
            return Result(const.EXIT_ROLLBACK_FAILED, "rollback_failed",
                          "Powrót do %s i przywrócenie %s nie powiodły się." % (target["version"], inst["version"]))
        idx = st["history"].index(target)
        st["history"] = st["history"][idx + 1:]
        newer_security = inst["type"] == "security" or st["flags"].get("vuln")
        if newer_security:
            vuln = inst["version"] if inst["type"] == "security" else st["flags"]["vuln"]
            st["flags"]["vuln"] = vuln
        st["installed"] = dict(target, installed_at=fmt_ts(self.host.now()))
        st["flags"]["rb"] = None
        self.store.admin["rejections"][inst["manifest_sha256"]] = {
            "version": inst["version"], "ts": fmt_ts(self.host.now()), "reason": "rollback", "actor": dict(self.actor)}
        self.store.admin["approvals"].pop(inst["manifest_sha256"], None)
        self.store.save()
        self.audit.append("rolled_back", params, self.actor)
        ev = self.refresh(None, fetch=False)
        self.finish()
        return Result(const.EXIT_OK, "rolled_back", "Przywrócono wersję %s (baza danych bez zmian)."
                      % target["version"], self._ev_data(ev))

    # --- canary attestation ----------------------------------------------------------------------
    def cmd_attest(self, release: str, report_path: str) -> Result:
        self.prepare()
        inst = self.store.state.get("installed")
        if self.policy["channel"] != "canary":
            raise Precondition("attest runs only on the canary server")
        if not inst or inst["version"] != release:
            raise Precondition("release %s is not the installed release" % release)
        key = self.host.p(const.CANARY_KEY)
        if not os.path.isfile(key):
            raise Precondition("missing canary key %s" % const.CANARY_KEY)
        raw = read_bytes(report_path)
        if raw is None:
            raise Precondition("missing report %s" % report_path)
        report = json.loads(raw.decode("utf-8"))
        if report.get("release") not in (None, release) or report.get("manifest_sha256") not in (
                None, inst["manifest_sha256"]):
            raise Precondition("report is for another release")
        result = report.get("result")
        if result not in ("PASS", "FAIL"):
            raise Precondition("report has no result PASS|FAIL")
        doc = {"schema": const.SCHEMA_IDS["attestation"], "product": "legatto", "version": release,
               "sequence": inst["sequence"], "manifest_sha256": inst["manifest_sha256"], "result": result,
               "verify_report_sha256": sha256_file(report_path), "installed_at": inst["installed_at"],
               "finished_at": fmt_ts(self.host.now()), "canary": self.office_env.get("LEGATTO_SLUG", "")}
        if result == "FAIL":
            doc["failed_checks"] = [str(c) for c in report.get("failed_checks") or []] or ["verify"]
        from . import schema as _schema
        errors = _schema.validate("attestation", doc)
        if errors:
            raise Precondition("attestation invalid: %s" % "; ".join(errors[:3]))
        out_dir = os.path.join(self.host.p(const.UPDATE_ATTEST), release)
        os.makedirs(out_dir, exist_ok=True)
        path = os.path.join(out_dir, "canary.json")
        self.host.write_bytes(path, (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode("utf-8"), mode=0o644)
        sig = path + ".sig"
        rmtree(sig)
        self.host.run(["ssh-keygen", "-Y", "sign", "-q", "-f", key, "-n", const.NS_CANARY, path], timeout=60)
        signer = const.CANARY_PRINCIPALS[0].split("@", 1)[0]
        os.replace(sig, "%s.%s.sig" % (path, signer))
        shutil.copyfile(report_path, os.path.join(out_dir, "verify-report.json"))
        self.audit.append("attested", {"version": release, "manifest_sha256": inst["manifest_sha256"],
                                       "result": result, "sha256": sha256_file(path)}, self.actor)
        self.finish()
        return Result(const.EXIT_OK, "attested", "Atestacja %s: %s." % (release, result),
                      {"path": path, "result": result})


def _existing_parent(path: str) -> str:
    while not os.path.exists(path):
        path = os.path.dirname(path)
    return path


def _public(c: dict) -> dict:
    return {k: v for k, v in c.items() if k != "manifest"}


def _waiting_message(ev: dict) -> str:
    if ev["stale"]:
        return "Indeks wydań nieaktualny lub niepoprawny (%s); nic nie zostanie zainstalowane." % ev["stale"]
    if not ev["candidates"]:
        return "Brak nowych wydań."
    states = ", ".join("%s: %s" % (c["version"], c["state"]) for c in ev["candidates"])
    return "Wydania oczekujące: %s." % states
