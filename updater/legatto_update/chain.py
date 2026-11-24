"""Release chain: fetch documents, verify them and compute the gate state of
every candidate release (section 4.7, rules 1-6).

Documents are mirrored byte-for-byte into downloads/ (same layout as the
update server); every decision is taken from that mirror, so `fetch`,
`verify` and `run` evaluate exactly the same bytes.
"""

import datetime as _dt
import json
import os
import zoneinfo

from . import bundle, const, schema, sshsig
from .host import (CommandError, fmt_ts, parse_semver, parse_ts, read_bytes, rmtree, semver_gt, sha256_bytes,
                   sha256_file)
from .source import DirSource, FetchError, SizeError, copy_file

class PolicyError(Exception):
    pass


def load_policy(host) -> dict:
    data = read_bytes(host.p(const.POLICY))
    if data is None:
        raise PolicyError("missing %s" % const.POLICY)
    try:
        policy = json.loads(data.decode("utf-8"))
    except ValueError as exc:
        raise PolicyError("policy.json is not JSON") from exc
    errors = schema.validate("policy", policy)
    if errors:
        raise PolicyError("policy.json invalid: %s" % "; ".join(errors[:5]))
    # Server floors (contract) win over anything lower.
    for typ, row in const.MIN_DELAY_HOURS.items():
        for ch, floor in row.items():
            policy["min_delay_hours"][typ][ch] = max(policy["min_delay_hours"][typ][ch], floor)
    policy["signatures_required"] = max(policy["signatures_required"], const.SIGNATURES_REQUIRED_DEFAULT)
    return policy


def clean_reason(text: str) -> str:
    """yanked_reason as shown to the office admin: printable text only, one line, <= 500 chars."""
    return " ".join("".join(ch if ch.isprintable() else " " for ch in str(text)).split())[:500]


def rel_release(version: str, name: str) -> str:
    return "releases/%s/%s" % (version, name)


class Chain:
    """One evaluation context (one run of the tool)."""

    def __init__(self, host, store, policy, office_env, audit, now: float, trusted: float):
        self.host = host
        self.store = store
        self.policy = policy
        self.office_env = office_env
        self.audit = audit
        self.now = now
        self.trusted = trusted
        self.dl = host.state(const.DOWNLOADS)
        self.local = DirSource(self.dl)
        self.allowed_signers = host.p(const.ALLOWED_SIGNERS)
        self.required = policy["signatures_required"]
        self.verifier = sshsig.Verifier(host, self.allowed_signers, self._krls())
        self.audit_queue = []

    # --- helpers -------------------------------------------------------------------------
    def _krls(self) -> list:
        krls = []
        local = self.host.p(const.KRL)
        if os.path.isfile(local):
            krls.append(local)
        store = self.host.state(const.KRL_STORE)
        if os.path.isdir(store):
            krls += [os.path.join(store, n) for n in sorted(os.listdir(store)) if n.endswith(".krl")]
        return krls

    def _signer_ids(self, namespace: str) -> list:
        return sshsig.signer_ids(self.allowed_signers, namespace)

    def _sigs(self, source, rel: str, namespace: str) -> dict:
        sigs = {}
        for sid in self._signer_ids(namespace):
            data = source.get("%s.%s.sig" % (rel, sid), const.MAX_SIG_BYTES)
            if data is not None:
                sigs[sid] = data
        return sigs

    def _mirror(self, rel: str, data) -> None:
        path = os.path.join(self.dl, *rel.split("/"))
        if data is None:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
            return
        if read_bytes(path) != data:
            self.host.write_bytes(path, data, mode=0o600)

    def _mirror_doc(self, remote, rel: str, namespace: str):
        data = remote.get(rel, const.MAX_DOC_BYTES)
        self._mirror(rel, data)
        for sid in self._signer_ids(namespace):
            srel = "%s.%s.sig" % (rel, sid)
            self._mirror(srel, remote.get(srel, const.MAX_SIG_BYTES))
        return data

    def queue(self, event: str, params: dict, once_key=None) -> None:
        if once_key is not None and not self.store.once(once_key, self.now):
            return
        self.audit_queue.append((event, params))

    def flush_audit(self) -> None:
        while self.audit_queue:
            event, params = self.audit_queue.pop(0)
            self.audit.append(event, params)

    def installed(self):
        return self.store.state.get("installed")

    # --- fetch -----------------------------------------------------------------------------
    def fetch(self, remote) -> None:
        """Mirror the documents the evaluation needs. Raises FetchError (transient)."""
        index_bytes = self._mirror_doc(remote, const.LAYOUT_INDEX, const.NS_INDEX)
        if index_bytes is None:
            raise FetchError("index.json not found")
        res = self.verifier.verify(index_bytes, self._sigs(self.local, const.LAYOUT_INDEX, const.NS_INDEX),
                                   const.NS_INDEX, self.required, const.RELEASE_PRINCIPALS)
        if not res["ok"]:
            # The publisher uploads signatures before the index: one retry
            # absorbs that window before the run reports sig=bad.
            self.host.sleep(const.INDEX_RETRY_SECONDS)
            index_bytes = self._mirror_doc(remote, const.LAYOUT_INDEX, const.NS_INDEX)
            if index_bytes is None:
                raise FetchError("index.json not found")
        try:
            index = json.loads(index_bytes.decode("utf-8"))
            entries = list(index.get("releases") or [])
            krl_sha = index.get("krl_sha256")
        except (ValueError, AttributeError, TypeError):
            return
        if krl_sha:
            self._mirror_doc(remote, const.LAYOUT_KRL, const.NS_REVOKE)
        else:
            self._mirror_doc_absent(const.LAYOUT_KRL, const.NS_REVOKE)
        inst = self.installed()
        wanted = set()
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("version"), str):
                continue
            version = entry["version"]
            try:
                parse_semver(version)
            except ValueError:
                continue
            if entry.get("yanked") or (inst and not semver_gt(version, inst["version"])):
                continue
            wanted.add(version)
            self._mirror_doc(remote, rel_release(version, "manifest.json"), const.NS_RELEASE)
            if entry.get("attestation_sha256"):
                self._mirror_doc(remote, rel_release(version, "attest/canary.json"), const.NS_CANARY)
            for ch in ("early", "stable"):
                if (entry.get("promotions") or {}).get(ch):
                    self._mirror_doc(remote, rel_release(version, "promote/%s.json" % ch), const.NS_PROMOTE)
                else:
                    self._mirror_doc_absent(rel_release(version, "promote/%s.json" % ch), const.NS_PROMOTE)
        rel_root = os.path.join(self.dl, "releases")
        if os.path.isdir(rel_root):
            for name in os.listdir(rel_root):
                if name not in wanted:
                    rmtree(os.path.join(rel_root, name))

    def _mirror_doc_absent(self, rel: str, namespace: str) -> None:
        self._mirror(rel, None)
        for sid in self._signer_ids(namespace):
            self._mirror("%s.%s.sig" % (rel, sid), None)

    # --- evaluation ---------------------------------------------------------------------
    def evaluate(self, remote=None, bootstrap=False) -> dict:
        """Verify the mirror and compute candidates. `remote` downloads missing artifacts."""
        st = self.store.state
        ev = {"index_ok": False, "sig": "none", "sig_errors": [], "stale": None, "candidates": [],
              "rejected": False, "chosen": None, "index": None}
        index_bytes = self.local.get(const.LAYOUT_INDEX, const.MAX_DOC_BYTES)
        if index_bytes is None:
            ev["stale"] = "index-missing"
            return ev
        index_sha = sha256_bytes(index_bytes)
        try:
            unverified = json.loads(index_bytes.decode("utf-8"))
        except ValueError:
            unverified = None
        # KRL first: it may revoke a key that signed the index.
        if isinstance(unverified, dict) and unverified.get("krl_sha256"):
            if not self._accept_krl(unverified["krl_sha256"], ev):
                ev["stale"] = "krl-invalid"
                return ev
        res = self.verifier.verify(index_bytes, self._sigs(self.local, const.LAYOUT_INDEX, const.NS_INDEX),
                                   const.NS_INDEX, self.required, const.RELEASE_PRINCIPALS)
        if not res["ok"]:
            ev["sig"] = "bad"
            ev["sig_errors"].append("index.json: " + "; ".join(res["errors"]))
            ev["stale"] = "index-signature"
            ev["rejected"] = True
            self.queue("rejected", {"document": "index.json", "code": "index-signature", "sha256": index_sha},
                       "rejected:index:%s" % index_sha)
            return ev
        ev["sig"] = "ok"
        index = unverified
        errors = schema.validate("index", index) if isinstance(index, dict) else ["not an object"]
        if errors:
            ev["stale"] = "index-schema"
            self.queue("stale", {"reason": "index-schema", "sha256": index_sha}, "stale:schema:%s" % index_sha)
            return ev
        last = st.get("index")
        reason = None
        issued, expires = parse_ts(index["issued_at"]), parse_ts(index["expires"])
        if last and index["sequence"] < last["sequence"]:
            reason = "index-rollback"
        elif last and index["sequence"] == last["sequence"] and index_sha != last["sha256"]:
            reason = "index-fork"
        elif expires <= self.now:
            reason = "index-expired"
        elif expires <= issued or expires - issued > self.policy["index_max_validity_days"] * 86400:
            reason = "index-validity"
        elif issued > self.now + const.CLOCK_SKEW_SECONDS:
            reason = "index-future"
        else:
            versions = [r["version"] for r in index["releases"]]
            seqs = [r["sequence"] for r in index["releases"]]
            if len(set(versions)) != len(versions) or len(set(seqs)) != len(seqs):
                reason = "index-duplicate"
        if reason:
            ev["stale"] = reason
            self.queue("stale", {"reason": reason, "index_sequence": index["sequence"], "sha256": index_sha},
                       "stale:%s:%s" % (reason, index_sha))
            return ev
        if not last or last["sequence"] != index["sequence"]:
            self.queue("fetched", {"index_sequence": index["sequence"], "sha256": index_sha,
                                   "releases": len(index["releases"])}, "fetched:%s" % index_sha)
        st["index"] = {"sequence": index["sequence"], "sha256": index_sha, "issued_at": index["issued_at"],
                       "expires": index["expires"]}
        ev["index_ok"] = True
        ev["index"] = index
        inst = self.installed()
        self._installed_yanked(index, inst)
        # Bootstrap installs one release: the newest installable one. Walking from the
        # newest and stopping at the first ready release downloads one bundle, not all.
        for entry in sorted(index["releases"], key=lambda r: r["sequence"], reverse=bootstrap):
            if entry["yanked"]:
                continue
            cand = self._classify(entry, inst)
            if cand is None:
                continue
            if cand["verify"]["code"] is None:
                cand = self._evaluate_release(entry, cand, remote, bootstrap, ev)
            else:
                ev["rejected"] = True
            ev["candidates"].append(cand)
            if bootstrap and cand["state"] == "ready":
                break
        ev["candidates"].sort(key=lambda c: c["sequence"])
        ready = [c for c in ev["candidates"] if c["state"] == "ready"]
        if ready:
            ev["chosen"] = max(ready, key=lambda c: c["sequence"])
        return ev

    def _installed_yanked(self, index: dict, inst) -> None:
        """Rule: a yanked release is never installed; a server already running it
        reports it (upd=yanked, audit once per change) and waits for a newer one.
        No automatic rollback: the office admin or the vendor decides."""
        flags = self.store.state["flags"]
        entry = None
        if inst:
            entry = next((r for r in index["releases"] if r["version"] == inst["version"]
                          and r["manifest_sha256"] == inst["manifest_sha256"]), None)
        if entry is None or not entry["yanked"]:
            flags["yanked"] = None
            return
        reason = clean_reason(entry.get("yanked_reason", ""))
        previous = flags.get("yanked")
        flags["yanked"] = {"version": inst["version"], "manifest_sha256": inst["manifest_sha256"],
                           "reason": reason, "since": (previous or {}).get("since") or fmt_ts(self.now)}
        if not previous or previous.get("manifest_sha256") != inst["manifest_sha256"]:
            self.queue("installed_yanked", {"version": inst["version"], "manifest_sha256": inst["manifest_sha256"],
                                            "sequence": inst["sequence"], "index_sequence": index["sequence"]})

    def _accept_krl(self, krl_sha: str, ev: dict) -> bool:
        stored = os.path.join(self.host.state(const.KRL_STORE), krl_sha + ".krl")
        if os.path.isfile(stored):
            return True
        data = self.local.get(const.LAYOUT_KRL, const.MAX_DOC_BYTES)
        if data is None or sha256_bytes(data) != krl_sha:
            ev["sig_errors"].append("revoked.krl: missing or sha256 differs from index")
            return False
        res = self.verifier.verify(data, self._sigs(self.local, const.LAYOUT_KRL, const.NS_REVOKE),
                                   const.NS_REVOKE, self.required, const.RELEASE_PRINCIPALS)
        if not res["ok"]:
            ev["sig"] = "bad"
            ev["rejected"] = True
            ev["sig_errors"].append("revoked.krl: " + "; ".join(res["errors"]))
            self.queue("rejected", {"document": "revoked.krl", "code": "krl-signature", "sha256": krl_sha},
                       "rejected:krl:%s" % krl_sha)
            return False
        tmp = stored + ".new"
        self.host.write_bytes(tmp, data, mode=0o644)
        if not sshsig.check_krl(self.host, tmp):
            os.unlink(tmp)
            ev["sig_errors"].append("revoked.krl: unreadable KRL")
            return False
        os.replace(tmp, stored)
        self.verifier.krls.append(stored)
        return True

    # --- per release ------------------------------------------------------------------------
    def _new_cand(self, entry: dict) -> dict:
        return {
            "version": entry["version"], "sequence": entry["sequence"], "type": entry["type"],
            "manifest_sha256": entry["manifest_sha256"], "state": "rejected", "channel": self.policy["channel"],
            "earliest_install_at": None, "first_seen_at": None, "promotion_first_seen_at": None,
            "released_at": None, "expires": None, "min_installed": None, "min_contract_version": None,
            "changelog_url": None, "notes_md": None, "advisories": [],
            "signers": {"manifest": [], "early": [], "stable": [], "canary": []},
            "canary_attestation": None, "egress": None, "approval": None, "rejection": None,
            "needs_approval": False, "verify": {"ok": False, "code": None, "detail": ""},
        }

    def _classify(self, entry: dict, inst):
        """Anti-rollback against the installed release (rule 2)."""
        if not inst:
            return self._new_cand(entry)
        newer_v = semver_gt(entry["version"], inst["version"])
        newer_s = entry["sequence"] > inst["sequence"]
        if not newer_v and not newer_s:
            return None
        cand = self._new_cand(entry)
        if newer_v and newer_s:
            return cand
        code = "older-version" if newer_s else "older-sequence"
        return self._reject(cand, code, "version %s / sequence %s vs installed %s / %s"
                            % (entry["version"], entry["sequence"], inst["version"], inst["sequence"]))

    def _reject(self, cand: dict, code: str, detail: str, state="rejected", alert=True) -> dict:
        cand["state"] = state
        cand["verify"] = {"ok": False, "code": code, "detail": detail[:500]}
        cand["alert"] = alert
        if alert:
            self.queue("rejected", {"version": cand["version"], "sequence": cand["sequence"],
                                    "manifest_sha256": cand["manifest_sha256"], "code": code},
                       "rejected:%s:%s" % (cand["manifest_sha256"], code))
        return cand

    def _verify_doc(self, rel: str, namespace: str, principals, required: int, ev: dict):
        data = self.local.get(rel, const.MAX_DOC_BYTES)
        if data is None:
            return None, None
        res = self.verifier.verify(data, self._sigs(self.local, rel, namespace), namespace, required, principals)
        if not res["ok"]:
            ev["sig"] = "bad"
            ev["sig_errors"].append("%s: %s" % (rel, "; ".join(res["errors"])))
        return data, res

    def _evaluate_release(self, entry, cand, remote, bootstrap, ev) -> dict:
        version, sha = entry["version"], entry["manifest_sha256"]
        rel = rel_release(version, "manifest.json")
        data, res = self._verify_doc(rel, const.NS_RELEASE, const.RELEASE_PRINCIPALS, self.required, ev)
        if data is None:
            return self._reject(cand, "manifest-missing", "manifest.json not available", alert=False)
        if sha256_bytes(data) != sha:
            ev["rejected"] = True
            return self._reject(cand, "manifest-hash", "manifest sha256 differs from index")
        if not res["ok"]:
            ev["rejected"] = True
            return self._reject(cand, "manifest-signature", "; ".join(res["errors"]))
        cand["signers"]["manifest"] = res["principals"]
        try:
            manifest = json.loads(data.decode("utf-8"))
        except ValueError:
            ev["rejected"] = True
            return self._reject(cand, "manifest-schema", "not JSON")
        errors = schema.validate("manifest", manifest)
        if errors:
            ev["rejected"] = True
            return self._reject(cand, "manifest-schema", "; ".join(errors[:5]))
        if (manifest["version"], manifest["sequence"], manifest["type"]) != (version, entry["sequence"], entry["type"]):
            ev["rejected"] = True
            return self._reject(cand, "manifest-mismatch", "version/sequence/type differ from index")
        rules = bundle.manifest_rules(manifest)
        if rules:
            ev["rejected"] = True
            return self._reject(cand, "manifest-rules", "; ".join(rules[:5]))
        cand.update({"released_at": manifest["released_at"], "expires": manifest["expires"],
                     "min_installed": manifest["min_installed"],
                     "min_contract_version": manifest["min_contract_version"],
                     "changelog_url": manifest["changelog_url"], "advisories": manifest["advisories"]})
        cand["manifest"] = manifest
        fs = self.store.seen(sha, self.trusted, self.now, "manifest", version)
        cand["first_seen_at"] = fs["wall"]
        cand["verify"] = {"ok": True, "code": "verified", "detail": ""}
        self.queue("verified", {"version": version, "sequence": entry["sequence"], "manifest_sha256": sha,
                                "type": entry["type"], "signers": res["principals"]}, "verified:%s" % sha)
        if parse_ts(manifest["expires"]) <= self.now:
            return self._reject(cand, "expired", "manifest expired", state="expired", alert=False)
        failed = self.store.state["failed_releases"].get(sha)
        approval = self.store.admin["approvals"].get(sha)
        if failed and not (approval and approval["ts"] > failed["ts"]):
            if failed.get("reason") == "validation":
                ev["rejected"] = True
                return self._reject(cand, "validation", "rejected by a validator before installation")
            return self._reject(cand, "install-failed", "installation failed and was rolled back", alert=False)
        rejection = self.store.admin["rejections"].get(sha)
        if rejection:
            cand["rejection"] = rejection
            return self._reject(cand, "declined", "declined by the office admin", alert=False)
        inst = self.installed()
        inst_version = inst["version"] if inst else "0.0.0"
        contract = int(self.office_env.get("LEGATTO_CONTRACT_VERSION", "0") or 0)
        if semver_gt(manifest["min_installed"], inst_version) or manifest["min_contract_version"] > contract:
            cand["state"] = "blocked-baseline"
            cand["verify"] = {"ok": True, "code": "baseline",
                              "detail": "requires installed >= %s and contract >= %s"
                              % (manifest["min_installed"], manifest["min_contract_version"])}
            return cand
        # Egress widening (rule 6) needs only the manifest: computed early so the
        # console can show the difference while the release still waits.
        if not bootstrap:
            egress = self._egress_diff(version)
            if egress.get("error"):
                ev["rejected"] = True
                return self._reject(cand, egress["code"], egress["error"])
            cand["egress"] = egress["diff"]
        # Approval need (rule 6) is shown to the admin while the release waits.
        optout = self.store.admin["auto_security_optout"]
        widening = bool(cand["egress"] and cand["egress"].get("widening"))
        needs = (manifest["type"] == "feature" or widening
                 or (manifest["type"] == "security" and (not self.policy["auto_security"] or optout)))
        cand["needs_approval"] = needs and not bootstrap
        cand["approval"] = approval
        # Promotion and delay (rules 4-5).
        state, earliest = self._promotion(entry, manifest, cand, ev, bootstrap)
        if state == "rejected":
            return cand
        cand["state"] = state
        cand["earliest_install_at"] = earliest
        if state == "waiting-promotion":
            return cand
        # Artifacts (rule 3) once the release can become installable.
        try:
            info = self.ensure_artifacts(version, manifest, remote)
        except bundle.BundleError as exc:
            ev["rejected"] = True
            return self._reject(cand, exc.code, exc.detail)
        except SizeError as exc:
            ev["rejected"] = True
            return self._reject(cand, "artifact-size", str(exc))
        except (FetchError, OSError) as exc:
            # Transient: retried at the next run; the release cannot install now.
            cand["verify"] = {"ok": False, "code": "artifact-download", "detail": str(exc)[:500]}
            if state == "ready":
                cand["state"] = "waiting-window"
            return cand
        cand["notes_md"] = info["notes_md"]
        if state != "ready":
            return cand
        if bootstrap:
            cand["state"] = "ready"
            return cand
        if needs and not approval:
            cand["state"] = "waiting-approval"
            self.queue("pending", {"version": version, "manifest_sha256": sha, "type": manifest["type"],
                                   "egress_widening": bool(cand["egress"] and cand["egress"].get("widening"))},
                       "pending:%s" % sha)
            return cand
        # "Install now" (approve --install-now) skips only the install window: promotion,
        # channel delay, approval and egress gates above are already satisfied here.
        if approval and approval.get("install_now"):
            cand["state"] = "ready"
            return cand
        not_before = parse_ts(approval["not_before"]) if approval and approval.get("not_before") else None
        start = max(self.now, not_before or self.now)
        if (not_before and not_before > self.now) or not self.in_window(self.now):
            cand["state"] = "waiting-window"
            cand["earliest_install_at"] = fmt_ts(self.next_window(start))
            return cand
        cand["state"] = "ready"
        return cand

    def _promotion(self, entry, manifest, cand, ev, bootstrap):
        channel = self.policy["channel"]
        if channel == "canary":
            return "ready", None
        version, sha = entry["version"], entry["manifest_sha256"]
        # Canary attestation: PASS, signed by the canary key, bound to this manifest.
        if not entry["attestation_sha256"]:
            return "waiting-promotion", None
        att_rel = rel_release(version, "attest/canary.json")
        att, res = self._verify_doc(att_rel, const.NS_CANARY, const.CANARY_PRINCIPALS, 1, ev)
        if att is None:
            return "waiting-promotion", None
        if sha256_bytes(att) != entry["attestation_sha256"]:
            ev["rejected"] = True
            self._reject(cand, "attestation-hash", "attestation sha256 differs from index")
            return "rejected", None
        if not res["ok"]:
            ev["rejected"] = True
            self._reject(cand, "attestation-signature", "; ".join(res["errors"]))
            return "rejected", None
        cand["signers"]["canary"] = res["principals"]
        try:
            attestation = json.loads(att.decode("utf-8"))
        except ValueError:
            attestation = None
        errs = schema.validate("attestation", attestation) if isinstance(attestation, dict) else ["not JSON"]
        if errs or (attestation["version"], attestation["sequence"], attestation["manifest_sha256"]) != (
                version, manifest["sequence"], sha):
            ev["rejected"] = True
            self._reject(cand, "attestation-invalid", "; ".join(errs[:3]) or "attestation not bound to manifest")
            return "rejected", None
        att_sha = sha256_bytes(att)
        cand["canary_attestation"] = {"result": attestation["result"], "sha256": att_sha}
        if attestation["result"] != "PASS":
            return "waiting-promotion", None
        needed = ["early"] if channel == "early" else ["early", "stable"]
        promos = {}
        for ch in needed:
            psha = entry["promotions"][ch]
            if not psha:
                return "waiting-promotion", None
            prel = rel_release(version, "promote/%s.json" % ch)
            pdata, pres = self._verify_doc(prel, const.NS_PROMOTE, const.RELEASE_PRINCIPALS, self.required, ev)
            if pdata is None:
                return "waiting-promotion", None
            if sha256_bytes(pdata) != psha:
                ev["rejected"] = True
                self._reject(cand, "promotion-hash", "%s promotion sha256 differs from index" % ch)
                return "rejected", None
            if not pres["ok"]:
                ev["rejected"] = True
                self._reject(cand, "promotion-signature", "%s: %s" % (ch, "; ".join(pres["errors"])))
                return "rejected", None
            try:
                promo = json.loads(pdata.decode("utf-8"))
            except ValueError:
                promo = None
            errs = schema.validate("promotion", promo) if isinstance(promo, dict) else ["not JSON"]
            bound = not errs and (promo["version"], promo["sequence"], promo["type"], promo["channel"],
                                  promo["manifest_sha256"], promo["canary_attestation_sha256"]) == (
                version, manifest["sequence"], manifest["type"], ch, sha, att_sha)
            if bound and ch == "stable":
                bound = promo.get("early_promotion_sha256") == entry["promotions"]["early"]
            if not bound:
                ev["rejected"] = True
                self._reject(cand, "promotion-invalid", "%s: %s" % (ch, "; ".join(errs[:3]) or "not bound to release"))
                return "rejected", None
            cand["signers"][ch] = pres["principals"]
            promos[ch] = self.store.seen(psha, self.trusted, self.now, "promotion-" + ch, version)
        own = promos[channel]
        cand["promotion_first_seen_at"] = own["wall"]
        if bootstrap:
            return "ready", None
        delay = self.policy["min_delay_hours"][manifest["type"]][channel] * 3600
        remaining = own["trusted"] + delay - self.trusted
        if remaining > 0:
            return "waiting-delay", fmt_ts(self.now + remaining)
        return "ready", None

    def _egress_diff(self, version: str) -> dict:
        current = self.host.p(const.CURRENT)
        from_dir = current if os.path.isfile(os.path.join(current, "manifest.json")) else "none"
        to_dir = os.path.join(self.dl, "releases", version)
        try:
            rc, out, err = self.host.run([const.CLI_EGRESS, "diff", "--from", from_dir, "--to", to_dir, "--json"],
                                         check=False, timeout=120)
        except CommandError as exc:
            return {"error": str(exc), "code": "egress-diff-error"}
        if rc == const.EGRESS_PINNED_REMOVED:
            return {"error": "release removes a pinned egress entry", "code": "egress-pinned"}
        if rc == const.EGRESS_INVALID:
            return {"error": "egress allowlist invalid: %s" % err.strip()[-300:], "code": "egress-invalid"}
        if rc not in (0, const.EGRESS_WIDENING):
            return {"error": "legatto-egress diff exit %s" % rc, "code": "egress-diff-error"}
        try:
            diff = json.loads(out)
        except ValueError:
            return {"error": "legatto-egress diff: output is not JSON", "code": "egress-diff-error"}
        diff["widening"] = rc == const.EGRESS_WIDENING
        return {"diff": diff}

    # --- artifacts ---------------------------------------------------------------------------
    def artifact_dir(self, version: str) -> str:
        return os.path.join(self.dl, "releases", version, "artifacts")

    def ensure_artifacts(self, version: str, manifest: dict, remote) -> dict:
        total = sum(a["size"] for a in manifest["artifacts"])
        if total > self.policy["max_bundle_bytes"]:
            raise SizeError("bundle %d bytes above max_bundle_bytes" % total)
        art_dir = self.artifact_dir(version)
        local = None
        for a in manifest["artifacts"]:
            path = os.path.join(art_dir, a["name"])
            if os.path.isfile(path) and os.path.getsize(path) == a["size"]:
                continue
            if local is None:
                local = self._local_artifacts(version)
            if self._reuse(local.get(a["sha256"]), path, a):
                continue
            if remote is None:
                raise FetchError("%s not downloaded" % a["name"])
            remote.download(rel_release(version, a["name"]), path, a["size"])
        return bundle.check_artifact_files(manifest, art_dir)

    def _local_artifacts(self, version: str) -> dict:
        """sha256 -> path of artifact files already on disk: kept releases
        (releases/<v>/artifacts) and downloads of other candidates. The listing comes
        from their manifests; _reuse() re-hashes a file before using it."""
        dirs = []
        kept = self.host.p(const.RELEASES)
        if os.path.isdir(kept):
            dirs += [os.path.join(kept, n) for n in sorted(os.listdir(kept)) if not n.startswith(".")]
        downloads = os.path.join(self.dl, "releases")
        if os.path.isdir(downloads):
            dirs += [os.path.join(downloads, n) for n in sorted(os.listdir(downloads)) if n != version]
        found = {}
        for d in dirs:
            data = read_bytes(os.path.join(d, "manifest.json"))
            try:
                arts = json.loads(data.decode("utf-8"))["artifacts"] if data else []
                for a in arts:
                    path = os.path.join(d, "artifacts", a["name"])
                    if a["sha256"] not in found and os.path.isfile(path) and os.path.getsize(path) == a["size"]:
                        found[a["sha256"]] = path
            except (ValueError, KeyError, TypeError, AttributeError, UnicodeDecodeError):
                continue
        return found

    def _reuse(self, src, dest: str, a: dict) -> bool:
        """Hard link (or copy) an identical local file instead of downloading it."""
        if src is None:
            return False
        rmtree(dest)
        try:
            copy_file(src, dest)
        except OSError:
            rmtree(dest)
            return False
        if os.path.getsize(dest) == a["size"] and sha256_file(dest) == a["sha256"]:
            return True
        rmtree(dest)
        return False

    # --- install window ---------------------------------------------------------------------
    def _tz(self):
        return zoneinfo.ZoneInfo(self.policy["timezone"])

    def _window(self):
        start = tuple(int(x) for x in self.policy["install_window"]["start"].split(":"))
        end = tuple(int(x) for x in self.policy["install_window"]["end"].split(":"))
        return start, end

    def in_window(self, epoch: float) -> bool:
        local = _dt.datetime.fromtimestamp(epoch, tz=self._tz())
        (sh, sm), (eh, em) = self._window()
        t, s, e = local.hour * 60 + local.minute, sh * 60 + sm, eh * 60 + em
        if s == e:
            return True
        if s < e:
            return s <= t < e
        return t >= s or t < e

    def next_window(self, epoch: float) -> float:
        if self.in_window(epoch):
            return epoch
        local = _dt.datetime.fromtimestamp(epoch, tz=self._tz())
        (sh, sm), _ = self._window()
        cand = local.replace(hour=sh, minute=sm, second=0, microsecond=0)
        if cand.timestamp() <= epoch:
            cand = (local + _dt.timedelta(days=1)).replace(hour=sh, minute=sm, second=0, microsecond=0)
        return cand.timestamp()
