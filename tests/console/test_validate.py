"""Validation of every request type (CONTRACT §4.3), envelope, actor and auth."""

import unittest

import harness  # noqa: F401
from legatto_console import contract, crypto, validate
from legatto_console.validate import Invalid

SHA = "4b1e" + "0" * 60
GOOD_HASH = crypto.scrypt_hash("long enough password")
PERSON = {"name": "Anna Nowak", "email": "anna@example.pl", "phone": "+48 600 100 200"}

VALID = {
    "breakglass.enable": [{"hours": 1, "reason": "Aktualizacja systemu"}, {"hours": 8, "reason": "x" * 500}],
    "breakglass.disable": [{}, {"reason": ""}, {"reason": "Koniec prac"}],
    "update.approve": [{"release": "1.5.0", "manifest_sha256": SHA},
                       {"release": "1.5.0-rc.1", "manifest_sha256": SHA, "not_before": "2026-11-22T22:00:00Z"}],
    "update.reject": [{"release": "1.5.0", "manifest_sha256": SHA}, {"release": "2.0.0", "manifest_sha256": SHA,
                                                                     "reason": "Nie teraz"}],
    "update.rollback": [{}, {"to": "1.4.2"}],
    "update.autosecurity": [{"enabled": True}, {"enabled": False}],
    "studio.enable": [{"hours": 1}, {"hours": 8}],
    "studio.disable": [{}],
    "device.enroll": [{"kind": "office-device"}, {"kind": "staff", "login": "anna.nowak"}],
    "device.revoke": [{"node_id": "12"}],
    "staff.set": [{"staff": []}, {"staff": ["anna.nowak", "jan-kowalski", "ab"]}],
    "features.set": [{"feature": "ai", "enabled": True}, {"feature": "hibp", "enabled": False},
                     {"feature": "ics", "enabled": True, "ics_hosts": ["kalendarz.example.pl"]},
                     {"feature": "ics", "enabled": False}],
    "recovery.generate": [{}],
    "console.user.add": [{"login": "anna.nowak", "display_name": "Anna Nowak"}],
    "console.user.remove": [{"login": "anna.nowak"}],
    "console.user.reset_totp": [{"login": "anna.nowak"}],
    "console.user.password": [{"login": "anna.nowak", "scrypt": GOOD_HASH}],
    "console.login": [{}],
    "contacts.set": [{"primary": PERSON}, {"primary": PERSON, "secondary": None, "iod": PERSON, "notes": "IOD w 2027"},
                     {"primary": {"name": "Jan", "email": "", "phone": "600100200"}}],
    "console.setup": [{"login": "szef", "display_name": "Szef Biura", "scrypt": GOOD_HASH}],
}

INVALID = {
    "breakglass.enable": [{}, {"hours": 0, "reason": "Aktualizacja systemu"}, {"hours": 9, "reason": "Aktualizacja"},
                          {"hours": True, "reason": "Aktualizacja systemu"}, {"hours": "2", "reason": "Aktualizacja"},
                          {"hours": 2, "reason": "za krótki"}, {"hours": 2, "reason": "x" * 501},
                          {"hours": 2, "reason": "linia\nlinia druga"}, {"hours": 2, "reason": "bidi \u202e text ok"},
                          {"hours": 2, "reason": "Aktualizacja systemu", "extra": 1}],
    "breakglass.disable": [{"reason": "x" * 501}, {"reason": 5}],
    "update.approve": [{"release": "1.5", "manifest_sha256": SHA}, {"release": "1.5.0", "manifest_sha256": SHA.upper()},
                       {"release": "1.5.0", "manifest_sha256": SHA, "not_before": "2026-11-22 22:00"},
                       {"release": "1.5.0", "manifest_sha256": SHA, "not_before": "2026-13-40T22:00:00Z"},
                       {"release": "01.5.0", "manifest_sha256": SHA}, {"release": "1.5.0"}],
    "update.reject": [{"release": "1.5.0", "manifest_sha256": "abc"}, {"release": "1.5.0", "manifest_sha256": SHA,
                                                                        "reason": "x" * 501}],
    "update.rollback": [{"to": "latest"}, {"to": ""}, {"version": "1.0.0"}],
    "update.autosecurity": [{"enabled": "true"}, {"enabled": 1}, {}],
    "studio.enable": [{"hours": 0}, {"hours": 9}, {}],
    "studio.disable": [{"hours": 1}],
    "device.enroll": [{"kind": "vendor"}, {"kind": "staff"}, {"kind": "office-device", "login": "anna"},
                      {"kind": "staff", "login": "Anna"}, {"kind": "staff", "login": "a"}],
    "device.revoke": [{"node_id": 12}, {"node_id": "0"}, {"node_id": "1; rm"}, {}],
    "staff.set": [{"staff": "anna"}, {"staff": ["anna", "anna"]}, {"staff": ["Anna"]}, {"staff": ["x" * 42]},
                  {"staff": ["a" + str(i) for i in range(201)]}],
    "features.set": [{"feature": "tracking", "enabled": True}, {"feature": "ai", "enabled": "yes"},
                     {"feature": "ai", "enabled": True, "ics_hosts": []},
                     {"feature": "ics", "enabled": True, "ics_hosts": []},
                     {"feature": "ics", "enabled": True, "ics_hosts": ["192.168.1.10"]},
                     {"feature": "ics", "enabled": True, "ics_hosts": ["cal.example.pl:8443"]},
                     {"feature": "ics", "enabled": True, "ics_hosts": ["https://cal.example.pl"]},
                     {"feature": "ics", "enabled": True, "ics_hosts": ["*.example.pl"]},
                     {"feature": "ics", "enabled": True, "ics_hosts": ["a.example.pl", "a.example.pl"]}],
    "recovery.generate": [{"x": 1}],
    "console.user.add": [{"login": contract.EMERGENCY_LOGIN, "display_name": "Ktoś"},
                         {"login": "anna", "display_name": "A"}, {"login": "anna"}],
    "console.user.remove": [{"login": contract.EMERGENCY_LOGIN}, {"login": "../etc"}],
    "console.user.reset_totp": [{"login": contract.EMERGENCY_LOGIN}],
    "console.user.password": [{"login": "anna", "scrypt": crypto.scrypt_hash("x", n=2 ** 14)},
                              {"login": "anna", "scrypt": "plaintext"},
                              {"login": contract.EMERGENCY_LOGIN, "scrypt": GOOD_HASH}],
    "console.login": [{"password_ok": True}],
    "contacts.set": [{}, {"primary": {"name": "Jan", "email": "", "phone": ""}},
                     {"primary": {"name": "Jan", "email": "nie-email", "phone": ""}},
                     {"primary": {"name": "x" * 201, "email": "a@b.pl", "phone": ""}},
                     {"primary": PERSON, "notes": "x" * 201}, {"primary": {**PERSON, "pesel": "1"}}],
    "console.setup": [{"login": contract.EMERGENCY_LOGIN, "display_name": "Awaria", "scrypt": GOOD_HASH},
                      {"login": "szef", "display_name": "Szef", "scrypt": crypto.scrypt_hash("x", r=1)}],
}


class RequestTypes(unittest.TestCase):
    def test_every_contract_type_is_covered(self):
        self.assertEqual(set(VALID), set(contract.REQUEST_TYPES))
        self.assertEqual(set(INVALID), set(contract.REQUEST_TYPES))

    def test_valid_params(self):
        for rtype, cases in VALID.items():
            for params in cases:
                with self.subTest(type=rtype, params=str(params)[:80]):
                    validate.params_for(rtype, params)

    def test_invalid_params(self):
        for rtype, cases in INVALID.items():
            for params in cases:
                with self.subTest(type=rtype, params=str(params)[:80]):
                    with self.assertRaises(Invalid):
                        validate.params_for(rtype, params)

    def test_unknown_type_and_non_object(self):
        with self.assertRaises(Invalid):
            validate.params_for("system.shell", {})
        with self.assertRaises(Invalid):
            validate.params_for("studio.disable", [])

    def test_normalisation(self):
        self.assertEqual(validate.params_for("staff.set", {"staff": ["b.b", "a.a"]}), {"staff": ["a.a", "b.b"]})
        self.assertEqual(validate.params_for("breakglass.disable", {}), {"reason": ""})


class Envelope(unittest.TestCase):
    def test_strict_json(self):
        self.assertEqual(validate.strict_json(b'{"a":1}'), {"a": 1})
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b"\xff\xfe", b"{", b""):
            with self.assertRaises(Invalid):
                validate.strict_json(raw)

    def test_envelope_keys_and_version(self):
        base = {"v": 1, "id": "x", "type": "t", "ts": "t", "actor": {}, "auth": {}, "params": {}}
        validate.envelope(dict(base))
        for broken in ({**base, "v": 2}, {**base, "v": True}, {k: v for k, v in base.items() if k != "auth"},
                       {**base, "extra": 1}, []):
            with self.assertRaises(Invalid):
                validate.envelope(broken)

    def test_actor_must_be_in_the_tailnet(self):
        self.assertEqual(validate.actor({"user": "szef", "ip": "100.64.0.9"})["ip"], "100.64.0.9")
        self.assertEqual(validate.actor({"user": "szef", "ip": "FD7A:115C:A1E0:0:0:0:0:5"})["ip"], "fd7a:115c:a1e0::5")
        for actor in ({"user": "szef", "ip": "192.168.1.5"}, {"user": "szef", "ip": "127.0.0.1"},
                      {"user": "szef", "ip": "fd7a:115c:a1e1::5"}, {"user": "Szef", "ip": "100.64.0.9"},
                      {"user": "szef"}, {"user": "szef", "ip": "100.64.0.9", "node": "x"}):
            with self.assertRaises(Invalid):
                validate.actor(actor)

    def test_auth(self):
        self.assertEqual(validate.auth({"method": "local-totp", "totp": "012345"}, "studio.disable")["totp"], "012345")
        for auth in ({"method": "local-totp", "totp": "12345"}, {"method": "local-totp", "totp": 123456},
                     {"method": "password", "totp": "123456"}, {"method": "local-totp"}, None,
                     {"method": "setup-code", "code": "AAAA-BBBB-CCCC-DDDD"}):
            with self.assertRaises(Invalid):
                validate.auth(auth, "studio.disable")
        validate.auth({"method": "setup-code", "code": "AAAA-BBBB-CCCC-DDDD"}, "console.setup")
        for auth in ({"method": "local-totp", "totp": "123456"}, {"method": "setup-code", "code": "aaaa-bbbb"}):
            with self.assertRaises(Invalid):
                validate.auth(auth, "console.setup")

    def test_local_display(self):
        self.assertEqual(validate.local_display("2026-07-01T10:00:00Z", "Europe/Warsaw"), "01.07.2026 12:00")
        self.assertEqual(validate.local_display("2026-12-01T10:00:00Z", "Europe/Warsaw"), "01.12.2026 11:00")
        self.assertEqual(validate.local_display(None), "—")


if __name__ == "__main__":
    unittest.main()
