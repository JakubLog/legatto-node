"""TOTP (RFC 4226/6238 vectors, window), scrypt hashes (format, minimum, constant-time compare), ULIDs."""

import base64
import hmac
import unittest
from unittest import mock

import harness  # noqa: F401  (sets sys.path)
from legatto_console import crypto

RFC6238_SECRETS = {
    "sha1": b"12345678901234567890",
    "sha256": b"12345678901234567890123456789012",
    "sha512": b"1234567890123456789012345678901234567890123456789012345678901234",
}
# RFC 6238 Appendix B: (time, sha1, sha256, sha512), 8 digits.
RFC6238_VECTORS = (
    (59, "94287082", "46119246", "90693936"),
    (1111111109, "07081804", "68084774", "25091201"),
    (1111111111, "14050471", "67062674", "99943326"),
    (1234567890, "89005924", "91819424", "93441116"),
    (2000000000, "69279037", "90698825", "38618901"),
    (20000000000, "65353130", "77737706", "47863826"),
)
# RFC 4226 Appendix D: counter 0..9, secret "12345678901234567890", 6 digits.
RFC4226_VECTORS = ("755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871",
                   "520489")


class TotpVectors(unittest.TestCase):
    def test_rfc4226_hotp(self):
        for counter, expected in enumerate(RFC4226_VECTORS):
            self.assertEqual(crypto.hotp(RFC6238_SECRETS["sha1"], counter), expected)

    def test_rfc6238_all_algorithms(self):
        for now, sha1, sha256, sha512 in RFC6238_VECTORS:
            for algorithm, expected in (("sha1", sha1), ("sha256", sha256), ("sha512", sha512)):
                with self.subTest(time=now, algorithm=algorithm):
                    self.assertEqual(crypto.totp(RFC6238_SECRETS[algorithm], now, digits=8, digest=algorithm), expected)

    def test_window_is_plus_minus_one_step(self):
        key = RFC6238_SECRETS["sha1"]
        now = 1_800_000_015
        step = crypto.totp_step(now)
        for delta in (-1, 0, 1):
            code = crypto.hotp(key, step + delta)
            self.assertEqual(crypto.totp_match(key, code, now), step + delta)
        for delta in (-3, -2, 2, 3):
            code = crypto.hotp(key, step + delta)
            if code not in {crypto.hotp(key, step + d) for d in (-1, 0, 1)}:
                self.assertIsNone(crypto.totp_match(key, code, now))

    def test_malformed_codes_rejected(self):
        key = RFC6238_SECRETS["sha1"]
        for code in ("", "12345", "1234567", "12a456", None, 123456, " 123456"):
            self.assertIsNone(crypto.totp_match(key, code, 1_800_000_000))

    def test_totp_compare_uses_compare_digest_for_every_step(self):
        key = RFC6238_SECRETS["sha1"]
        with mock.patch("legatto_console.crypto.hmac.compare_digest", wraps=hmac.compare_digest) as spy:
            crypto.totp_match(key, crypto.totp(key, 1_800_000_000), 1_800_000_000)
        self.assertEqual(spy.call_count, 2 * crypto.TOTP_WINDOW + 1)  # no early exit

    def test_seed_and_uri(self):
        secret = crypto.new_totp_secret()
        self.assertEqual(len(crypto.decode_totp_secret(secret)), crypto.TOTP_SECRET_BYTES)
        self.assertEqual(crypto.decode_totp_secret(secret.lower() + "\n"), crypto.decode_totp_secret(secret))
        uri = crypto.otpauth_uri(secret, "jan.kowalski", "Legatto example")
        self.assertTrue(uri.startswith("otpauth://totp/Legatto%20example%3Ajan.kowalski?secret=" + secret))
        for part in ("issuer=Legatto%20example", "algorithm=SHA1", "digits=6", "period=30"):
            self.assertIn(part, uri)
        with self.assertRaises(ValueError):
            crypto.decode_totp_secret("not-base32!")


class Scrypt(unittest.TestCase):
    def test_hash_format_and_verify(self):
        stored = crypto.scrypt_hash("zażółć gęślą jaźń 123")
        parts = stored.split("$")
        self.assertEqual(parts[:4], ["scrypt", str(2 ** 15), "8", "1"])
        self.assertEqual(len(base64.b64decode(parts[4])), 16)
        self.assertEqual(len(base64.b64decode(parts[5])), 64)
        self.assertTrue(crypto.scrypt_verify("zażółć gęślą jaźń 123", stored))
        self.assertFalse(crypto.scrypt_verify("zażółć gęślą jaźń 124", stored))
        self.assertFalse(crypto.scrypt_verify("", stored))

    def test_salt_is_random(self):
        self.assertNotEqual(crypto.scrypt_hash("same"), crypto.scrypt_hash("same"))

    def test_contract_minimum_enforced(self):
        weak = (
            crypto.scrypt_hash("x", n=2 ** 14),
            crypto.scrypt_hash("x", r=4),
            crypto.scrypt_hash("x", p=2),
            crypto.scrypt_hash("x", salt=b"short-salt"),
        )
        for stored in weak:
            with self.subTest(stored=stored[:30]):
                with self.assertRaises(crypto.WeakHash):
                    crypto.parse_scrypt(stored)
                self.assertFalse(crypto.scrypt_verify("x", stored))
        good = crypto.scrypt_hash("x")
        n, r, p, salt, digest = crypto.parse_scrypt(good)
        short = "scrypt${}${}${}${}${}".format(n, r, p, base64.b64encode(salt).decode(),
                                               base64.b64encode(digest[:32]).decode())
        with self.assertRaises(crypto.WeakHash):
            crypto.parse_scrypt(short)

    def test_malformed_hashes(self):
        for value in ("", "scrypt$", "bcrypt$2$8$1$AAAA$AAAA", "scrypt$32768$8$1$***$AAAA",
                      "scrypt$30000$8$1$" + "A" * 24 + "$" + "A" * 88, "scrypt$" + str(2 ** 22) + "$8$1$AAAA$AAAA",
                      None, 42):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    crypto.parse_scrypt(value)
                self.assertFalse(crypto.scrypt_verify("x", value))

    def test_verify_uses_compare_digest(self):
        stored = crypto.scrypt_hash("secret-password")
        with mock.patch("legatto_console.crypto.hmac.compare_digest", wraps=hmac.compare_digest) as spy:
            self.assertFalse(crypto.scrypt_verify("wrong-password", stored))
            self.assertTrue(crypto.scrypt_verify("secret-password", stored))
        self.assertEqual(spy.call_count, 2)

    def test_dummy_hash_costs_the_same_scrypt_work(self):
        stored = crypto.scrypt_hash("p")
        calls = []
        real = crypto.hashlib.scrypt

        def counting(*args, **kwargs):
            calls.append((kwargs["n"], kwargs["r"], kwargs["p"]))
            return real(*args, **kwargs)

        with mock.patch("legatto_console.crypto.hashlib.scrypt", side_effect=counting):
            dummy = crypto.dummy_hash()
            calls.clear()
            crypto.scrypt_verify("guess", stored)
            crypto.scrypt_verify("guess", dummy)
        self.assertEqual(calls[0], calls[1])


class Identifiers(unittest.TestCase):
    def test_ulid(self):
        a = crypto.new_ulid(1_700_000_000)
        b = crypto.new_ulid(1_700_000_001)
        self.assertTrue(crypto.is_ulid(a))
        self.assertLess(a, b)  # lexicographic order follows time
        for bad in ("", "8" + a[1:], a.lower(), a[:-1], a + "0", a[:-1] + "U", None):
            self.assertFalse(crypto.is_ulid(bad))

    def test_setup_code_normalisation(self):
        code = crypto.new_setup_code()
        self.assertRegex(code, r"^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){3}$")
        self.assertEqual(crypto.normalize_setup_code(code.lower().replace("-", " ")), code)
        self.assertEqual(crypto.normalize_setup_code("oooo-iiii-llll-0000"), "0000-1111-1111-0000")

    def test_password_generator(self):
        password = crypto.new_password()
        self.assertRegex(password, r"^[a-z2-9]{5}(-[a-z2-9]{5}){4}$")
        self.assertNotRegex(password, r"[01oli]")


if __name__ == "__main__":
    unittest.main()
