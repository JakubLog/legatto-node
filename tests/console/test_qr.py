"""QR encoder: reference matrices (segno with spec padding), structure, SVG output."""

import hashlib
import json
import os
import unittest
import xml.etree.ElementTree as ET

import harness
from legatto_console import qr


def matrix_sha256(code: qr.QrCode) -> str:
    bits = "".join("".join("1" if c else "0" for c in row) for row in code.modules)
    return hashlib.sha256(bits.encode()).hexdigest()


class ReferenceVectors(unittest.TestCase):
    def test_matrices_match_reference_encoder(self):
        with open(os.path.join(harness.HERE, "fixtures", "qr_vectors.json"), encoding="utf-8") as handle:
            vectors = json.load(handle)["vectors"]
        self.assertGreater(len(vectors), 40)
        for v in vectors:
            data = bytes.fromhex(v["data_hex"])
            with self.subTest(level=v["level"], version=v["version"], mask=v["mask"], length=len(data)):
                code = qr.encode(data, v["level"], min_version=v["version"], mask=v["mask"])
                self.assertEqual(code.version, v["version"])
                self.assertEqual(matrix_sha256(code), v["matrix_sha256"])


class Structure(unittest.TestCase):
    def test_finder_patterns_and_timing(self):
        code = qr.encode("otpauth://totp/Legatto:test?secret=JBSWY3DPEHPK3PXP", "M")
        size = code.size
        self.assertEqual(size, code.version * 4 + 17)
        for x0, y0 in ((0, 0), (size - 7, 0), (0, size - 7)):
            for i in range(7):
                self.assertTrue(code.modules[y0][x0 + i])  # outer ring of each finder
                self.assertTrue(code.modules[y0 + 6][x0 + i])
        for i in range(8, size - 8):
            self.assertEqual(code.modules[6][i], i % 2 == 0)
            self.assertEqual(code.modules[i][6], i % 2 == 0)
        self.assertTrue(code.modules[size - 8][8])  # dark module

    def test_smallest_version_and_limits(self):
        self.assertEqual(qr.encode(b"x" * 14, "M").version, 1)
        self.assertEqual(qr.encode(b"x" * 15, "M").version, 2)
        self.assertEqual(qr.encode(b"x" * 2953, "L").version, 40)
        with self.assertRaises(qr.DataTooLong):
            qr.encode(b"x" * 2954, "L")

    def test_automatic_mask_is_one_of_the_forced_results(self):
        data = "tailscale up --login-server=https://vpn.legatto-example.example --auth-key=" + "k" * 48
        auto = qr.encode(data, "M")
        forced = qr.encode(data, "M", mask=auto.mask)
        self.assertEqual(auto.modules, forced.modules)

    def test_svg_is_well_formed_and_inert(self):
        svg = qr.svg('<script>alert("x")</script>&', title='Kod "QR" <test>')
        root = ET.fromstring(svg)
        self.assertEqual(root.tag, "{http://www.w3.org/2000/svg}svg")
        self.assertNotIn("<script", svg)
        self.assertNotIn("href", svg)
        path = root.find("{http://www.w3.org/2000/svg}path")
        self.assertTrue(path.get("d").startswith("M4,4h7"))  # top-left finder row after the quiet zone


if __name__ == "__main__":
    unittest.main()
