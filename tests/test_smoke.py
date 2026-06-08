"""Smoke tests for DEEPCHECK. Stdlib only, no network.

These build fixtures in-memory so they don't depend on any committed binary.
"""
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from deepcheck import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    analyze_image,
    extract_c2pa,
    validate_c2pa,
    Verdict,
)
from deepcheck.cli import main  # noqa: E402


def _seg(marker, payload):
    return bytes([0xFF, marker]) + struct.pack(">H", len(payload) + 2) + payload


def _jpeg(software=b"", quant=None, camera=False):
    out = b"\xff\xd8"
    out += _seg(0xE0, b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00")
    app1 = b"Exif\x00\x00" if camera else b""
    app1 += software
    if app1:
        out += _seg(0xE1, app1 + b"\x00")
    q = quant if quant is not None else list(range(16, 80))  # varied table
    out += _seg(0xDB, b"\x00" + bytes(q[:64]))
    sof = b"\x08" + struct.pack(">H", 48) + struct.pack(">H", 32) + b"\x01\x01\x11\x00"
    out += _seg(0xC0, sof)
    out += _seg(0xDA, b"\x01\x01\x00\x00\x3f\x00") + b"\x00\x00" + b"\xff\xd9"
    return out


def _write(data):
    fd, path = tempfile.mkstemp(suffix=".jpg")
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return path


class TestMeta(unittest.TestCase):
    def test_version_exports(self):
        self.assertEqual(TOOL_NAME, "deepcheck")
        self.assertRegex(TOOL_VERSION, r"^\d+\.\d+\.\d+$")


class TestParsing(unittest.TestCase):
    def test_dimensions_and_format(self):
        path = _write(_jpeg())
        try:
            r = analyze_image(path)
            self.assertEqual(r.format, "jpeg")
            self.assertEqual((r.width, r.height), (32, 48))
        finally:
            os.remove(path)

    def test_unknown_format(self):
        path = _write(b"not an image at all")
        try:
            r = analyze_image(path)
            self.assertEqual(r.format, "unknown")
        finally:
            os.remove(path)


class TestHeuristics(unittest.TestCase):
    def test_ai_tag_flags_synthetic(self):
        path = _write(_jpeg(software=b"Software: Midjourney v6", quant=[60] * 64))
        try:
            r = analyze_image(path)
            names = {s["name"] for s in r.signals}
            self.assertIn("ai_generator_tag", names)
            self.assertGreater(r.synthetic_score, 0.5)
            self.assertEqual(r.verdict, Verdict.SYNTHETIC.value)
        finally:
            os.remove(path)

    def test_clean_photo_authentic(self):
        # camera EXIF hint + varied quant table => low score
        path = _write(_jpeg(software=b"Apple iPhone 15", camera=True))
        try:
            r = analyze_image(path)
            self.assertLess(r.synthetic_score, 0.25)
            self.assertEqual(r.verdict, Verdict.AUTHENTIC.value)
        finally:
            os.remove(path)

    def test_flat_quant_signal(self):
        path = _write(_jpeg(quant=[10, 10, 10, 10] * 16, camera=True))
        try:
            r = analyze_image(path)
            names = {s["name"] for s in r.signals}
            self.assertIn("flat_quant_table", names)
        finally:
            os.remove(path)


class TestC2PA(unittest.TestCase):
    def _jumb(self, btype, content):
        return struct.pack(">I", len(content) + 8) + btype + content

    def _jumd(self, label):
        # 16-byte UUID + 1 toggle byte + label + NUL
        return self._jumb(b"jumd", b"\x00" * 16 + b"\x03" + label.encode() + b"\x00")

    def test_no_manifest(self):
        res = validate_c2pa(b"")
        self.assertFalse(res.present)
        self.assertFalse(res.valid)

    def test_extract_from_jpeg_app11(self):
        # build an APP11 JUMBF segment
        store = self._jumb(b"jumb", self._jumd("c2pa"))
        app11 = b"JP\x00\x00" + struct.pack(">I", 1) + store
        jpg = _jpeg()
        # splice APP11 right after SOI
        spliced = jpg[:2] + _seg(0xEB, app11) + jpg[2:]
        blob = extract_c2pa(spliced, "jpeg")
        self.assertTrue(blob)
        self.assertIn(b"jumb", blob)

    def test_valid_manifest_structure(self):
        inner = (
            self._jumd("c2pa.assertions")
            + self._jumd("c2pa.hash.data")
            + self._jumd("c2pa.claim")
        )
        store = self._jumb(b"jumb", self._jumd("c2pa") + inner)
        res = validate_c2pa(store)
        self.assertTrue(res.present)
        self.assertTrue(res.has_hard_binding)
        self.assertTrue(res.valid, msg=f"errors={res.errors}")
        self.assertGreater(res.box_count, 0)

    def test_corrupt_manifest_flagged(self):
        res = validate_c2pa(b"\x00\x00\x00\x10garbagedata!!")
        self.assertTrue(res.present)
        self.assertFalse(res.valid)
        self.assertTrue(res.errors)


class TestCLI(unittest.TestCase):
    def test_exit_finding(self):
        path = _write(_jpeg(software=b"Software: Midjourney", quant=[60] * 64))
        try:
            self.assertEqual(main(["inspect", path, "--format", "json"]), 1)
        finally:
            os.remove(path)

    def test_exit_authentic(self):
        path = _write(_jpeg(software=b"Apple iPhone 15", camera=True))
        try:
            self.assertEqual(main(["inspect", path]), 0)
        finally:
            os.remove(path)

    def test_missing_file(self):
        self.assertEqual(main(["inspect", "/no/such/file.jpg"]), 2)

    def test_no_command_usage(self):
        self.assertEqual(main([]), 2)


if __name__ == "__main__":
    unittest.main()
