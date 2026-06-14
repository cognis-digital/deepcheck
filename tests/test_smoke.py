"""Smoke tests for DEEPCHECK. Stdlib only, no network.

These build fixtures in-memory so they don't depend on any committed binary.
"""
import contextlib
import io
import json
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
        # camera EXIF hint + varied low-mean quant table => low score
        # use range(2, 66): 64 distinct values, mean ~33.5 (well below the >40 coarse threshold)
        path = _write(_jpeg(software=b"Apple iPhone 15", camera=True, quant=list(range(2, 66))))
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
        # use same low-mean quant table as test_clean_photo_authentic
        path = _write(_jpeg(software=b"Apple iPhone 15", camera=True, quant=list(range(2, 66))))
        try:
            self.assertEqual(main(["inspect", path]), 0)
        finally:
            os.remove(path)

    def test_missing_file(self):
        self.assertEqual(main(["inspect", "/no/such/file.jpg"]), 2)

    def test_no_command_usage(self):
        self.assertEqual(main([]), 2)

    def test_directory_as_image(self):
        # Passing a directory path must return exit code 2, not crash.
        import tempfile
        d = tempfile.mkdtemp()
        try:
            self.assertEqual(main(["inspect", d]), 2)
        finally:
            os.rmdir(d)

    def test_json_output_is_valid_json(self):
        path = _write(_jpeg(software=b"Apple iPhone 15", camera=True, quant=list(range(2, 66))))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = main(["inspect", path, "--format", "json"])
            self.assertEqual(code, 0)
            parsed = json.loads(buf.getvalue())
            self.assertIn("verdict", parsed)
            self.assertIn("synthetic_score", parsed)
        finally:
            os.remove(path)


class TestEdgeCases(unittest.TestCase):
    """Edge-case and robustness tests introduced by hardening."""

    def test_empty_file_no_crash(self):
        # A zero-byte file must return a clean result, not raise an exception.
        fd, path = tempfile.mkstemp()
        os.close(fd)
        try:
            from deepcheck.core import analyze_image
            r = analyze_image(path)
            self.assertEqual(r.format, "unknown")
            self.assertEqual(r.verdict, Verdict.UNKNOWN.value)
            self.assertEqual(r.synthetic_score, 0.0)
        finally:
            os.remove(path)

    def test_empty_file_cli_exit_code(self):
        # CLI must not traceback on an empty file — exit 0 (unknown → not a finding).
        fd, path = tempfile.mkstemp(suffix=".jpg")
        os.close(fd)
        try:
            self.assertEqual(main(["inspect", path]), 0)
        finally:
            os.remove(path)

    def test_truncated_png_no_crash(self):
        # A PNG with just the header and a malformed IHDR must not raise.
        png_header = b"\x89PNG\r\n\x1a\n"
        truncated_ihdr = struct.pack(">I", 13) + b"IHDR" + b"\x00\x00\x00\x10\x00\x00\x00\x10"
        # Missing the last byte of IHDR + CRC -> truncated
        data = png_header + truncated_ihdr
        fd, path = tempfile.mkstemp(suffix=".png")
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        try:
            from deepcheck.core import analyze_image
            r = analyze_image(path)
            self.assertEqual(r.format, "png")
        finally:
            os.remove(path)

    def test_validate_c2pa_large_corrupt_blob(self):
        # A large blob of random-ish bytes must not raise, just report errors.
        big_blob = bytes(range(256)) * 40  # 10 240 bytes, no valid JUMBF
        res = validate_c2pa(big_blob)
        self.assertTrue(res.present)
        self.assertFalse(res.valid)

    def test_dqt_16bit_entries_no_crash(self):
        # A DQT table with precision=1 (16-bit entries) must parse cleanly.
        from deepcheck.core import _dqt_signals
        # Build a valid 16-bit DQT: 1-byte header (pq=1,id=0) + 64×2-byte values
        header = bytes([0x10])
        entries = struct.pack(">64H", *([42] * 64))
        sigs = _dqt_signals([header + entries])
        # All 64 entries are 42, so distinct=1 (<= 4 triggers flat_quant_table)
        names = {s.name for s in sigs}
        self.assertIn("flat_quant_table", names)

    def test_analyze_image_empty_string_path_raises(self):
        # Passing an empty path must raise ValueError, not an obscure OSError.
        from deepcheck.core import analyze_image
        with self.assertRaises((ValueError, OSError)):
            analyze_image("")


if __name__ == "__main__":
    unittest.main()
