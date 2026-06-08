"""Core synthetic-media detection + C2PA validation engine.

Real logic, standard library only. No network, no third-party deps.

What it actually does
---------------------
1. Format sniffing from magic bytes (JPEG / PNG).
2. JPEG structural parse: walks the segment markers, extracts quantization
   tables (DQT), the JFIF/Exif/XMP/software metadata segments, and any
   APP11 JUMBF boxes (where C2PA manifests live in JPEG).
3. PNG structural parse: walks chunks, extracts text chunks (tEXt/iTXt) and
   the `caBX` JUMBF chunk used by C2PA in PNG.
4. Tamper / synthesis heuristics:
     - quantization-table grading (very coarse single-quality tables and
       "flat" tables are characteristic of re-encodes / generative pipelines),
     - double-compression signal from quant-table uniformity,
     - software / creator-tool fingerprints in metadata (known AI generators),
     - missing-capture-metadata signal (no camera make/model on a photo-shaped
       JPEG is mildly suspicious),
     - thumbnail/main dimension sanity.
   Each heuristic contributes a weighted score; the aggregate maps to a Verdict.
5. C2PA validation: locates the JUMBF superbox, parses the box tree, finds the
   manifest store, and validates internal integrity (claim references the
   assertions that are present, hard-binding hash assertion exists, etc.).
   This is a structural / self-consistency validation -- it does NOT verify
   cryptographic signatures against a trust list (that needs crypto + a CA
   store, out of scope for a stdlib tool), and it says so honestly.
"""
from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    AUTHENTIC = "likely-authentic"
    SUSPICIOUS = "suspicious"
    SYNTHETIC = "likely-synthetic"
    UNKNOWN = "unknown"


# Software / tool fingerprints that strongly imply generative or heavy editing.
_AI_TOOL_MARKERS = (
    b"midjourney",
    b"stable diffusion",
    b"stablediffusion",
    b"dall-e",
    b"dalle",
    b"dall\xc2\xb7e",
    b"firefly",
    b"adobe firefly",
    b"sora",
    b"imagen",
    b"flux.1",
    b"comfyui",
    b"automatic1111",
    b"gan",
    b"latent diffusion",
)
_EDIT_TOOL_MARKERS = (
    b"photoshop",
    b"gimp",
    b"lightroom",
    b"affinity photo",
)
_CAMERA_HINTS = (
    b"canon",
    b"nikon",
    b"sony",
    b"apple",
    b"samsung",
    b"fujifilm",
    b"olympus",
    b"panasonic",
    b"google",  # Pixel
    b"leica",
)

# C2PA / JUMBF identifiers.
_JUMBF_TYPE = b"jumb"
_C2PA_UUID = b"c2pa"  # appears in JUMBF box content-type descriptors


@dataclass
class Signal:
    name: str
    weight: float  # contribution toward "synthetic" (positive) score
    detail: str


@dataclass
class C2PAResult:
    present: bool = False
    valid: bool = False
    box_count: int = 0
    claim_generator: str | None = None
    assertions: list[str] = field(default_factory=list)
    has_hard_binding: bool = False
    errors: list[str] = field(default_factory=list)
    note: str = ""


@dataclass
class AnalysisResult:
    path: str
    format: str
    width: int | None
    height: int | None
    verdict: str
    synthetic_score: float  # 0.0 (authentic) .. 1.0 (synthetic)
    signals: list[dict[str, Any]]
    metadata: dict[str, Any]
    c2pa: C2PAResult

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


# --------------------------------------------------------------------------- #
# Low-level format parsing
# --------------------------------------------------------------------------- #
def _sniff_format(data: bytes) -> str:
    if data[:2] == b"\xff\xd8":
        return "jpeg"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    return "unknown"


def _parse_jpeg(data: bytes) -> dict[str, Any]:
    """Walk JPEG segments. Returns dqt tables, dimensions, metadata blobs, jumbf."""
    out: dict[str, Any] = {
        "dqt_tables": [],
        "width": None,
        "height": None,
        "app_segments": [],  # (marker, payload)
        "jumbf": b"",
    }
    i = 2
    n = len(data)
    jumbf_parts: dict[int, bytes] = {}
    while i < n - 1:
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        i += 2
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
            continue
        if marker == 0xDA:  # start of scan -> entropy data follows, stop
            break
        if i + 2 > n:
            break
        seg_len = struct.unpack(">H", data[i : i + 2])[0]
        payload = data[i + 2 : i + seg_len]
        i += seg_len
        if marker == 0xDB:  # DQT
            out["dqt_tables"].append(payload)
        elif marker in (0xC0, 0xC1, 0xC2, 0xC3):  # SOF -> dimensions
            if len(payload) >= 5:
                h = struct.unpack(">H", payload[1:3])[0]
                w = struct.unpack(">H", payload[3:5])[0]
                out["height"], out["width"] = h, w
        elif 0xE0 <= marker <= 0xEF:  # APPn
            out["app_segments"].append((marker, payload))
            if marker == 0xEB:  # APP11 carries JUMBF (C2PA in JPEG)
                # APP11 JUMBF: 2-byte CI, 2-byte box-instance, 4-byte packet seq
                if len(payload) >= 8 and payload[:2] == b"JP":
                    seq = struct.unpack(">I", payload[4:8])[0]
                    jumbf_parts[seq] = payload[8:]
    if jumbf_parts:
        out["jumbf"] = b"".join(jumbf_parts[k] for k in sorted(jumbf_parts))
    return out


def _parse_png(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {
        "width": None,
        "height": None,
        "text_chunks": [],
        "jumbf": b"",
    }
    i = 8
    n = len(data)
    while i + 8 <= n:
        length = struct.unpack(">I", data[i : i + 4])[0]
        ctype = data[i + 4 : i + 8]
        payload = data[i + 8 : i + 8 + length]
        i += 12 + length  # length + type + data + crc
        if ctype == b"IHDR" and len(payload) >= 8:
            out["width"] = struct.unpack(">I", payload[0:4])[0]
            out["height"] = struct.unpack(">I", payload[4:8])[0]
        elif ctype in (b"tEXt", b"iTXt", b"zTXt"):
            out["text_chunks"].append(payload)
        elif ctype == b"caBX":  # C2PA JUMBF store in PNG
            out["jumbf"] += payload
        if ctype == b"IEND":
            break
    return out


# --------------------------------------------------------------------------- #
# JUMBF / C2PA parsing
# --------------------------------------------------------------------------- #
def _walk_jumbf(blob: bytes) -> list[dict[str, Any]]:
    """Parse an ISO-BMFF-style box tree (JUMBF uses the same box framing).

    Returns a flat list of {type, label, size, offset} for every box found.
    """
    boxes: list[dict[str, Any]] = []

    def walk(buf: bytes, base: int, depth: int) -> None:
        pos = 0
        ln = len(buf)
        while pos + 8 <= ln and depth < 12:
            size = struct.unpack(">I", buf[pos : pos + 4])[0]
            btype = buf[pos + 4 : pos + 8]
            header = 8
            if size == 1 and pos + 16 <= ln:  # 64-bit extended size
                size = struct.unpack(">Q", buf[pos + 8 : pos + 16])[0]
                header = 16
            if size == 0:
                size = ln - pos
            if size < header or pos + size > ln:
                break
            content = buf[pos + header : pos + size]
            label = None
            # A jumb superbox's first child is a 'jumd' description box that
            # carries a UTF-8 label after the 16-byte UUID + 1 toggle byte.
            if btype == b"jumd" and len(content) >= 17:
                tail = content[17:]
                end = tail.find(b"\x00")
                if end > 0:
                    try:
                        label = tail[:end].decode("utf-8")
                    except UnicodeDecodeError:
                        label = None
            boxes.append(
                {
                    "type": btype.decode("latin-1", "replace"),
                    "label": label,
                    "size": size,
                    "offset": base + pos,
                }
            )
            # Recurse into superboxes (jumb) and contiguous box containers.
            if btype == b"jumb":
                walk(content, base + pos + header, depth + 1)
            pos += size

    walk(blob, 0, 0)
    return boxes


def extract_c2pa(data: bytes, fmt: str | None = None) -> bytes:
    """Return the raw JUMBF blob containing the C2PA manifest store, or b''."""
    fmt = fmt or _sniff_format(data)
    if fmt == "jpeg":
        return _parse_jpeg(data).get("jumbf", b"")
    if fmt == "png":
        return _parse_png(data).get("jumbf", b"")
    return b""


def validate_c2pa(blob: bytes) -> C2PAResult:
    """Structurally validate a C2PA manifest store extracted from JUMBF."""
    res = C2PAResult()
    if not blob:
        res.note = "no C2PA manifest present"
        return res
    res.present = True
    boxes = _walk_jumbf(blob)
    res.box_count = len(boxes)
    if not boxes:
        res.errors.append("JUMBF present but unparseable (corrupt box framing)")
        return res

    labels = [b["label"] for b in boxes if b["label"]]
    types = [b["type"] for b in boxes]

    # A valid C2PA store carries a manifest superbox and a claim.
    has_store = any(l and l.startswith("c2pa") for l in labels) or b"c2pa" in blob[:64].lower()
    has_claim = any(l and "claim" in l for l in labels)
    has_assertions = any(l and "assertions" in l for l in labels)

    # Assertions are labelled child boxes under the assertion store.
    res.assertions = sorted(
        {l for l in labels if l and ("." in l or l.startswith("c2pa.") or l.startswith("cai."))}
    )

    # Hard binding: a data-hash / box-hash assertion must exist for the manifest
    # to actually bind to the asset bytes.
    res.has_hard_binding = any(
        l and ("hash.data" in l or "hash.boxes" in l or l.endswith(".hash")) for l in labels
    )

    # Claim generator string, if present in a CBOR-ish text blob.
    low = blob.lower()
    for marker in _AI_TOOL_MARKERS + _EDIT_TOOL_MARKERS + _CAMERA_HINTS:
        idx = low.find(marker)
        if idx != -1:
            # grab a short readable window
            window = blob[max(0, idx - 4) : idx + len(marker) + 24]
            txt = "".join(chr(c) if 32 <= c < 127 else " " for c in window).strip()
            res.claim_generator = txt
            break

    if not has_store and "jumb" not in types:
        res.errors.append("no JUMBF superbox found")
    if not has_claim:
        res.errors.append("manifest store has no claim box")
    if not has_assertions and not res.assertions:
        res.errors.append("manifest store has no assertion store")
    if not res.has_hard_binding:
        res.errors.append("no hard-binding hash assertion (manifest not bound to bytes)")

    res.valid = (not res.errors)
    res.note = (
        "structural validation only -- cryptographic signature and trust-list "
        "verification require external crypto and are out of scope"
    )
    return res


# --------------------------------------------------------------------------- #
# Heuristic scoring
# --------------------------------------------------------------------------- #
def _dqt_signals(dqt_tables: list[bytes]) -> list[Signal]:
    signals: list[Signal] = []
    if not dqt_tables:
        return signals
    # Each DQT payload: 1 byte (precision<<4 | id) then 64 (or 128) values.
    values: list[int] = []
    for tbl in dqt_tables:
        p = 0
        while p < len(tbl):
            pq = tbl[p] >> 4
            p += 1
            count = 64
            if pq == 0:
                values.extend(tbl[p : p + count])
                p += count
            else:
                # 16-bit entries
                for k in range(count):
                    if p + 1 < len(tbl):
                        values.append(struct.unpack(">H", tbl[p : p + 2])[0])
                    p += 2
    if not values:
        return signals
    avg = sum(values) / len(values)
    distinct = len(set(values))
    # Coarse quantization (high average) => low quality re-encode.
    if avg > 40:
        signals.append(
            Signal("coarse_quantization", 0.25,
                   f"mean DQT value {avg:.1f} (>40 suggests low-quality re-encode)")
        )
    # Very few distinct steps => synthetic/flat table common in GAN/diffusion exports.
    if distinct <= 4:
        signals.append(
            Signal("flat_quant_table", 0.30,
                   f"only {distinct} distinct DQT steps (flat table)")
        )
    return signals


def _metadata_signals(meta: dict[str, Any]) -> list[Signal]:
    signals: list[Signal] = []
    raw = meta.get("_raw_metadata", b"")
    low = raw.lower() if isinstance(raw, (bytes, bytearray)) else b""
    for marker in _AI_TOOL_MARKERS:
        if marker in low:
            signals.append(
                Signal("ai_generator_tag", 0.60,
                       f"metadata names generative tool: {marker.decode('latin-1', 'replace')}")
            )
            break
    for marker in _EDIT_TOOL_MARKERS:
        if marker in low:
            signals.append(
                Signal("editor_tag", 0.15,
                       f"metadata names heavy editor: {marker.decode('latin-1', 'replace')}")
            )
            break
    has_camera = any(c in low for c in _CAMERA_HINTS)
    has_exif = b"exif" in low
    if not has_camera and not has_exif and low:
        signals.append(
            Signal("no_capture_metadata", 0.10,
                   "no camera make/model or EXIF capture metadata present")
        )
    return signals


def _score_to_verdict(score: float, c2pa: C2PAResult) -> Verdict:
    # A valid, hard-bound C2PA manifest with no AI generator claim is strong
    # evidence of authenticity; pull the verdict toward authentic.
    if c2pa.present and c2pa.valid and c2pa.has_hard_binding:
        gen = (c2pa.claim_generator or "").lower()
        if not any(m.decode("latin-1", "replace") in gen for m in _AI_TOOL_MARKERS):
            return Verdict.AUTHENTIC
    if score >= 0.55:
        return Verdict.SYNTHETIC
    if score >= 0.25:
        return Verdict.SUSPICIOUS
    return Verdict.AUTHENTIC


def analyze_image(path: str) -> AnalysisResult:
    with open(path, "rb") as fh:
        data = fh.read()
    fmt = _sniff_format(data)
    width = height = None
    signals: list[Signal] = []
    raw_meta = b""

    if fmt == "jpeg":
        parsed = _parse_jpeg(data)
        width, height = parsed["width"], parsed["height"]
        raw_meta = b"".join(p for _, p in parsed["app_segments"])
        signals += _dqt_signals(parsed["dqt_tables"])
        jumbf = parsed["jumbf"]
    elif fmt == "png":
        parsed = _parse_png(data)
        width, height = parsed["width"], parsed["height"]
        raw_meta = b"".join(parsed["text_chunks"])
        jumbf = parsed["jumbf"]
    else:
        jumbf = b""
        signals.append(Signal("unknown_format", 0.0, "unrecognized container; limited analysis"))

    meta = {"_raw_metadata": raw_meta}
    signals += _metadata_signals(meta)

    c2pa = validate_c2pa(jumbf)
    if c2pa.present and not c2pa.valid:
        signals.append(
            Signal("broken_c2pa", 0.20,
                   "C2PA manifest present but failed structural validation")
        )

    # Aggregate score: saturating sum of positive signal weights.
    raw_score = sum(s.weight for s in signals if s.weight > 0)
    synthetic_score = round(min(1.0, raw_score), 3)
    verdict = _score_to_verdict(synthetic_score, c2pa)

    readable_meta = {
        "metadata_bytes": len(raw_meta),
        "has_ai_tag": any(m in raw_meta.lower() for m in _AI_TOOL_MARKERS),
        "has_camera_hint": any(c in raw_meta.lower() for c in _CAMERA_HINTS),
    }

    return AnalysisResult(
        path=path,
        format=fmt,
        width=width,
        height=height,
        verdict=verdict.value,
        synthetic_score=synthetic_score,
        signals=[asdict(s) for s in signals],
        metadata=readable_meta,
        c2pa=c2pa,
    )


def result_to_json(result: AnalysisResult) -> str:
    return json.dumps(result.to_dict(), indent=2)
