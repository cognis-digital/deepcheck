"""Generate the demo JPEG `ai_generated.jpg` deterministically (stdlib only).

This builds a minimal but structurally valid baseline JPEG by hand:
  SOI, APP0(JFIF), APP1 with a generative-tool fingerprint, DQT (flat/coarse),
  SOF0 (dimensions), a tiny SOS + entropy stub, EOI.
DEEPCHECK only walks headers up to SOS, so the entropy stub need not decode.

Run once to (re)create the demo input:
    python demos/01-basic/make_input.py
"""
import os
import struct


def seg(marker: int, payload: bytes) -> bytes:
    return bytes([0xFF, marker]) + struct.pack(">H", len(payload) + 2) + payload


def build() -> bytes:
    out = b"\xff\xd8"  # SOI
    # APP0 JFIF
    out += seg(0xE0, b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00")
    # APP1 with a generative-tool fingerprint (no real EXIF camera tags)
    out += seg(0xE1, b"Software: Stable Diffusion XL 1.0 / generated image\x00")
    # DQT: flat + coarse table (precision 0, id 0, 64 identical coarse values)
    out += seg(0xDB, b"\x00" + bytes([60] * 64))
    # SOF0: precision 8, height 64, width 64, 1 component
    sof = b"\x08" + struct.pack(">H", 64) + struct.pack(">H", 64) + b"\x01\x01\x11\x00"
    out += seg(0xC0, sof)
    # SOS header (1 component) + a tiny entropy stub
    out += seg(0xDA, b"\x01\x01\x00\x00\x3f\x00")
    out += b"\x00\x00\x00"
    out += b"\xff\xd9"  # EOI
    return out


def main() -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "ai_generated.jpg")
    with open(path, "wb") as fh:
        fh.write(build())
    print(f"wrote {path} ({os.path.getsize(path)} bytes)")


if __name__ == "__main__":
    main()
