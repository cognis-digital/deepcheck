"""DEEPCHECK command-line interface.

Usage:
    deepcheck inspect IMAGE [--format {table,json}]
    deepcheck --version

Exit codes:
    0  analysis ran AND verdict is likely-authentic
    1  analysis ran but verdict is suspicious / likely-synthetic (a finding)
    2  usage / IO error
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import TOOL_NAME, TOOL_VERSION
from .core import analyze_image, AnalysisResult, Verdict


def _render_table(r: AnalysisResult) -> str:
    lines = []
    lines.append(f"DEEPCHECK report  {r.path}")
    lines.append("-" * 60)
    lines.append(f"format          : {r.format}")
    dim = f"{r.width}x{r.height}" if r.width and r.height else "unknown"
    lines.append(f"dimensions      : {dim}")
    lines.append(f"verdict         : {r.verdict}")
    lines.append(f"synthetic_score : {r.synthetic_score:.3f}  (0=authentic .. 1=synthetic)")
    lines.append("")
    lines.append("C2PA provenance:")
    c = r.c2pa
    lines.append(f"  present       : {c.present}")
    if c.present:
        lines.append(f"  valid         : {c.valid}")
        lines.append(f"  boxes         : {c.box_count}")
        lines.append(f"  hard binding  : {c.has_hard_binding}")
        if c.claim_generator:
            lines.append(f"  generator     : {c.claim_generator}")
        if c.assertions:
            lines.append(f"  assertions    : {', '.join(c.assertions)}")
        for e in c.errors:
            lines.append(f"  ! error       : {e}")
    lines.append("")
    lines.append("Signals:")
    if not r.signals:
        lines.append("  (none)")
    for s in r.signals:
        lines.append(f"  [{s['weight']:+.2f}] {s['name']}: {s['detail']}")
    return "\n".join(lines)


def _is_finding(r: AnalysisResult) -> bool:
    return r.verdict in (Verdict.SUSPICIOUS.value, Verdict.SYNTHETIC.value)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Lightweight synthetic-media detector with C2PA validation.",
    )
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    insp = sub.add_parser("inspect", help="Analyze an image for synthesis/tampering + C2PA.")
    insp.add_argument("image", help="path to a JPEG or PNG image")
    insp.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="output format (default: table)",
    )
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "inspect":
        parser.print_help(sys.stderr)
        return 2

    if not os.path.isfile(args.image):
        print(f"{TOOL_NAME}: error: no such file: {args.image}", file=sys.stderr)
        return 2

    try:
        result = analyze_image(args.image)
    except (OSError, struct_error_t()) as exc:  # type: ignore[misc]
        print(f"{TOOL_NAME}: error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(_render_table(result))

    return 1 if _is_finding(result) else 0


def struct_error_t():
    import struct
    return struct.error


if __name__ == "__main__":
    raise SystemExit(main())
