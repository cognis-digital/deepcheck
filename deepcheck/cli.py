"""DEEPCHECK command-line interface."""
from cognis_core import build_cli
from deepcheck.core import scan, TOOL_NAME, TOOL_VERSION

main = build_cli(
    tool_name=TOOL_NAME,
    tool_version=TOOL_VERSION,
    description="Lightweight synthetic-media detector with C2PA validation",
    scan_fn=scan,
)

if __name__ == "__main__":
    import sys
    sys.exit(main())
