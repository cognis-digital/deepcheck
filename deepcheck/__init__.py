"""DEEPCHECK - lightweight synthetic-media detector with C2PA validation.

Standard-library-only, zero-install. Inspects images for tampering/synthesis
signals and validates embedded C2PA provenance manifests.
"""
from .core import (
    analyze_image,
    extract_c2pa,
    validate_c2pa,
    Verdict,
    AnalysisResult,
    C2PAResult,
)

TOOL_NAME = "deepcheck"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "analyze_image",
    "extract_c2pa",
    "validate_c2pa",
    "Verdict",
    "AnalysisResult",
    "C2PAResult",
]
