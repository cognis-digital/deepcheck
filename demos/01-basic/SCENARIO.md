# Demo 01 - basic inspection

DEEPCHECK is a zero-install, stdlib-only synthetic-media detector with C2PA
provenance validation. It parses the real byte structure of JPEG/PNG files
(segment/chunk walking, quantization tables, metadata segments, and JUMBF/C2PA
manifest boxes) and grades a set of tamper / synthesis heuristics.

## Input

`ai_generated.jpg` is a minimal but structurally valid JPEG whose APP1 metadata
segment embeds a generative-tool fingerprint (`Stable Diffusion`) and whose
quantization table is a flat, coarse table characteristic of a generative
export pipeline. There is no camera/EXIF capture metadata and no C2PA manifest.

## Run it

```bash
# human-readable table
python -m deepcheck inspect demos/01-basic/ai_generated.jpg

# machine-readable JSON (for pipelines / CI gates)
python -m deepcheck inspect demos/01-basic/ai_generated.jpg --format json
```

## What you should see

- `format: jpeg`, dimensions parsed from the SOF marker.
- A `synthetic_score` driven up by the `ai_generator_tag`, `flat_quant_table`,
  and `no_capture_metadata` signals.
- `verdict: likely-synthetic`.
- C2PA: `present: false` (this asset carries no provenance manifest).

## Exit codes

- `0`  verdict is `likely-authentic`
- `1`  verdict is `suspicious` or `likely-synthetic` (a finding -- usable as a
  CI gate, e.g. block AI-generated assets from a press pipeline)
- `2`  usage / file error

Because the demo image is flagged synthetic, the command exits `1`.

## Honest scope note

C2PA validation here is **structural / self-consistency** validation (box tree,
claim, assertion store, hard-binding hash). It does NOT verify cryptographic
signatures against a trust list -- that requires real crypto and a CA store,
which is out of scope for a standard-library-only tool. The tool reports this
in its output rather than implying a stronger guarantee than it provides.
