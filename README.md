# DEEPCHECK — Lightweight synthetic-media detector with C2PA validation

> Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** by [Cognis Digital](https://cognis.digital)
> MIT License · domain: `info-integrity`

[![PyPI](https://img.shields.io/pypi/v/cognis-deepcheck.svg)](https://pypi.org/project/cognis-deepcheck/)
[![CI](https://github.com/cognis-digital/deepcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/deepcheck/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Lightweight synthetic-media detector with C2PA validation.

## Install

```bash
pip install cognis-deepcheck
```

For local development from this repo:

```bash
pip install -e .
```

## Quick start

```bash
deepcheck --version
deepcheck scan demos/                          # run against bundled demo
deepcheck scan demos/ --format sarif --out r.sarif --fail-on high
deepcheck mcp                                   # start as MCP server (Cognis.Studio / Claude Desktop / Cursor)
```

## Built-in demo scenarios

Every scenario folder includes a `SCENARIO.md` describing what it represents and what findings to expect.

- `demos/01-news-org-verification/` — see [`SCENARIO.md`](demos/01-news-org-verification/SCENARIO.md)
- `demos/02-marketing-asset-audit/` — see [`SCENARIO.md`](demos/02-marketing-asset-audit/SCENARIO.md)
- `demos/03-evidence-collection/` — see [`SCENARIO.md`](demos/03-evidence-collection/SCENARIO.md)

## How it fits the Cognis Neural Suite

This tool is one of 52 in the [Cognis Neural Suite](https://github.com/cognis-digital). The full suite + launcher lives at:

- Suite landing: https://cognis.digital
- All 52 repos: https://github.com/cognis-digital
- Cognis.Studio (Enterprise AI Workforce, MCP host): https://cognis.studio

Every Suite tool ships an MCP server, so Cognis.Studio agents can call them as scoped capabilities.

## License

MIT. See [LICENSE](LICENSE).

## About

**[Cognis Digital](https://cognis.digital)** — Wyoming, USA · *Making Tomorrow Better Today: Advanced Cybersecurity, AI Innovation, and Blockchain Expertise.*
