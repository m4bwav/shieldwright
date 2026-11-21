# AGENTS.md

Rules for any AI agent working in this repository. `CLAUDE.md` imports this file; `.github/copilot-instructions.md` points here.

## What this is

shieldwright: one hub skill, `skills/shieldwright/`, with `scripts/sw.py` (standard library only: repo, gh, device, pwned, incident) and five references. `evals/` holds the skill eval suite, `ai-docs/` the notes, plans and handoff (start with `ai-docs/HANDOFF.md`).

## Rules

- Python 3.9+, standard library only. UTF-8, LF. Exit 1 from sw.py means findings.
- Every change gets a test: `python -m unittest discover -s tests`.
- Evergreen unit at the root: read `evergreen.json` before editing; changes go in CHANGELOG with the reason, lessons in LEARNINGS.
- A release bumps `.claude-plugin/plugin.json` and CHANGELOG together.
- Defensive only. Never print, store or commit a real secret in a test, fixture or doc; build fake keys at run time. Plain short sentences, no em dashes, relative links. No AI attribution anywhere.
