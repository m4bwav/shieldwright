# GitHub wiki (2026-11-21, shieldwright 0.1.1)

Wiki: https://github.com/m4bwav/shieldwright/wiki, working copy `D:/m4bwa/Claude/Projects/Ai/shieldwright.wiki` (branch master, fast-forward on top of the placeholder). Written with the wikiwright skill.

Pages: Home, Getting-Started, Commands, Secret-Scanning, Incident-Playbooks, How-The-Skill-Works, FAQ, Versions-And-Upgrading, Development, _Sidebar, _Footer.

## How examples were verified
`git archive v0.1.0 skills` into a scratch folder; ran sw.py from there: `incident` (list, each name, unknown name), `repo` on a throwaway repo with a runtime-built ghp_ token in config.py (text and --json), `gh m4bwav/shieldwright`, `device`, and `repo` on a repo with `AWS_SECRET_ACCESS_KEY = "..."` in .env under 0.1.0 (0 findings) and 0.1.1 (1 finding). Output saved in `2026-11-21-wiki-verify.out.txt` (commit hashes vary per run). `gh` and `device` blocks are marked outputs: skip (live state). `pwned` not run (needs a typed password). `wikiwright check`, `outputs` and `live` all passed (9 pages).

## Facts the README lacks
- `gh` always exits 0; `device` exits 1 on a FIX line; `pwned` exits 1 when found; unknown incident exits 2.
- Workflow checks (unpinned actions, write-all, pull_request_target) run inside `repo`, even with gitleaks.
- Masking: first 4 + `******` + last 2; private-key headers printed as is.

## Inaccuracies in shipped docs
1. README and SKILL.md say "Exit 1 means findings" for sw.py; `gh` returns 0 even with settings off (not fixed).

## Update procedure
Rerun the commands above against the new tag, diff with the saved output, update Versions-And-Upgrading, Home (names the version) and _Footer (version, date).
