# shieldwright repo handoff
Status: released 0.1.0 (2026-11-21). Plan: ai-docs/plans/2026-11-21-scope-and-plan.md.
Done: skills/shieldwright/SKILL.md hub (5 hard rules, route table) + references repo-leak, accounts, device, incidents, family; scripts/sw.py repo, gh, device, pwned, incident; 11 tests (python -m unittest tests.test_sw); .claude-plugin/plugin.json 0.0.1.
Verified 2026-11-21: GitHub REST off vs unavailable by message text (see research); sw.py device on Windows 11 Home (3 s, no admin); Pwned Passwords range API live with Add-Padding; GitHub sensitive-data page steps (filter-repo 2.47+, push --force --mirror, count refs/pull in changed-refs).
Unverified: BitLockerProtection value map (community sources), flagged in device.md.
Session 4 (2026-11-21): evergreen unit, 4 evals (with 4/4, bare 3/4), README banner, LICENSE, SECURITY, AGENTS/CLAUDE, v0.1.0 tag + release, mark-local install. Secret/privacy scan of history clean (sw.py repo builtin: only the header-only test fixture string; grep for emails, local paths, names).
Next: manager flips visibility, sets description/topics, makes the first wiki page. Candidate fix L-002 (generic-assignment misses AWS_SECRET_ACCESS_KEY).
- 2026-11-21: 0.1.1 released (rule gap fixed, marketplace.json); wiki live at https://github.com/m4bwav/shieldwright/wiki (note in ai-docs/notes).
