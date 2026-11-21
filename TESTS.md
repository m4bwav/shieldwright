# Tests

- Unit: `python -m unittest discover -s tests` (11 tests).
- Skill evals: `evals/evals.json` (4 cases: leak, pwned, clicked, refuse). Build the leak fixture fresh with `python evals/fixtures/make_leak_repo.py <dir>`.
- T-001 2026-11-21, one run each, graded by the parent session on evergreen-tester reports: with skill 4/4, bare baseline 3/4. Bare failed leak: it never looked at the repo (no proof the key was in history) and offered to run the history rewrite itself. With the skill the agent ran `sw.py repo` (exit 1, commit and masked key named) and `sw.py incident clicked-link`, and sent the password check to `sw.py pwned` for the user to type. No trigger proxy run: the plugin was not installed during the run.
