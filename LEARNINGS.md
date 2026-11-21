# Learnings

- L-001 `strong-baseline-advice` (2026-11-21): the bare model already gives good rotate-then-scrub, phishing and refusal advice. The skill's gain is proof and hygiene: it scans history and names the commit with a masked key instead of guessing, routes a password to a hidden prompt instead of offering to hash it in the agent, and leaves destructive steps to the owner.
- L-002 `secret-var-not-matched` (2026-11-21): the built-in `generic-assignment` rule misses `AWS_SECRET_ACCESS_KEY = "..."` because `\bsecret\b` fails inside an underscore name. gitleaks catches it. Candidate fix: allow `_` around the keyword.
- L-003 `echoes-example-password` (2026-11-21): with and without the skill, the reply named the pasted password because it is the xkcd example. Harmless here; watch for it with a real password.
