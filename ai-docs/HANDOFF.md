# shieldwright repo handoff
Status: building. Plan: ai-docs/plans/2026-11-21-scope-and-plan.md.
Done: scripts/sw.py `repo` (gitleaks or built-in regex over git log -p, masked) and `gh` (settings audit) with 7 tests (python -m unittest tests.test_sw).
Verified 2026-11-21 live on a free private repo: vulnerability-alerts 404 "disabled", dependabot/alerts 403 "disabled", secret-scanning/alerts 404 "disabled", branches/*/protection and rulesets 403 "Upgrade to GitHub Pro" (= unavailable), actions/permissions(/workflow) 200; security_and_analysis absent from GET repo. Status code alone cannot tell off from unavailable: classify by message text.
Next: sw.py device, pwned, incident; SKILL.md + references.
