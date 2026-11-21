# shieldwright scope and plan (2026-11-21)

Defensive only. Never asks for, prints or stores a secret; reports findings by location and type, masked.

## Shape (small package)
- One hub skill `shieldwright` with references loaded on demand: repo-leak.md (scan, rotate, scrub order), accounts.md (2FA/password-manager checklist per NIST 800-63B-4 and CISA), device.md (Windows checks), incidents.md (playbooks: clicked a link, account posting spam, token leaked in a commit, lost phone, ransom note), family.md (kids' accounts, short).
- `skills/shieldwright/scripts/sw.py`, stdlib, read-only:
  - `repo PATH`: runs gitleaks if installed (history), else a built-in regex pass over `git log -p`; masked output.
  - `gh [OWNER|--all]`: gh api settings audit (table above in research); unavailable-on-plan distinct from off; Actions unpinned uses and write-all permissions from workflow files.
  - `device`: Windows checks via PowerShell, no admin; JSON.
  - `pwned`: Pwned Passwords range check reading the password from a prompt (getpass), never argv; only the 5-char prefix leaves the machine.
  - `incident NAME`: prints the ordered checklist.
- Personal account checklist goes on a decision page (yes/no per account), never asks for a secret.
- Destructive steps (filter-repo, force-push, revoking tokens) are printed as commands for the owner; the agent runs them only with explicit go-ahead.

## Order
1. sw.py repo + gh with fixture tests (session 2).
2. device, pwned, incident; SKILL.md + references (session 3).
3. evergreen-new unit, evals with baselines, README + banner, release, marketplace install.

## Rulings (decided, flagged)
- Name kept: shieldwright. A public build must hold no details of the owner's setup.
- trufflehog (AGPL) only as optional external binary, never vendored.

## Goal
Ship the plugin as scoped below.

## Status
Done: released 0.1.0 (2026-11-21); see HANDOFF.md.

## Next single action
See HANDOFF.md.
