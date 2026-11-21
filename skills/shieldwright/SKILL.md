---
name: shieldwright
description: "Defensive security for one person and their family: secrets leaked in a git repo (find, rotate, scrub history), GitHub repo security settings, account and 2FA hygiene, Windows device checks, breached-password check, and 'I think I got hacked' playbooks. sw.py repo, gh, device, pwned, incident (read-only). Use on 'did I leak a key', 'I committed my API key', 'audit my repos' security', 'is my PC secure', 'was my password breached', 'I clicked a phishing link', 'my account got hacked', 'lost my phone', 'set up 2FA for the family'. Defensive only: no attack tooling, scanning others' systems or cracking. Not for dependency bumps (everkeep) or Windows shell quirks (quirkwright)."
---

# Shieldwright

Keep one person's code, accounts, machines and family safe, and walk them through it when something goes wrong.

## Hard rules

1. **Defensive only.** Check the user's own repos, accounts and machines. Refuse attack tooling, scanning systems they do not own, password cracking, phishing kits or getting into someone else's account; offer the defensive version instead.
2. **Never ask for, print or store a secret.** Findings are reported by type and location, masked. A password to check goes through `sw.py pwned` (hidden prompt, only 5 hex chars of its SHA-1 leave the machine), never chat or argv.
3. **Rotate before scrub.** A leaked secret is fixed at its issuer; history rewriting is cleanup.
4. **The owner runs destructive steps.** `git filter-repo`, force-push, revoking tokens, wiping a device and changing account settings are printed as commands or steps; the agent runs one only on explicit go-ahead in this conversation.
5. **Unavailable is not off.** A GitHub feature that needs a paid plan is reported as unavailable, never as switched off.

`SW` below means `python "<this folder>/scripts/sw.py"` (stdlib, Python 3.9+). Exit 1 means findings.

## Routes

| Ask | Do | Reference |
|---|---|---|
| leaked key, secret in a commit, scan my repo | `SW repo PATH`, then rotate and scrub | [repo-leak](references/repo-leak.md) |
| audit my repos' security settings | `SW gh OWNER/REPO` or `SW gh OWNER` | [repo-leak](references/repo-leak.md) |
| accounts, passwords, 2FA, password manager | checklist; per-account answers on an askwright page | [accounts](references/accounts.md) |
| is my PC secure | `SW device` | [device](references/device.md) |
| was this password breached | `SW pwned` (the user types it, not the agent) | [accounts](references/accounts.md) |
| clicked a link, hacked account, lost phone, ransom note, sextortion email, token in a commit | `SW incident NAME`, then walk it step by step | [incidents](references/incidents.md) |
| kids' accounts, family devices | short checklist | [family](references/family.md) |

In an incident, act first and explain after: give step 1 at once, then the rest in order. Ask what has already been done before repeating it.

Neighbours: Dependabot and PR triage are everkeep; Windows shell and process quirks are quirkwright; installing gitleaks or gh is evergreen-setup.

## Maintenance

Evergreen unit at the repository root: `evergreen.json`, RESEARCH.md, CHANGELOG.md, LEARNINGS.md, TESTS.md (evals in `evals/`). Refresh every 30 days; check volatile facts (GitHub endpoints, filter-repo flags, BitLocker values) against their docs before relying on them.
