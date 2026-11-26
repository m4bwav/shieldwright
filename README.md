![shieldwright](.github/images/banner.jpg)

# shieldwright

Defensive security for one person and their family, as an agent plugin. It finds secrets leaked in your git history and walks you through rotating and scrubbing them, audits your GitHub repos' security settings, checks a Windows PC, tells you whether a password is in a breach without the password leaving your machine, and gives ordered playbooks for "I think I got hacked".

Defensive only: it checks what you own and refuses attack tooling.

## Install

```
/plugin marketplace add m4bwav/shieldwright
/plugin install shieldwright@shieldwright
```

Needs Python 3.9+. `gh` (logged in) for the settings audit; gitleaks is used when installed.

Full documentation is on the [wiki](https://github.com/m4bwav/shieldwright/wiki): getting started, every `sw.py` command, the incident playbooks, FAQ.

## Ask it

- "I committed my API key, did I leak it?"
- "Audit my repos' security settings"
- "Is my PC secure?"
- "Was my password breached?"
- "I clicked a phishing link", "my account got hacked", "I lost my phone"
- "Set up 2FA for the family"

## sw.py

Standard library only, read-only. Exit 1 means findings (for `gh`: vulnerability alerts, Dependabot alerts or secret scanning off, open alerts, or a write-default workflow token; each is marked WARN).

| Command | Does |
|---|---|
| `sw.py repo PATH` | secret scan of the whole history, masked output |
| `sw.py gh OWNER/REPO` or `OWNER` | secret scanning, push protection, Dependabot, branch rules, Actions permissions |
| `sw.py device` | Windows: Defender, firewall, BitLocker, updates and more |
| `sw.py pwned` | hidden prompt; sends 5 hex chars of the SHA-1 to Pwned Passwords |
| `sw.py incident [NAME]` | ordered steps for token-in-commit, clicked-link, account-taken-over, lost-phone, ransom-note, sextortion-email |

The agent never runs history rewrites, force-pushes or revocations itself; it prints them for you.

## Tests

`python -m pytest` or `python -m unittest discover -s tests`; skill evals in [evals/evals.json](evals/evals.json), results in [TESTS.md](TESTS.md).

## License

MIT, see [LICENSE](LICENSE). Security reports: [SECURITY.md](SECURITY.md).
