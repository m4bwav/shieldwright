# Changelog

## 0.1.1 (2026-11-21)
- Fix: the built-in scanner's generic rule now catches a keyword inside a longer name (`AWS_SECRET_ACCESS_KEY = "..."`, `db_password: '...'`, `"apiKey": "..."`, `GITHUB_TOKEN="..."`, `private_key => '...'`); before, the word-boundary check missed them. Regression tests added.
- `.claude-plugin/marketplace.json`, so `/plugin marketplace add m4bwav/shieldwright` works.
- `pytest.ini` limits collection to `tests/`, so the eval fixture is not collected.
- README: install commands, a link to the wiki, how to run the tests with pytest.

## 0.1.0 (2026-11-21)
- First release: hub skill `shieldwright` with references (repo-leak, accounts, device, incidents, family) and `sw.py` (repo: masked secret scan of history, gitleaks when installed; gh: repo security settings audit; device: Windows checks; pwned: k-anonymity breached-password check behind a hidden prompt; incident: ordered playbooks).
- Eval suite of four cases with no-skill baselines; the leak fixture is built at run time.
