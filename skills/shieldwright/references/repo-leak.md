# Repo leaks and GitHub settings

Checked 2026-11-21 against GitHub's "Removing sensitive data from a repository" page and live `gh api` calls.

## Find
- `SW repo PATH` scans every commit on every ref. With gitleaks installed (`winget install gitleaks`, MIT) it uses gitleaks with `--redact`; without it, a built-in regex floor (GitHub, AWS, OpenAI, Anthropic, Google, Slack, Stripe, npm tokens, private keys, quoted password/secret/token assignments). It also flags workflow files: unpinned third-party actions, `permissions: write-all`, `pull_request_target`.
- trufflehog (AGPL-3.0) can verify whether a found secret is still live; use it only as a separate binary the owner installs.

## Fix, in order
1. Rotate or revoke the secret at its issuer. Check the issuer's logs for use since the commit date. If rotation is done, rewriting history may not be needed.
2. Owner rewrites a fresh clone with git-filter-repo 2.47 or later (`pip install git-filter-repo`):
   - whole file: `git-filter-repo --sensitive-data-removal --invert-paths --path PATH` (one `--path` per old name)
   - strings: `git-filter-repo --sensitive-data-removal --replace-text ../passwords.txt`
3. Verify with `SW repo .` again.
4. Count touched PRs: `grep -c '^refs/pull/.*/head$' .git/filter-repo/changed-refs`. Stop if higher than expected: the next step cannot be undone.
5. `git push --force --mirror origin` (refs/pull failures are expected; other failures usually mean branch protection must be paused).
6. GitHub Support, with the repo, the PR count and the "First Changed Commit(s)", for cached views and PR refs.
7. Collaborators rebase, never merge, old branches. Forks and other clones cannot be cleaned: that is why step 1 matters.
8. Prevent: a gitleaks pre-commit hook, `.env` in `.gitignore`.

## Settings audit (`SW gh`)
Reports per repo: vulnerability alerts, Dependabot alerts (open count), secret scanning, branch protection, rulesets, default workflow token permission (warn on write), SHA pinning required.
- Free private repos: secret scanning and branch protection come back unavailable (need a paid plan or a public repo). Say so; do not tell the user to switch them on.
- Off but available: vulnerability alerts and Dependabot alerts (Settings, Code security), workflow token (Settings, Actions, General, read-only).
- Status code alone cannot tell off from unavailable; sw.py reads the message text.
