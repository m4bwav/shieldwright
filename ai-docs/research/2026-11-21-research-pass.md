# shieldwright research pass (2026-11-21)

Version numbers come from search snippets; REST endpoint and Windows details are partly unverified. Pin them before building on them.

## Existing skills and servers (overlap)
- Trail of Bits skills: code audit only (static analysis, insecure defaults). No secrets, accounts or incidents.
- GitGuardian agent-skills: wraps ggshield and needs an account.
- Community gitleaks wrappers (skills.sh laurigates git-security-checks, jeremylongshore scanning-for-secrets): working-tree scans, mostly docs.
- GitHub MCP server: secret_protection / dependabot / code_security toolsets, off by default; secret scanning GA 2026-05-11 (remote server).
- Built-in /security-review: pending diff only. everkeep: dependency vulns. scamwright: incoming scams.
- Gap shieldwright fills: history scrub + rotate order, settings audit across all own repos, account/2FA hygiene, Windows device checks, incident playbooks.

## Tools (all free, run on Windows)
gitleaks 8.30.x MIT (winget/scoop) · trufflehog 3.9x AGPL-3.0 (verifies live secrets; call as an external binary only) · osv-scanner 2.5 Apache-2.0 · Scorecard 5.x Apache-2.0 · zizmor MIT (pip) for Actions · git-filter-repo >=2.47 MIT (pip) with --sensitive-data-removal · BFG GPL-3.0, Java, no longer in GitHub's guide.

## GitHub REST via gh api (verify)
- GET /repos/{o}/{r}: security_and_analysis returned only to admins.
- secret-scanning/alerts: admin; free private repos return 404 (needs Secret Protection).
- dependabot/alerts: works on private repos once alerts are on.
- vulnerability-alerts: 204 on / 404 off.
- branches/{b}/protection: admin; free private repos fail (needs Pro). rulesets readable on public.
- actions/permissions and actions/permissions/workflow: default_workflow_permissions.
A 404/403 must be reported as "not available on this plan", never as "off".

## Guidance
- NIST SP 800-63B-4 final (July 2025): length over composition, no forced rotation, check breached lists.
- CISA Secure Our World: MFA everywhere; phishing-resistant FIDO/passkeys first.
- GitHub "Removing sensitive data": rotate first, close PRs, git-filter-repo --sensitive-data-removal, force-push, Support only if rotation cannot fix; forks/clones cannot be cleaned.
- HIBP: Pwned Passwords range API (k-anonymity) free, no key. Email search needs a paid key; skip.

## Windows checks without admin (test on box)
Get-MpComputerStatus, Get-NetFirewallProfile, Microsoft.Update.Session COM QueryHistory (Get-HotFix partial). BitLocker cmdlets need admin; Shell.Application System.Volume.BitLockerProtection works without. Windows 11 Home has Device encryption only on supported hardware: report "not available".
