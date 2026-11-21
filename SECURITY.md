# Security

Report a vulnerability through GitHub's private vulnerability reporting on this repository (Security tab, "Report a vulnerability"). Please do not open a public issue.

shieldwright is read-only. `sw.py` reads a git repo's history, calls `gh api` with your own login, reads Windows security settings, and sends only the first 5 characters of a password's SHA-1 to the Pwned Passwords range API. It never stores a secret, never rewrites history and never changes a setting; destructive steps are printed for you to run.
