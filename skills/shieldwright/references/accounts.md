# Accounts, passwords, 2FA

Sources: NIST SP 800-63B-4 (final, July 2025), CISA Secure Our World, Have I Been Pwned Pwned Passwords API (checked live 2026-11-21).

## Rules to give the user
- One password manager (the browser's built-in one is fine); a unique, long password per account. Length beats symbols; no forced periodic changes; change a password when it is breached or reused.
- 2FA on every account that offers it, best first: passkey or hardware key, then authenticator app, then SMS (still better than none).
- Save recovery codes offline (printed, or in the password manager). Keep the recovery email and phone current.
- Email is the master key: it gets the strongest password and a passkey first, because every other account resets through it.

## Order of accounts
Email, password manager, phone carrier (port-out PIN), bank and payment, Apple/Google/Microsoft account, GitHub and package registries, social media, shopping.

## Doing the check
- Put one yes/no question per account on an askwright page ("2FA on?", "unique password?", "recovery codes saved?"). Never ask for the password itself.
- Breached password: the user runs `SW pwned` and types it at the hidden prompt. Only the first 5 hex chars of its SHA-1 are sent (k-anonymity, `Add-Padding` header). A hit means change it everywhere it is used.
- Breached email: point to haveibeenpwned.com in the browser; the API email search needs a paid key, so sw.py does not do it.
- GitHub: `gh auth status` shows the token scopes; review Settings, Sessions, SSH keys, Personal access tokens (delete unused, set expiry), Applications.
