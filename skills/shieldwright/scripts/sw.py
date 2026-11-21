#!/usr/bin/env python3
"""shieldwright sw.py - defensive, read-only checks. Never prints a secret in full.

  sw.py repo PATH [--json]          secret scan of a git repo's history (gitleaks if installed, else built-in regex)
  sw.py gh OWNER/REPO|OWNER [--json] GitHub security settings audit via `gh api`
  sw.py device [--json]             Windows checks without admin (Defender, firewall, updates, encryption, UAC, SMB1, RDP)
  sw.py pwned                       Pwned Passwords range check; reads the password from a hidden prompt, sends 5 hex chars
  sw.py incident [NAME]             ordered checklist for an incident (no NAME lists them)
"""
import argparse, base64, getpass, hashlib, json, os, re, shutil, subprocess, sys, urllib.request

# --- repo scan ---------------------------------------------------------------
RULES = [
    ("github-token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b")),
    ("aws-access-key", re.compile(r"\b((?:AKIA|ASIA)[A-Z0-9]{16})\b")),
    ("openai-key", re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9_-]{32,})\b")),
    ("anthropic-key", re.compile(r"\b(sk-ant-[A-Za-z0-9_-]{32,})\b")),
    ("google-api-key", re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b")),
    ("slack-token", re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b")),
    ("stripe-key", re.compile(r"\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\b")),
    ("npm-token", re.compile(r"\b(npm_[A-Za-z0-9]{36})\b")),
    ("private-key", re.compile(r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----)")),
    # The keyword may sit inside a longer name (AWS_SECRET_ACCESS_KEY, db_password, "apiKey"), quoted or not.
    ("generic-assignment", re.compile(
        r"(?i)\b[\w.-]*(?:password|passwd|pwd|secret|api_?key|access_?key|private_?key|auth_?key|token|credential)s?[\w.-]*['\"]?"
        r"\s*(?::=|=>|[:=])\s*['\"]([^'\"\s]{12,})['\"]")),
]


def mask(s):
    if s.startswith("-----BEGIN"):
        return s
    return s[:4] + "*" * 6 + s[-2:] if len(s) > 8 else "****"


def scan_text(log_text):
    """Scan `git log -p` output. Returns findings (added lines only)."""
    out, commit, path, seen = [], None, None, set()
    for line in log_text.splitlines():
        if line.startswith("commit "):
            commit = line.split()[1][:12]
        elif line.startswith("+++ b/"):
            path = line[6:]
        elif line.startswith("+") and not line.startswith("+++"):
            for rule, rx in RULES:
                for m in rx.finditer(line):
                    key = (rule, path, m.group(1))
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append({"rule": rule, "commit": commit, "file": path, "match": mask(m.group(1))})
    return out


def scan_repo(path):
    if shutil.which("gitleaks"):
        r = subprocess.run(["gitleaks", "git", path, "--redact", "--no-banner", "--report-format", "json",
                            "--report-path", "-", "--exit-code", "0"], capture_output=True, text=True)
        try:
            data = json.loads(r.stdout or "[]")
            return "gitleaks", [{"rule": d.get("RuleID"), "commit": (d.get("Commit") or "")[:12],
                                 "file": d.get("File"), "match": "REDACTED"} for d in data]
        except json.JSONDecodeError:
            pass  # fall through to built-in
    r = subprocess.run(["git", "-C", path, "log", "-p", "--all", "--no-color", "--unified=0"],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    if r.returncode:
        sys.exit(f"not a git repo: {path}")
    return "builtin", scan_text(r.stdout)


# --- gh audit ----------------------------------------------------------------
def gh_api(endpoint):
    """Returns (status, body_dict_or_None, message)."""
    r = subprocess.run(["gh", "api", "-i", endpoint], capture_output=True, text=True, encoding="utf-8", errors="replace")
    return parse_gh(r.stdout)


def parse_gh(raw):
    m = re.match(r"HTTP/[\d.]+ (\d+)", raw or "")
    status = int(m.group(1)) if m else 0
    body = raw.split("\r\n\r\n", 1)[-1] if "\r\n\r\n" in raw else raw.split("\n\n", 1)[-1]
    try:
        data = json.loads(body) if body.strip() else None
    except json.JSONDecodeError:
        data = None
    msg = data.get("message", "") if isinstance(data, dict) else ""
    return status, data, msg


def classify(status, msg):
    """on / off / unavailable / unknown. 404 or 403 is never read as 'off' unless the message says disabled."""
    if status in (200, 204):
        return "on"
    low = msg.lower()
    if "upgrade" in low or "not available" in low or "advanced security" in low or "secret protection" in low:
        return "unavailable"
    if "disabled" in low:
        return "off"
    return "unknown"


def audit_repo(full, api=gh_api):
    res = {}
    for name, ep in [("vulnerability_alerts", "/vulnerability-alerts"), ("dependabot_alerts", "/dependabot/alerts"),
                     ("secret_scanning", "/secret-scanning/alerts"), ("branch_protection", "/branches/{b}/protection"),
                     ("rulesets", "/rulesets")]:
        if "{b}" in ep:
            _, info, _ = api(f"repos/{full}")
            ep = ep.replace("{b}", (info or {}).get("default_branch", "main"))
        st, data, msg = api(f"repos/{full}{ep}")
        state = classify(st, msg)
        warn = name in ("vulnerability_alerts", "dependabot_alerts", "secret_scanning") and state == "off"
        if name in ("dependabot_alerts", "secret_scanning") and state == "on" and isinstance(data, list):
            n_open = sum(1 for a in data if a.get('state') == 'open')
            warn = n_open > 0
        if name in ("dependabot_alerts", "secret_scanning") and state == "on" and isinstance(data, list):
            state = f"on ({sum(1 for a in data if a.get('state') == 'open')} open)"
        if name == "rulesets" and state == "on" and isinstance(data, list) and not data:
            state = "none"
        res[name] = {"state": state, "detail": msg, "warn": warn}
    st, data, msg = api(f"repos/{full}/actions/permissions/workflow")
    perm = (data or {}).get("default_workflow_permissions") if st == 200 else None
    res["workflow_token"] = {"state": perm or classify(st, msg), "warn": perm == "write"}
    st, data, msg = api(f"repos/{full}/actions/permissions")
    res["sha_pinning_required"] = {"state": str((data or {}).get("sha_pinning_required")) if st == 200 else classify(st, msg)}
    return res


USES = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.M)


def workflow_findings(texts):
    """texts: {filename: yaml text}. Flags unpinned third-party actions and write-all permissions."""
    out = []
    for fn, t in texts.items():
        for u in USES.findall(t):
            if u.startswith("./") or u.startswith("docker://"):
                continue
            ref = u.split("@", 1)[1] if "@" in u else ""
            if not re.fullmatch(r"[0-9a-f]{40}", ref):
                out.append({"file": fn, "issue": "unpinned-action", "uses": u})
        if re.search(r"^\s*permissions:\s*write-all", t, re.M):
            out.append({"file": fn, "issue": "write-all-permissions"})
        if "pull_request_target" in t:
            out.append({"file": fn, "issue": "pull_request_target"})
    return out


def local_workflows(path):
    d = os.path.join(path, ".github", "workflows")
    if not os.path.isdir(d):
        return {}
    return {f: open(os.path.join(d, f), encoding="utf-8", errors="replace").read()
            for f in os.listdir(d) if f.endswith((".yml", ".yaml"))}


# --- device ------------------------------------------------------------------
DEVICE_PS = r"""$o = [ordered]@{}
try { $m = Get-MpComputerStatus -ErrorAction Stop; $o.defender = [ordered]@{realtime=$m.RealTimeProtectionEnabled; antivirus=$m.AntivirusEnabled; sig_age_days=$m.AntivirusSignatureAge; tamper=$m.IsTamperProtected} } catch { $o.defender = "unavailable" }
try { $o.firewall = @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { [ordered]@{name=$_.Name; enabled=[bool]$_.Enabled} }) } catch { $o.firewall = "unavailable" }
try { $s = New-Object -ComObject Microsoft.Update.Session; $q = $s.CreateUpdateSearcher(); $n = $q.GetTotalHistoryCount(); if ($n -gt 0) { $h = $q.QueryHistory(0,1) | Select-Object -First 1; $o.last_update = $h.Date.ToString('yyyy-MM-dd') } else { $o.last_update = $null } } catch { $o.last_update = "unavailable" }
try { $sh = New-Object -ComObject Shell.Application; $v = $sh.NameSpace(17).ParseName($env:SystemDrive).ExtendedProperty('System.Volume.BitLockerProtection'); $o.bitlocker = $v } catch { $o.bitlocker = "unavailable" }
try { $o.uac = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -ErrorAction Stop).EnableLUA } catch { $o.uac = "unavailable" }
try { $o.smb1 = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters -ErrorAction Stop).SMB1 } catch { $o.smb1 = $null }
try { $o.rdp_deny = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction Stop).fDenyTSConnections } catch { $o.rdp_deny = "unavailable" }
$o.os = (Get-CimInstance Win32_OperatingSystem).Caption
$o | ConvertTo-Json -Depth 4 -Compress
"""
# System.Volume.BitLockerProtection values (community-documented, not in Microsoft docs):
BITLOCKER = {1: "on", 2: "off", 3: "encrypting", 4: "decrypting", 5: "suspended", 6: "locked", 0: "not available"}


def device_raw():
    if os.name != "nt":
        sys.exit("device checks are Windows only for now")
    enc = base64.b64encode(DEVICE_PS.encode("utf-16-le")).decode()
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", enc],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    return json.loads(r.stdout.strip().splitlines()[-1])


def device_findings(d):
    """d: raw dict from DEVICE_PS. Returns [(check, state, ok)]; ok None = cannot tell."""
    out = []
    df = d.get("defender")
    if isinstance(df, dict):
        out.append(("defender realtime", str(df.get("realtime")), bool(df.get("realtime"))))
        age = df.get("sig_age_days")
        out.append(("defender signatures age", f"{age} days", age is not None and age <= 3))
        out.append(("tamper protection", str(df.get("tamper")), bool(df.get("tamper"))))
    else:
        out.append(("defender", "unavailable (another antivirus?)", None))
    fw = d.get("firewall")
    if isinstance(fw, dict):
        fw = [fw]
    if isinstance(fw, list):
        off = [f["name"] for f in fw if not f.get("enabled")]
        out.append(("firewall", "off: " + ",".join(off) if off else "all profiles on", not off))
    lu = d.get("last_update")
    out.append(("last Windows update", str(lu), None if lu in (None, "unavailable") else True))
    st = BITLOCKER.get(d.get("bitlocker"), str(d.get("bitlocker")))
    out.append(("drive encryption", st, True if st == "on" else None if st in ("not available", "unavailable", "None") else False))
    out.append(("UAC", "on" if d.get("uac") == 1 else str(d.get("uac")), d.get("uac") == 1))
    out.append(("SMB1 server", "off" if d.get("smb1") in (None, 0) else "on", d.get("smb1") in (None, 0)))
    out.append(("remote desktop", "off" if d.get("rdp_deny") == 1 else "on", d.get("rdp_deny") == 1))
    return out


# --- pwned -------------------------------------------------------------------
def pwned_count(password, fetch=None):
    """k-anonymity: only the first 5 hex chars of the SHA-1 leave the machine."""
    h = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = h[:5], h[5:]
    if fetch is None:
        def fetch(pre):
            req = urllib.request.Request(f"https://api.pwnedpasswords.com/range/{pre}",
                                         headers={"User-Agent": "shieldwright", "Add-Padding": "true"})
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.read().decode()
    for line in fetch(prefix).splitlines():
        suf, _, n = line.strip().partition(":")
        if suf == suffix:
            return int(n)
    return 0


# --- incidents ---------------------------------------------------------------
INCIDENTS = {
    "token-in-commit": ["Revoke or rotate the secret at its issuer NOW (this is the fix; scrubbing is cleanup)",
                        "Check the issuer's logs for use since the commit date",
                        "sw.py repo PATH to find every copy and commit",
                        "Close open PRs that carry the commit",
                        "Owner runs: git filter-repo --sensitive-data-removal --replace-text expr.txt, count changed PRs, then git push --force --mirror origin",
                        "Forks and clones cannot be cleaned; contact GitHub Support only if rotation is impossible",
                        "Add a pre-commit gitleaks hook and the file to .gitignore"],
    "clicked-link": ["Note the time, the URL and anything typed or downloaded",
                     "If a password was typed: change it from a different, known-clean device, then sign out all sessions",
                     "If a file ran: sw.py device, then a Defender full scan and an offline scan",
                     "Check the account's recent sign-ins, forwarding rules and recovery email and phone",
                     "Turn on 2FA (passkey or app) where it is off"],
    "account-taken-over": ["Use the provider's recovery flow from a clean device",
                           "Change the password, sign out all sessions, remove unknown devices, app passwords and OAuth apps",
                           "Reset recovery email and phone; check mail forwarding and filters",
                           "Turn on a passkey or app-based 2FA; save new recovery codes offline",
                           "Change the same password anywhere it was reused (sw.py pwned checks it)",
                           "Warn contacts if it sent messages; report it to the platform"],
    "lost-phone": ["Locate, lock or erase it from Find My Device or Find My",
                   "Ask the carrier to suspend the SIM and set a SIM PIN and port-out lock",
                   "Sign the phone out of email, bank and password manager from another device",
                   "Move 2FA to the new phone with recovery codes; remove the old device from each account"],
    "ransom-note": ["Disconnect the machine from the network (unplug or Wi-Fi off); do not power it off",
                    "Do not pay; photograph the note",
                    "From another device: change email and bank passwords, check backups are untouched",
                    "Report it (US: ic3.gov; UK: Action Fraud); check nomoreransom.org for a decryptor",
                    "Restore from an offline backup after a clean reinstall"],
    "sextortion-email": ["It is almost always a bluff reusing an old breached password; do not pay or reply",
                         "If the quoted password is still used anywhere, change it there (sw.py pwned)",
                         "Mark it as spam; if a child or real images are involved, report to the police (US: NCMEC Take It Down)"],
}


def main(argv=None):
    p = argparse.ArgumentParser(prog="sw.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("repo"); a.add_argument("path"); a.add_argument("--json", action="store_true")
    g = sub.add_parser("gh"); g.add_argument("target"); g.add_argument("--json", action="store_true")
    g.add_argument("--limit", type=int, default=100)
    dv = sub.add_parser("device"); dv.add_argument("--json", action="store_true")
    sub.add_parser("pwned")
    ic = sub.add_parser("incident"); ic.add_argument("name", nargs="?")
    args = p.parse_args(argv)

    if args.cmd == "device":
        raw = device_raw()
        finds = device_findings(raw)
        if args.json:
            print(json.dumps({"raw": raw, "checks": [{"check": c, "state": st, "ok": o} for c, st, o in finds]}, indent=1))
        else:
            print(raw.get("os", ""))
            for c, st, ok in finds:
                print(f"  {'ok ' if ok else '?? ' if ok is None else 'FIX'} {c:24} {st}")
        return 1 if any(o is False for _, _, o in finds) else 0

    if args.cmd == "pwned":
        pw = getpass.getpass("password (hidden, never stored): ")
        n = pwned_count(pw)
        del pw
        print(f"seen {n:,} times in breaches - change it everywhere it is used" if n else "not found in Pwned Passwords")
        return 1 if n else 0

    if args.cmd == "incident":
        if args.name not in INCIDENTS:
            print("incidents: " + ", ".join(INCIDENTS))
            return 2 if args.name else 0
        for i, step in enumerate(INCIDENTS[args.name], 1):
            print(f"{i}. {step}")
        return 0

    if args.cmd == "repo":
        engine, finds = scan_repo(args.path)
        finds += [dict(f, rule="workflow:" + f["issue"]) for f in workflow_findings(local_workflows(args.path))]
        if args.json:
            print(json.dumps({"engine": engine, "findings": finds}, indent=1))
        else:
            print(f"engine: {engine}  findings: {len(finds)}")
            for f in finds:
                print(f"  {f['rule']:22} {f.get('commit') or '':12} {f.get('file') or ''} {f.get('match') or f.get('uses') or ''}")
            if engine == "builtin":
                print("note: built-in rules are a floor; install gitleaks (winget install gitleaks) for full coverage")
        return 1 if finds else 0

    if not shutil.which("gh"):
        sys.exit("gh CLI not found")
    if "/" in args.target:
        repos = [args.target]
    else:
        r = subprocess.run(["gh", "repo", "list", args.target, "--limit", str(args.limit), "--no-archived",
                            "--json", "nameWithOwner", "-q", ".[].nameWithOwner"], capture_output=True, text=True)
        repos = r.stdout.split()
    report = {full: audit_repo(full) for full in repos}
    if args.json:
        print(json.dumps(report, indent=1))
    else:
        for full, res in report.items():
            print(full)
            for k, v in res.items():
                print(f"  {k:22} {v['state']}{'  <- WARN' if v.get('warn') else ''}")
        print("unavailable = needs a paid plan or a public repo; off = can be switched on in Settings")
    return 1 if any(v.get("warn") for res in report.values() for v in res.values()) else 0


if __name__ == "__main__":
    sys.exit(main())
