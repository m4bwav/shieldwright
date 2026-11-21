#!/usr/bin/env python3
"""shieldwright sw.py - defensive, read-only checks. Never prints a secret in full.

  sw.py repo PATH [--json]          secret scan of a git repo's history (gitleaks if installed, else built-in regex)
  sw.py gh OWNER/REPO|OWNER [--json] GitHub security settings audit via `gh api`
"""
import argparse, json, os, re, shutil, subprocess, sys

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
    ("generic-assignment", re.compile(r"(?i)\b(?:password|passwd|secret|api_?key|token)\b\s*[:=]\s*['\"]([^'\"\s]{12,})['\"]")),
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
        if name in ("dependabot_alerts", "secret_scanning") and state == "on" and isinstance(data, list):
            state = f"on ({sum(1 for a in data if a.get('state') == 'open')} open)"
        if name == "rulesets" and state == "on" and isinstance(data, list) and not data:
            state = "none"
        res[name] = {"state": state, "detail": msg}
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


def main(argv=None):
    p = argparse.ArgumentParser(prog="sw.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("repo"); a.add_argument("path"); a.add_argument("--json", action="store_true")
    g = sub.add_parser("gh"); g.add_argument("target"); g.add_argument("--json", action="store_true")
    g.add_argument("--limit", type=int, default=100)
    args = p.parse_args(argv)

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
    return 0


if __name__ == "__main__":
    sys.exit(main())
