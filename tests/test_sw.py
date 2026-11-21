import os, subprocess, sys, tempfile, unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skills", "shieldwright", "scripts"))
import sw  # noqa: E402

FAKE_GH = "ghp_" + "a1B2c3D4e5" * 4  # built at runtime so this file holds no literal token


class Scan(unittest.TestCase):
    def test_masks_and_locates(self):
        log = f"commit abcdef1234567890\n+++ b/app.py\n+TOKEN = '{FAKE_GH}'\n"
        f = sw.scan_text(log)
        self.assertTrue(any(x["rule"] == "github-token" and x["file"] == "app.py" for x in f))
        self.assertNotIn(FAKE_GH, repr(f))

    def test_key_assignments_inside_longer_names(self):
        val = "wJalrXUtnFEMI" + "K7MDENGbPxRfiCY"  # built at runtime
        for line in (f'AWS_SECRET_ACCESS_KEY = "{val}"', f"db_password: '{val}'",
                     f'"apiKey": "{val}"', f'export GITHUB_TOKEN="{val}"', f"private_key => '{val}'"):
            f = sw.scan_text(f"commit 1\n+++ b/x\n+{line}\n")
            self.assertTrue(any(x["rule"] == "generic-assignment" for x in f), line)
            self.assertNotIn(val, repr(f))

    def test_short_or_unquoted_values_ignored(self):
        self.assertEqual(sw.scan_text("commit 1\n+++ b/x\n+password = 'short'\n+token = os.environ['X']\n"), [])

    def test_removed_lines_ignored(self):
        self.assertEqual(sw.scan_text(f"commit 1\n+++ b/a\n-{FAKE_GH}\n"), [])

    def test_real_git_history(self):
        with tempfile.TemporaryDirectory() as d:
            run = lambda *a: subprocess.run(["git", "-C", d, *a], capture_output=True, check=True)
            run("init", "-q"); run("config", "user.email", "t@t"); run("config", "user.name", "t")
            open(os.path.join(d, "k.txt"), "w").write("-----BEGIN OPENSSH PRIVATE KEY-----\n")
            run("add", "."); run("commit", "-qm", "a")
            os.remove(os.path.join(d, "k.txt")); run("commit", "-qam", "rm")
            engine, f = sw.scan_repo(d)
            if engine == "builtin":
                self.assertEqual([x["rule"] for x in f], ["private-key"])


class Gh(unittest.TestCase):
    def test_classify(self):
        self.assertEqual(sw.classify(404, "Vulnerability alerts are disabled."), "off")
        self.assertEqual(sw.classify(403, "Upgrade to GitHub Pro or make this repository public to enable this feature."), "unavailable")
        self.assertEqual(sw.classify(204, ""), "on")
        self.assertEqual(sw.classify(404, "Not Found"), "unknown")

    def test_parse_gh(self):
        st, data, msg = sw.parse_gh('HTTP/2.0 403 Forbidden\r\nX: y\r\n\r\n{"message":"Dependabot alerts are disabled for this repository."}')
        self.assertEqual((st, sw.classify(st, msg)), (403, "off"))

    def test_audit_with_fake_api(self):
        answers = {
            "repos/o/r": (200, {"default_branch": "main"}, ""),
            "repos/o/r/vulnerability-alerts": (204, None, ""),
            "repos/o/r/dependabot/alerts": (200, [{"state": "open"}, {"state": "fixed"}], ""),
            "repos/o/r/secret-scanning/alerts": (404, {}, "Secret scanning is disabled on this repository."),
            "repos/o/r/branches/main/protection": (403, {}, "Upgrade to GitHub Pro or make this repository public to enable this feature."),
            "repos/o/r/rulesets": (200, [], ""),
            "repos/o/r/actions/permissions/workflow": (200, {"default_workflow_permissions": "write"}, ""),
            "repos/o/r/actions/permissions": (200, {"sha_pinning_required": False}, ""),
        }
        r = sw.audit_repo("o/r", api=lambda ep: answers[ep])
        self.assertEqual(r["dependabot_alerts"]["state"], "on (1 open)")
        self.assertEqual(r["secret_scanning"]["state"], "off")
        self.assertEqual(r["branch_protection"]["state"], "unavailable")
        self.assertEqual(r["rulesets"]["state"], "none")
        self.assertTrue(r["workflow_token"]["warn"])
        self.assertTrue(r["secret_scanning"]["warn"])
        self.assertTrue(r["dependabot_alerts"]["warn"])
        self.assertFalse(r["vulnerability_alerts"]["warn"])
        self.assertFalse(r["branch_protection"]["warn"])

    def test_gh_exit_codes(self):
        from unittest import mock
        ok = {"vulnerability_alerts": {"state": "on", "warn": False}, "workflow_token": {"state": "read", "warn": False}}
        bad = {"secret_scanning": {"state": "off", "warn": True}}
        with mock.patch.object(sw.shutil, "which", return_value="gh"), mock.patch("sys.stdout"):
            with mock.patch.object(sw, "audit_repo", return_value=ok):
                self.assertEqual(sw.main(["gh", "o/r"]), 0)
            with mock.patch.object(sw, "audit_repo", return_value=bad):
                self.assertEqual(sw.main(["gh", "o/r"]), 1)

    def test_workflow_findings(self):
        sha = "a" * 40
        t = f"permissions: write-all\non: pull_request_target\njobs:\n x:\n  steps:\n   - uses: actions/checkout@v4\n   - uses: o/a@{sha}\n   - uses: ./local\n"
        issues = sorted(x["issue"] for x in sw.workflow_findings({"ci.yml": t}))
        self.assertEqual(issues, ["pull_request_target", "unpinned-action", "write-all-permissions"])


if __name__ == "__main__":
    unittest.main()


class Device(unittest.TestCase):
    def test_findings(self):
        raw = {"defender": {"realtime": True, "sig_age_days": 9, "tamper": True},
               "firewall": [{"name": "Public", "enabled": False}], "last_update": "2026-11-01",
               "bitlocker": 2, "uac": 1, "smb1": 1, "rdp_deny": 0}
        f = {c: ok for c, _, ok in sw.device_findings(raw)}
        self.assertFalse(f["defender signatures age"]); self.assertFalse(f["firewall"])
        self.assertFalse(f["drive encryption"]); self.assertFalse(f["SMB1 server"]); self.assertFalse(f["remote desktop"])
        self.assertTrue(f["UAC"])

    def test_unknowns_not_failures(self):
        f = {c: ok for c, _, ok in sw.device_findings({"defender": "unavailable", "bitlocker": 0, "uac": 1, "rdp_deny": 1})}
        self.assertIsNone(f["defender"]); self.assertIsNone(f["drive encryption"])


class Pwned(unittest.TestCase):
    def test_only_prefix_sent(self):
        sent = []
        body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3\r\n0000000000000000000000000000000000A:1"
        n = sw.pwned_count("password", fetch=lambda pre: sent.append(pre) or body)
        self.assertEqual((sent, n), (["5BAA6"], 3))
        self.assertEqual(sw.pwned_count("not-in-list-xyz", fetch=lambda pre: body), 0)


class Incident(unittest.TestCase):
    def test_listing_and_unknown(self):
        self.assertEqual(sw.main(["incident"]), 0)
        self.assertEqual(sw.main(["incident", "nope"]), 2)
        self.assertEqual(sw.main(["incident", "token-in-commit"]), 0)
