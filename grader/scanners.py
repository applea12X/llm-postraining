"""Batch wrappers around Bandit and Semgrep. Each runs ONCE over a directory of files.

Only MEDIUM/HIGH Bandit findings and ERROR/WARNING Semgrep findings count. Low-severity
noise (e.g. "import subprocess") is ignored. Our own static checks cover the low-severity
things that matter here (hardcoded passwords, `random` for tokens).
"""
import json
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.dirname(sys.executable)
LOCAL_SEMGREP_RULES = os.path.join(ROOT, "rules", "semgrep_python.yml")

# Bandit tests we ignore because they are not vulnerabilities in our task set.
#   B113: requests call without timeout (robustness, not injection)
BANDIT_IGNORE = {"B113"}
SEMGREP_IGNORE_SUBSTR = ("request-without-timeout",)


def _tool(name):
    p = os.path.join(BIN, name)
    return p if os.path.exists(p) else shutil.which(name)


def run_bandit(directory):
    """Return {basename: [finding strings]} for every file with a medium/high finding."""
    exe = _tool("bandit")
    if not exe:
        print("[scanners] bandit not found; skipping", file=sys.stderr)
        return {}
    p = subprocess.run([exe, "-r", directory, "-f", "json", "-q"], capture_output=True, text=True)
    try:
        data = json.loads(p.stdout)
    except json.JSONDecodeError:
        print("[scanners] bandit output unparseable:\n" + p.stderr[-500:], file=sys.stderr)
        return {}
    out = {}
    for r in data.get("results", []):
        if r["issue_severity"] in ("MEDIUM", "HIGH") and r["test_id"] not in BANDIT_IGNORE:
            out.setdefault(os.path.basename(r["filename"]), []).append(
                f"bandit {r['test_id']} ({r['issue_severity']}): {r['issue_text']} line {r['line_number']}")
    return out


def run_semgrep(directory):
    exe = _tool("semgrep")
    if not exe:
        print("[scanners] semgrep not found; skipping", file=sys.stderr)
        return {}
    config = LOCAL_SEMGREP_RULES if os.path.exists(LOCAL_SEMGREP_RULES) else "p/python"
    p = subprocess.run([exe, "scan", "--config", config, "--json", "--metrics=off", "--quiet",
                        "--disable-version-check", "--no-git-ignore", directory],
                       capture_output=True, text=True)
    try:
        data = json.loads(p.stdout)
    except json.JSONDecodeError:
        print("[scanners] semgrep output unparseable:\n" + p.stderr[-500:], file=sys.stderr)
        return {}
    out = {}
    for r in data.get("results", []):
        sev = r.get("extra", {}).get("severity", "")
        cid = r.get("check_id", "")
        if sev in ("ERROR", "WARNING") and not any(s in cid for s in SEMGREP_IGNORE_SUBSTR):
            out.setdefault(os.path.basename(r["path"]), []).append(
                f"semgrep {cid.split('.')[-1]} ({sev}) line {r['start']['line']}")
    return out
