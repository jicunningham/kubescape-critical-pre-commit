#!/usr/bin/env python3
import subprocess
import sys
import json

def get_staged_yaml_files():
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
        capture_output=True,
        text=True,
    )
    return [f for f in result.stdout.splitlines() if f.endswith((".yaml", ".yml"))]

def run_kubescape(files):
    if not files:
        print("No staged YAML files to scan with Kubescape.")
        return 0, "{}"

    cmd = [
        "kubescape",
        "scan",
        "framework",
        "nsa",
        *files,
        "--format",
        "json",
    ]
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return completed.returncode, completed.stdout
    except FileNotFoundError:
        print("Error: kubescape CLI not found. Install it and ensure it's on PATH.", file=sys.stderr)
        sys.exit(1)

def check_critical_findings(json_output):
    data = json.loads(json_output)
    critical = [
        res
        for res in data.get("resources", [])
        for r in res.get("results", [])
        if r.get("severity") == "critical"
    ]
    return critical

def main():
    yaml_files = get_staged_yaml_files()
    retcode, output = run_kubescape(yaml_files)
    critical_issues = check_critical_findings(output)

    if critical_issues:
        print(f"❌ Kubescape found {len(critical_issues)} critical issues:")
        for issue in critical_issues:
            print(f"- {issue.get('message')} ({issue.get('resourceID')})")
        sys.exit(1)
    else:
        print("✅ Kubescape check passed: no critical issues.")
        sys.exit(0)

if __name__ == "__main__":
    main()
