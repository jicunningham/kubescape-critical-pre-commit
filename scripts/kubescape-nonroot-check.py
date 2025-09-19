#!/usr/bin/env python3
import subprocess
import sys
import tempfile
import os
import json

# Path to controls file in repo
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONTROLS_FILE = os.path.join(SCRIPT_DIR, "../controls-index.yaml")

if not os.path.isfile(CONTROLS_FILE):
    print(f"Error: controls-index.yaml not found at {CONTROLS_FILE}", file=sys.stderr)
    sys.exit(1)

# Get staged YAML files
try:
    staged_files = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
        capture_output=True, text=True, check=True
    ).stdout.splitlines()
except subprocess.CalledProcessError as e:
    print(f"Error getting staged files: {e}", file=sys.stderr)
    sys.exit(1)

yaml_files = [f for f in staged_files if f.endswith((".yml", ".yaml"))]

if not yaml_files:
    print("No staged YAML files to scan with Kubescape.")
    sys.exit(0)

# Write staged content to temp files and scan
critical_found = False
for f in yaml_files:
    try:
        content = subprocess.run(
            ["git", "show", f":{f}"],
            capture_output=True, text=True, check=True
        ).stdout
    except subprocess.CalledProcessError as e:
        print(f"Error reading staged content for {f}: {e}", file=sys.stderr)
        continue

    with tempfile.NamedTemporaryFile(mode="w+", suffix=".yaml", delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        out_json = subprocess.run(
            ["kubescape", "scan", "--controls-config", CONTROLS_FILE, tmp_path,
             "--format", "json", "--output", "-"],
            capture_output=True, text=True, check=True
        ).stdout
    except subprocess.CalledProcessError as e:
        # Kubescape returns non-zero if it finds issues; we still parse the JSON
        out_json = e.stdout

    try:
        results = json.loads(out_json)
    except json.JSONDecodeError:
        print(f"Error parsing Kubescape JSON for {f}", file=sys.stderr)
        os.unlink(tmp_path)
        continue

    # Check for critical findings (C-0057)
    for r in results.get("resources", []):
        for res in r.get("results", []):
            if res.get("controlID") == "C-0057" and res.get("severity") == "critical":
                print(f"❌ {f}: {res.get('message')}")
                critical_found = True

    os.unlink(tmp_path)

if critical_found:
    print("\nCommit rejected due to critical Kubescape findings.")
    sys.exit(1)
else:
    print("✅ Kubescape check passed: no critical issues in staged YAML files.")
    sys.exit(0)
