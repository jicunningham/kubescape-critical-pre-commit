#!/usr/bin/env python3
import os
import subprocess
import sys

def get_staged_yaml_files():
    """Return a list of staged YAML files."""
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            check=True,
            capture_output=True,
            text=True,
        )
        files = [f.strip() for f in result.stdout.splitlines() if f.endswith((".yaml", ".yml"))]
        return files
    except subprocess.CalledProcessError:
        return []

def main():
    staged_files = get_staged_yaml_files()
    if not staged_files:
        print("No staged YAML files to scan with Kubescape.")
        sys.exit(0)

    # Kubescape controls path relative to this script
    script_dir = os.path.dirname(os.path.realpath(__file__))
    controls_index = os.path.join(script_dir, "../controls-index.yaml")

    if not os.path.isfile(controls_index):
        print(f"Error: controls-index.yaml not found at {controls_index}")
        sys.exit(1)

    # Run Kubescape
    cmd = [
        "kubescape",
        "scan",
        "--controls-config",
        controls_index,
        "--format",
        "json",
    ] + staged_files

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        print("Error: kubescape CLI not found. Install and ensure it is on PATH.")
        sys.exit(1)

    if not result.stdout.strip():
        print("Kubescape did not produce any output.")
        sys.exit(1)

    # Parse results
    import json
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        print("Error: Kubescape output is not valid JSON:")
        print(result.stdout)
        sys.exit(1)

    # Count critical findings
    critical_findings = [
        r for r in data.get("resources", [])
        if any(res.get("severity") == "critical" for res in r.get("results", []))
    ]

    if critical_findings:
        print(f"❌ Kubescape found {len(critical_findings)} critical issues in staged YAML files!")
        for r in critical_findings:
            for res in r.get("results", []):
                if res.get("severity") == "critical":
                    print(f"{r.get('name')}: {res.get('message')}")
        sys.exit(1)
    else:
        print("✅ Kubescape check passed: no critical issues in staged YAML files.")
        sys.exit(0)

if __name__ == "__main__":
    main()
