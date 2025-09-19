#!/usr/bin/env python3
import subprocess
import sys
import json
import os

def get_staged_yaml_files():
    """Get staged YAML files"""
    output = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
        capture_output=True,
        text=True
    )
    files = [f for f in output.stdout.splitlines() if f.endswith((".yaml", ".yml"))]
    return files

def scan_file(file_path):
    """Run kubescape scan for a single file using NSA framework"""
    try:
        result = subprocess.run(
            ["kubescape", "scan", "framework", "nsa", file_path, "--format", "json"],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        # kubescape returns non-zero on failed scan, still captures output
        return e.stdout

def main():
    files = get_staged_yaml_files()
    if not files:
        print("No staged YAML files to scan.")
        sys.exit(0)

    has_critical = False

    for f in files:
        output = scan_file(f)
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            print(f"❌ Kubescape output for {f} is not valid JSON.")
            print(output)
            has_critical = True
            continue

        # Traverse JSON for critical findings
        for resource in data.get("resources", []):
            for result in resource.get("results", []):
                if result.get("severity", "").lower() == "critical":
                    print(f"❌ Critical issue in {f}: {result.get('message')}")
                    has_critical = True

    if has_critical:
        sys.exit(1)
    else:
        print("✅ Kubescape NSA check passed: no critical issues.")
        sys.exit(0)

if __name__ == "__main__":
    main()
