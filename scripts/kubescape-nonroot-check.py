#!/usr/bin/env python3
import sys
import subprocess
import json
from pathlib import Path

def get_staged_yaml_files():
    """Return a list of staged YAML files (new or modified)"""
    # Modified / added files in index
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
        capture_output=True, text=True
    )
    staged = result.stdout.splitlines()

    # Newly added files not yet committed
    result_new = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard"],
        capture_output=True, text=True
    )
    new_files = result_new.stdout.splitlines()

    # Combine and filter YAML files
    files = [f for f in staged + new_files if f.endswith((".yaml", ".yml"))]
    return files

def run_kubescape(files):
    """Run Kubescape on given files with the controls-index.yaml"""
    if not files:
        print("No staged YAML files to scan with Kubescape.")
        return None

    # Path to controls-index.yaml relative to script
    script_dir = Path(__file__).resolve().parent
    controls_index = script_dir.parent / "controls-index.yaml"
    if not controls_index.exists():
        print(f"Error: controls-index.yaml not found at {controls_index}", file=sys.stderr)
        sys.exit(1)

    cmd = [
        "kubescape", "scan",
        "--controls-config", str(controls_index),
        "--format", "json",
        *files
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        # Kubescape returns non-zero on findings, ignore exit code
        return e.stdout

    return result.stdout

def parse_results(json_text):
    """Parse Kubescape JSON output and print critical findings with container info"""
    try:
        data = json.loads(json_text)
    except json.JSONDecodeError:
        print("Error: Kubescape output is not valid JSON")
        print(json_text)
        sys.exit(1)

    failed = False
    for res in data.get("resources", []):
        file_path = res.get("filePath", "?")
        for r in res.get("results", []):
            if r.get("controlID") == "C-0057" and r.get("severity", "").lower() == "critical":
                failed = True
                # Extract container name if present
                container_name = r.get("resourceName") or "unknown"
                # Extract line number from metadata if available
                line_info = r.get("ruleResponses", [{}])[0].get("line", "?")
                message = r.get("message", "Container runs as root")
                print(f"{file_path}:{line_info} [{container_name}] {message}")
    return failed

def main():
    files = get_staged_yaml_files()
    output = run_kubescape(files)
    if output is None:
        sys.exit(0)

    failed = parse_results(output)
    if failed:
        print("❌ Kubescape check failed: root containers detected.")
        sys.exit(1)
    else:
        print("✅ Kubescape check passed: no root containers found.")
        sys.exit(0)

if __name__ == "__main__":
    main()
