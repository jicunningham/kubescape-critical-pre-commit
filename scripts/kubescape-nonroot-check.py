#!/usr/bin/env python3
import sys
import subprocess
import json
import tempfile
from pathlib import Path

def get_staged_yaml_files():
    """Return a list of staged YAML files (new or modified)"""
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
        capture_output=True, text=True
    )
    staged = result.stdout.splitlines()
    # Include new files not yet committed
    result_new = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard"],
        capture_output=True, text=True
    )
    new_files = result_new.stdout.splitlines()
    files = [f for f in staged + new_files if f.endswith((".yaml", ".yml"))]
    return files

def write_staged_to_temp(file_path):
    """Get staged version of file and write to a temporary file"""
    result = subprocess.run(
        ["git", "show", f":{file_path}"],
        capture_output=True, text=True, check=True
    )
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".yaml")
    tmp.write(result.stdout.encode())
    tmp.close()
    return tmp.name

def run_kubescape(temp_files):
    """Run Kubescape on temp files with controls-index.yaml"""
    script_dir = Path(__file__).resolve().parent
    controls_index = script_dir.parent / "controls-index.yaml"
    if not controls_index.exists():
        print(f"Error: controls-index.yaml not found at {controls_index}", file=sys.stderr)
        sys.exit(1)

    cmd = [
        "kubescape", "scan",
        "--controls-config", str(controls_index),
        "--format", "json",
        *temp_files
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        # Kubescape returns non-zero on findings, ignore exit code
        return e.stdout
    return result.stdout

def parse_results(json_text, file_map):
    """Parse Kubescape JSON output and print critical findings with container info"""
    try:
        data = json.loads(json_text)
    except json.JSONDecodeError:
        print("Error: Kubescape output is not valid JSON")
        print(json_text)
        sys.exit(1)

    failed = False
    for res in data.get("resources", []):
        # Map temp file back to original staged file
        temp_file = Path(res.get("filePath", "?")).resolve()
        original_file = file_map.get(temp_file, "?")
        for r in res.get("results", []):
            if r.get("controlID") == "C-0057" and r.get("severity", "").lower() == "critical":
                failed = True
                container_name = r.get("resourceName") or "unknown"
                # Line number from Kubescape if available
                line_info = r.get("ruleResponses", [{}])[0].get("line", "?")
                message = r.get("message", "Container runs as root")
                print(f"{original_file}:{line_info} [{container_name}] {message}")
    return failed

def main():
    files = get_staged_yaml_files()
    if not files:
        print("No staged YAML files to scan with Kubescape.")
        sys.exit(0)

    temp_files_map = {}
    temp_files = []
    for f in files:
        tmp = write_staged_to_temp(f)
        temp_files.append(tmp)
        temp_files_map[Path(tmp).resolve()] = f

    output = run_kubescape(temp_files)

    # Clean up temp files
    for tmp in temp_files:
        Path(tmp).unlink()

    failed = parse_results(output, temp_files_map)
    if failed:
        print("❌ Kubescape check failed: root containers detected.")
        sys.exit(1)
    else:
        print("✅ Kubescape check passed: no root containers found.")
        sys.exit(0)

if __name__ == "__main__":
    main()
