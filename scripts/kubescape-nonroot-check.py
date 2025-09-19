#!/usr/bin/env python3
import subprocess
import sys
import json
import tempfile
import os
import shutil
import yaml

def get_staged_yaml_files():
    """Return a list of staged YAML files."""
    try:
        staged_files = (
            subprocess.check_output(
                ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"]
            )
            .decode()
            .strip()
            .splitlines()
        )
    except subprocess.CalledProcessError as e:
        print(f"Error getting staged files: {e}", file=sys.stderr)
        return []
    return [f for f in staged_files if f.endswith((".yaml", ".yml"))]

def run_kubescape(yaml_files):
    """Run kubescape on staged YAML files."""
    tmpdir = tempfile.mkdtemp(prefix="kubescape-precommit-")
    for f in yaml_files:
        if os.path.exists(f):
            dest = os.path.join(tmpdir, os.path.basename(f))
            subprocess.run(["cp", f, dest], check=False)

    outfile = os.path.join(tmpdir, "kubescape-out.json")
    try:
        subprocess.run(
            [
                "kubescape",
                "scan",
                "framework",
                "nsa",
                "--severity-threshold",
                "critical",
                "-v",
                tmpdir,
                "--format",
                "json",
                "--output",
                outfile,
            ],
            check=True,
        )
    except subprocess.CalledProcessError as e:
        print(f"Error running kubescape: {e}", file=sys.stderr)
        return None

    try:
        with open(outfile, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"Error parsing kubescape output: {e}", file=sys.stderr)
        return None

def find_root_containers(yaml_file):
    """Return (line, text) of explicit or implicit root cases in a YAML file."""
    issues = []
    try:
        with open(yaml_file, "r") as f:
            docs = list(yaml.safe_load_all(f))
    except Exception:
        return issues

    with open(yaml_file, "r") as f:
        lines = f.readlines()

    for doc in docs:
        if not isinstance(doc, dict):
            continue
        spec = doc.get("spec", {})
        # handle Pod and Deployment-like templates
        template = spec.get("template", {}) if "template" in spec else spec
        pod_spec = template.get("spec", {})
        for c in pod_spec.get("containers", []):
            name = c.get("name", "<unnamed>")
            sc = c.get("securityContext", {})
            if "runAsUser" in sc:
                if sc["runAsUser"] == 0:
                    # Explicit root
                    for i, line in enumerate(lines, start=1):
                        if "runAsUser" in line and "0" in line:
                            issues.append((i, line.strip(), name, "explicit root"))
            else:
                # No runAsUser at all (implicit root)
                issues.append((None, "securityContext missing runAsUser (implicit root)", name, "implicit root"))
    return issues

def main():
    yaml_files = get_staged_yaml_files()
    if not yaml_files:
        print("No staged YAML files to scan with Kubescape.")
        return 0

    if not shutil.which("kubescape"):
        print("Error: kubescape CLI not found in PATH", file=sys.stderr)
        return 1

    data = run_kubescape(yaml_files)
    if data is None:
        return 1

    failed = False

    # Report Kubescape failures
    for resource in data.get("resources", []):
        for result in resource.get("results", []):
            if result.get("controlID") == "C-0057" and result.get("status") == "failed":
                failed = True
                resource_id = resource.get("resourceID", resource.get("resourceKind", "Unknown"))
                print(f"❌ Kubescape flagged resource: {resource_id}")

    # Extra check for explicit + implicit root
    for f in yaml_files:
        issues = find_root_containers(f)
        for line, text, cname, itype in issues:
            failed = True
            if line:
                print(f"❌ {f}:{line} [{cname}] -> {text} ({itype})")
            else:
                print(f"❌ {f} [{cname}] -> {text} ({itype})")

    if failed:
        print("Commit rejected due to root containers.")
        return 1

    print("✅ No containers running as root detected in staged YAML files.")
    return 0

if __name__ == "__main__":
    sys.exit(main())

