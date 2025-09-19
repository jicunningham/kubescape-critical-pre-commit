#!/usr/bin/env python3
import subprocess
import sys
from pathlib import Path
import yaml
import json

class LineLoader(yaml.SafeLoader):
    """YAML loader that keeps track of line numbers."""
    def construct_mapping(self, node, deep=False):
        mapping = super().construct_mapping(node, deep=deep)
        mapping['__line__'] = node.start_mark.line + 1  # 1-indexed
        return mapping

def get_staged_yaml_files():
    """Return staged YAML files"""
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
        capture_output=True,
        text=True,
    )
    return [f for f in result.stdout.splitlines() if f.endswith((".yaml", ".yml"))]

def parse_yaml_with_lines(file_path):
    """Return list of docs with line numbers"""
    try:
        with open(file_path) as f:
            docs = list(yaml.load_all(f, Loader=LineLoader))
            return docs
    except Exception as e:
        return [{"__line__": 1, "parse_error": str(e)}]

def check_root_containers(file_path):
    """Return list of root container issues with file name and line numbers"""
    issues = []
    docs = parse_yaml_with_lines(file_path)
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        spec = doc.get("spec", {})
        containers = spec.get("containers", [])
        for container in containers:
            sc = container.get("securityContext", {})
            line_num = container.get("__line__", 0)
            cname = container.get("name", "<unknown>")
            if sc.get("runAsUser") == 0:
                issues.append(f"{file_path}:{line_num}: container '{cname}' explicitly runs as root")
            elif "runAsUser" not in sc:
                issues.append(f"{file_path}:{line_num}: container '{cname}' implicitly runs as root")
    return issues

def run_kubescape(files):
    """Run Kubescape NSA framework on files and return JSON output"""
    if not files:
        return {}
    try:
        result = subprocess.run(
            ["kubescape", "scan", "framework", "NSA"] + files + ["--format", "json"],
            capture_output=True,
            text=True,
            check=False  # Don't fail immediately
        )
        return json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        print("⚠️ Kubescape output is not valid JSON. Raw output below:\n")
        print(result.stdout)
        return {}

def map_resources_to_files(yaml_files):
    """Create a mapping of (kind, metadata.name) -> (file_path, line)"""
    mapping = {}
    for f in yaml_files:
        docs = parse_yaml_with_lines(f)
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            kind = doc.get("kind")
            name = doc.get("metadata", {}).get("name")
            line = doc.get("__line__", 0)
            if kind and name:
                mapping[(kind, name)] = (f, line)
    return mapping

def parse_kubescape_critical(json_data, resource_map):
    """Return list of critical/high findings with file and line numbers"""
    issues = []
    resources = json_data.get("resources", [])
    for res in resources:
        kind = res.get("kind")
        name = res.get("name")
        results = res.get("results", [])
        file_line = resource_map.get((kind, name), ("<unknown file>", 0))
        for r in results:
            severity = r.get("severity", "").lower()
            if severity in ["critical", "high"]:
                control = r.get("controlName", "<unknown>")
                issues.append(f"{file_line[0]}:{file_line[1]}: Kubescape {severity.upper()} issue in resource '{name}' [{control}]")
    return issues

def main():
    yaml_files = get_staged_yaml_files()
    if not yaml_files:
        print("No staged YAML files to scan.")
        sys.exit(0)

    all_issues = []
    # Check root containers
    for f in yaml_files:
        all_issues.extend(check_root_containers(f))

    # Map resources to files for line reporting
    resource_map = map_resources_to_files(yaml_files)

    # Run Kubescape NSA framework
    ks_output = run_kubescape(yaml_files)
    all_issues.extend(parse_kubescape_critical(ks_output, resource_map))

    if all_issues:
        print("❌ Security issues found:")
        for issue in all_issues:
            print(f" - {issue}")
        sys.exit(1)
    else:
        print("✅ All checks passed: no root containers or critical Kubescape findings.")
        sys.exit(0)

if __name__ == "__main__":
    main()

