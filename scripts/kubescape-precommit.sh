#!/bin/bash
set -e

# Check for required tools
if ! command -v kubescape >/dev/null 2>&1; then
  echo "Error: kubescape CLI not found. Please install it and ensure it is on your PATH." >&2
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "Error: jq not found. Please install jq and ensure it is on your PATH." >&2
  exit 1
fi

# Only scan staged YAML files
staged=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.ya?ml$' || true)

if [[ -z "$staged" ]]; then
  echo "No staged YAML files to scan with Kubescape."
  exit 0
fi

# Fetch the latest controls from your remote repo
RULES_REPO_URL="https://github.com/jicunningham/kubescape-critical-pre-commit"
RULES_LOCAL_DIR="/tmp/kubescape-critical-controls"
rm -rf "$RULES_LOCAL_DIR"
git clone --depth=1 "$RULES_REPO_URL" "$RULES_LOCAL_DIR"

# Run Kubescape scan on staged YAML files with custom controls
kubescape scan "$RULES_LOCAL_DIR/controls-index.yaml" $staged --output json > /tmp/kubescape-out.json

# Check for critical issues in the output
critical_findings=$(jq '[ .resources[] | select(.results[]?.severity=="critical") ] | length' /tmp/kubescape-out.json)

if [[ "$critical_findings" -gt 0 ]]; then
  echo "Kubescape found critical security issues in staged YAML files! Commit rejected."
  exit 1
else
  echo "Kubescape check passed: no critical issues in staged YAML files."
  exit 0
fi
