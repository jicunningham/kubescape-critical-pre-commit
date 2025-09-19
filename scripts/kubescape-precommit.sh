#!/bin/bash
set -e

# -----------------------------
# Check required tools
# -----------------------------
for cmd in kubescape jq git; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Error: $cmd not found. Please install it and ensure it is on your PATH." >&2
    exit 1
  fi
done

# -----------------------------
# Only scan staged YAML files
# -----------------------------
staged=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.ya?ml$' || true)
if [[ -z "$staged" ]]; then
  echo "No staged YAML files to scan with Kubescape."
  exit 0
fi

# -----------------------------
# Use the repo's controls-index.yaml
# -----------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTROLS_INDEX="$SCRIPT_DIR/../controls-index.yaml"

if [[ ! -f "$CONTROLS_INDEX" ]]; then
  echo "Error: controls-index.yaml not found at $CONTROLS_INDEX" >&2
  exit 1
fi

# -----------------------------
# Run Kubescape scan
# -----------------------------
OUTFILE=$(mktemp)
kubescape scan --controls-config "$CONTROLS_INDEX" $staged --format json --output "$OUTFILE" || true

# -----------------------------
# Validate JSON
# -----------------------------
if ! jq empty "$OUTFILE" >/dev/null 2>&1; then
  echo "Error: Kubescape output is not valid JSON. Output below:"
  cat "$OUTFILE"
  rm "$OUTFILE"
  exit 1
fi

# -----------------------------
# Count critical findings
# -----------------------------
critical_findings=$(jq '[.resources[] | select(.results[]?.severity=="critical")] | length' "$OUTFILE")

if [[ "$critical_findings" -gt 0 ]]; then
  echo "❌ Kubescape found $critical_findings critical security issues in staged YAML files!"
  jq -r '.resources[] | select(.results[]?.severity=="critical") | "\(.name): \(.results[]?.message)"' "$OUTFILE" || true
  rm "$OUTFILE"
  exit 1
else
  echo "✅ Kubescape check passed: no critical issues in staged YAML files."
  rm "$OUTFILE"
  exit 0
fi
