#!/usr/bin/env bash
# scripts/policy-gate.sh (adapted from Lab 3.4)
# Usage: policy-gate.sh [--workspace terraform] [--policy policies] [--evidence evidence]
# Requires a saved plan (terraform plan -out=tfplan) in the workspace.
#
# 1. Runs the policy unit tests: a policy that can't fail its own failing
#    fixtures is blind, so the gate refuses to run with it.
# 2. Evaluates every policy namespace against the plan (fails closed).
# 3. Writes machine-readable results into the evidence directory.
set -euo pipefail

POLICY_DIR="policies"
WORKSPACE="terraform"
EVIDENCE_DIR="evidence"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace) WORKSPACE="$2"; shift 2 ;;
    --policy)    POLICY_DIR="$2"; shift 2 ;;
    --evidence)  EVIDENCE_DIR="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

mkdir -p "$EVIDENCE_DIR"

echo "== Policy unit tests =="
conftest verify --policy "$POLICY_DIR" | tee "$EVIDENCE_DIR/policy-tests.txt"

echo "== Plan to JSON =="
terraform -chdir="$WORKSPACE" show -json tfplan > "$EVIDENCE_DIR/plan.json"

echo "== Policy check =="
set +e
conftest test --policy "$POLICY_DIR" --all-namespaces --output=json \
  "$EVIDENCE_DIR/plan.json" > "$EVIDENCE_DIR/conftest-results.json"
STATUS=$?
set -e

# Human-readable results in the log, so a failed PR shows the HIPAA messages
conftest test --policy "$POLICY_DIR" --all-namespaces "$EVIDENCE_DIR/plan.json" || true

if [[ $STATUS -eq 0 ]]; then
  echo "policy-gate: PASS"
else
  echo "policy-gate: FAIL (see $EVIDENCE_DIR/conftest-results.json)"
fi
exit $STATUS