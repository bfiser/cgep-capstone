#!/usr/bin/env bash
# scripts/verify-evidence.sh <run_id> [--vault <bucket>] [--profile <p>]
# (adapted from Lab 4.4)
#
# Verifies one pipeline run's evidence bundle three ways:
#   1. Integrity:    SHA-256 matches the stored hash and the receipt
#   2. Authenticity: Cosign signature from THIS repo's grc-gate.yml on main,
#                    verified against the public Sigstore transparency log
#   3. Preservation: Object Lock retention is still active
set -euo pipefail

RUN_ID="${1:?usage: verify-evidence.sh <run_id> [--vault <bucket>] [--profile <p>]}"
shift || true
VAULT="${EVIDENCE_VAULT:-}"
PROFILE_ARG=""
EXPECTED_IDENTITY="https://github.com/bfiser/cgep-capstone/.github/workflows/grc-gate.yml@refs/heads/main"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vault)   VAULT="$2"; shift 2 ;;
    --profile) PROFILE_ARG="--profile $2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done
[[ -z "$VAULT" ]] && { echo "Set --vault or EVIDENCE_VAULT"; exit 2; }

if command -v sha256sum >/dev/null 2>&1; then SHASUM="sha256sum"
elif command -v shasum >/dev/null 2>&1; then SHASUM="shasum -a 256"
else echo "Need sha256sum or shasum" >&2; exit 2; fi

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT; cd "$WORK"
PREFIX="runs/${RUN_ID}"

aws $PROFILE_ARG s3 cp "s3://${VAULT}/${PREFIX}/" . --recursive \
  --exclude "*" --include "evidence-*.tar.gz*" --include "receipt.json"

BUNDLE=$(ls evidence-*.tar.gz | head -1)

# 1. Integrity: recompute and compare against the stored hash AND the receipt
ACTUAL=$($SHASUM "${BUNDLE}" | awk '{print $1}')
STORED=$(cat "${BUNDLE}.sha256")
RECEIPT=$(jq -r .sha256 receipt.json)
[[ "$ACTUAL" == "$STORED" ]]  || { echo "FAIL: SHA does not match stored hash"; exit 1; }
[[ "$ACTUAL" == "$RECEIPT" ]] || { echo "FAIL: SHA does not match receipt"; exit 1; }
echo "1. Integrity:    OK  sha256=${ACTUAL}"

# 2. Authenticity: signed by this repo's workflow on main, logged in Rekor
cosign verify-blob \
  --bundle "${BUNDLE}.sig.bundle" \
  --certificate-identity "${EXPECTED_IDENTITY}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "${BUNDLE}"
echo "2. Authenticity: OK  signer=${EXPECTED_IDENTITY}"

# 3. Preservation: Object Lock retention still in the future
RETAIN_UNTIL=$(aws $PROFILE_ARG s3api get-object-retention \
  --bucket "${VAULT}" --key "${PREFIX}/${BUNDLE}" \
  --query 'Retention.RetainUntilDate' --output text)
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
[[ "$RETAIN_UNTIL" > "$NOW" ]] || { echo "FAIL: retention expired"; exit 1; }
echo "3. Preservation: OK  retained until ${RETAIN_UNTIL}"

echo "CHAIN INTACT for run ${RUN_ID}"