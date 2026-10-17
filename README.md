# Acme Health: CGE-P Capstone

Governed fork of [`GRCEngClub/cgep-app-starter`](https://github.com/GRCEngClub/cgep-app-starter). The Patient Intake API handles ePHI, so the primary framework is the **HIPAA Security Rule**. The starter's resources are unchanged in purpose and still deployable; the GRC controls are wrapped around them.

- **Design reasoning, trade-offs, and gaps:** [WRITEUP.md](WRITEUP.md)
- **The named gaps:** [GAPS.md](GAPS.md)

| Layer | Where |
|---|---|
| 1. Terraform baseline | `terraform/` (`kms.tf`, `hardening.tf`, `evidence-vault.tf`, `cloudtrail.tf`, `oidc-trust.tf`, `backend.tf`) |
| 2. Policy suite | `policies/` (7 policies) and `policies/tests/` (37 tests) |
| 3. Pipeline | `.github/workflows/grc-gate.yml`, `scripts/policy-gate.sh`, `scripts/verify-evidence.sh` |
| 4. OSCAL | `oscal/components/acme-health-intake.json`, `oscal/profiles/cge-p-minimum.json` |

## Prerequisites

To run the verification steps: `git`, `jq`, `unzip`, [OPA](https://www.openpolicyagent.org/docs/latest/#running-opa), [Cosign](https://docs.sigstore.dev/cosign/system_config/installation/), and Python 3 with `compliance-trestle` (`pip install compliance-trestle`). Steps 2 and 6 also need the AWS CLI with access to the deployment account. Versions used: OPA 1.21, Conftest 0.71, Terraform 1.16.4, Cosign v2.2.4 in the pipeline (v3 verifies the same bundles), trestle 5.2.0. In the commands below, replace `<aws-profile>` with the name of your AWS CLI profile (often `default`).

## Grader verification

### 1. Policies

```bash
opa test policies -v
# expect: PASS: 37/37
```

In the pipeline, `scripts/policy-gate.sh` runs the same policies with Conftest against each Terraform plan. To see a real result without AWS access, open the **Policy check** step on red PR #16's run: it shows Conftest failing GAP-07 with a HIPAA 164.312(a)(1) message. To run Conftest against a plan yourself, see [Planning in another AWS account](#planning-in-another-aws-account).

### 2. Evidence chain (with access to the deployment account)

```bash
bash scripts/verify-evidence.sh 38632599567 \
  --vault acme-health-intake-evidence-80633ffe \
  --profile <aws-profile>
# expect: CHAIN INTACT for run 38632599567
```

Runs three checks: SHA-256 against the stored hash and the receipt, Cosign signature against the public Sigstore log (identity pinned to this repo's `grc-gate.yml` on `main`), and active Object Lock retention.

Run 38632599567 is the merge of PR #19 (commit 86b36db), the same run traced in WRITEUP.md and cited by the OSCAL component.

### 3. Evidence chain (without AWS access)

Every merge's run artifact (`grc-evidence-<run id>`) contains the signed bundle, its hash, its signature, and a receipt. Download it from the run's **Summary** page, unzip, then:

```bash
BUNDLE=$(ls evidence-*.tar.gz)
sha256sum "$BUNDLE"; cat "$BUNDLE.sha256"; jq -r .sha256 receipt.json   # all three match
cosign verify-blob --bundle "$BUNDLE.sig.bundle" \
  --certificate-identity "https://github.com/bfiser/cgep-capstone/.github/workflows/grc-gate.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "$BUNDLE"
# expect: Verified OK
jq -r .retain_until receipt.json   # Object Lock date recorded at upload
```

This path proves integrity and authenticity. Live retention can only be confirmed from the vault (path 2).

### 4. OSCAL

Trestle requires a workspace; this keeps it out of the repo (`.trestle-work/` is gitignored):

```bash
mkdir .trestle-work && cd .trestle-work && trestle init
mkdir -p component-definitions/acme-health-intake profiles/cge-p-minimum
cp ../oscal/components/acme-health-intake.json component-definitions/acme-health-intake/component-definition.json
cp ../oscal/profiles/cge-p-minimum.json profiles/cge-p-minimum/profile.json
trestle validate -a
# expect: VALID for both models
```

Catalog source is NIST SP 800-66 Rev. 2 (no official HIPAA OSCAL catalog exists); each requirement carries its 164.x citation, Terraform addresses, Rego package, and an `s3://` link to a signed bundle.

### 5. The gate has teeth

- **Green PR:** [#15](https://github.com/bfiser/cgep-capstone/pull/15) enabled DynamoDB point-in-time recovery. Passed the gate, merged, applied by the pipeline, evidence signed and uploaded.
- **Red PR:** [#16](https://github.com/bfiser/cgep-capstone/pull/16) grants the Lambda `dynamodb:*` (GAP-07). Failed the gate with a HIPAA 164.312(a)(1) violation; merge blocked by the required check. Left open as evidence.

### 6. The workload still runs

```bash
make test AWS_PROFILE=<aws-profile>
# expect: "status": "received"
```

## Planning in another AWS account

`backend.tf` uses this project's private state bucket. To plan from your own account, override it with local state (Terraform merges `*_override.tf` files over the main configuration):

```bash
cat > terraform/backend_override.tf <<'EOF'
terraform {
  backend "local" {}
}
EOF
cd terraform && terraform init && terraform plan -out=tfplan
terraform show -json tfplan > ../plan.json && cd ..
conftest test plan.json --policy policies --all-namespaces
```

The OIDC roles look up an existing GitHub OIDC provider (`token.actions.githubusercontent.com`); the plan expects one in the account.

## Pipeline

`grc-gate.yml` runs **Plan → Policy check → Apply → Sign → Upload**. Pull requests run the first two with a read-only OIDC role; merges to `main` run all five with a main-only apply role. A repository ruleset requires a PR and a passing `grc-gate` check for `main`, with no bypass.

Repository variables: `AWS_PLAN_ROLE_ARN`, `AWS_APPLY_ROLE_ARN`, `EVIDENCE_VAULT`.

## Do not run `make destroy`

The vault (Object Lock, deletion-deny policy) and the CloudTrail bucket (`force_destroy = false`) are designed to resist deletion, so a full destroy would fail partway. Teardown needs an ordered, manual process.