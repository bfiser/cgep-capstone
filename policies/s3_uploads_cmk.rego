# METADATA
# title: GAP-01 - Uploads bucket encrypted with a customer-managed KMS key
# description: "aws_s3_bucket.uploads must use SSE-KMS with a customer-managed key, not AWS-managed SSE-S3."
# custom:
#   gap_id: GAP-01
#   framework: hipaa
#   control_id: "164.312(a)(2)(iv)"
#   controls:
#     - "164.312(a)(2)(iv)"
#   severity: high
#   remediation: "Add aws_s3_bucket_server_side_encryption_configuration for aws_s3_bucket.uploads with sse_algorithm = \"aws:kms\" and kms_master_key_id set to a customer-managed key."
package hipaa.gap01_uploads_cmk

import rego.v1

uploads := "aws_s3_bucket.uploads"

uploads_refs := {uploads, sprintf("%s.id", [uploads]), sprintf("%s.bucket", [uploads])}

resources := input.configuration.root_module.resources

uploads_present if {
	some r in resources
	r.address == uploads
}

# Encryption configs that point at the uploads bucket
sse_configs contains r if {
	some r in resources
	r.type == "aws_s3_bucket_server_side_encryption_configuration"
	some ref in r.expressions.bucket.references
	ref in uploads_refs
}

# aws:kms with a key referenced from Terraform (e.g. aws_kms_key.phi.arn)
uses_cmk(r) if {
	some rule in r.expressions.rule
	some d in rule.apply_server_side_encryption_by_default
	d.sse_algorithm.constant_value == "aws:kms"
	count(d.kms_master_key_id.references) > 0
}

# aws:kms with a key ARN typed in directly
uses_cmk(r) if {
	some rule in r.expressions.rule
	some d in rule.apply_server_side_encryption_by_default
	d.sse_algorithm.constant_value == "aws:kms"
	d.kms_master_key_id.constant_value != ""
}

deny contains msg if {
	uploads_present
	count(sse_configs) == 0
	msg := "[HIPAA 164.312(a)(2)(iv)] GAP-01 aws_s3_bucket.uploads: no encryption configuration, so it defaults to AWS-managed SSE-S3. Remediation: add an SSE-KMS configuration using a customer-managed key."
}

deny contains msg if {
	some r in sse_configs
	not uses_cmk(r)
	msg := sprintf("[HIPAA 164.312(a)(2)(iv)] GAP-01 %s: uploads bucket is not SSE-KMS with a customer-managed key. Remediation: set sse_algorithm = \"aws:kms\" and kms_master_key_id to a customer-managed key.", [r.address])
}