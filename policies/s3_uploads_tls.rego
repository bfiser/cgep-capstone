# METADATA
# title: GAP-03 - Uploads bucket denies non-TLS requests
# description: "aws_s3_bucket.uploads must have a bucket policy that denies all S3 actions, for all principals, when aws:SecureTransport is false."
# custom:
#   gap_id: GAP-03
#   control_id: "164.312(e)(1)"
#   framework: hipaa-security-rule
#   severity: high
#   remediation: "Attach an aws_s3_bucket_policy to aws_s3_bucket.uploads whose policy is an aws_iam_policy_document with a Deny on s3:* for principal * when aws:SecureTransport is false."
package hipaa.gap03_uploads_tls

import rego.v1

uploads := "aws_s3_bucket.uploads"

uploads_refs := {uploads, sprintf("%s.id", [uploads]), sprintf("%s.bucket", [uploads])}

resources := input.configuration.root_module.resources

uploads_present if {
	some r in resources
	r.address == uploads
}

# Bucket policies attached to the uploads bucket
bucket_policies contains r if {
	some r in resources
	r.type == "aws_s3_bucket_policy"
	some ref in r.expressions.bucket.references
	ref in uploads_refs
}

# A statement that denies all S3 actions to everyone when TLS is not used
tls_deny(st) if {
	st.effect.constant_value == "Deny"
	"s3:*" in st.actions.constant_value
	some p in st.principals
	"*" in p.identifiers.constant_value
	some c in st.condition
	c.test.constant_value == "Bool"
	c.variable.constant_value == "aws:SecureTransport"
	"false" in c.values.constant_value
}

# The bucket policy's document is a policy document data source
# (verifiable at plan time) containing a TLS-deny statement
enforces_tls(bp) if {
	some ref in bp.expressions.policy.references
	some doc in resources
	doc.type == "aws_iam_policy_document"
	doc.address == ref
	some st in doc.expressions.statement
	tls_deny(st)
}

deny contains msg if {
	uploads_present
	count(bucket_policies) == 0
	msg := "[HIPAA 164.312(e)(1)] GAP-03 aws_s3_bucket.uploads: no bucket policy, so non-TLS requests are not denied. Remediation: attach a bucket policy that denies s3:* when aws:SecureTransport is false."
}

deny contains msg if {
	some bp in bucket_policies
	not enforces_tls(bp)
	msg := sprintf("[HIPAA 164.312(e)(1)] GAP-03 %s: no verifiable TLS-deny statement. Remediation: author the policy as an aws_iam_policy_document with a Deny on s3:* for principal * when aws:SecureTransport is false.", [bp.address])
}