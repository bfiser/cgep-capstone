# METADATA
# title: GAP-04 - Uploads bucket versioning enabled
# description: "aws_s3_bucket.uploads must have versioning enabled so overwritten or deleted PHI is recoverable."
# custom:
#   gap_id: GAP-04
#   framework: hipaa
#   control_id: "164.308(a)(7)"
#   controls:
#     - "164.308(a)(7)"
#   severity: medium
#   remediation: "Add aws_s3_bucket_versioning for aws_s3_bucket.uploads with versioning_configuration { status = \"Enabled\" }."
package hipaa.gap04_uploads_versioning

import rego.v1

uploads := "aws_s3_bucket.uploads"

uploads_refs := {uploads, sprintf("%s.id", [uploads]), sprintf("%s.bucket", [uploads])}

resources := input.configuration.root_module.resources

uploads_present if {
	some r in resources
	r.address == uploads
}

# Versioning resources that point at the uploads bucket
versioning_configs contains r if {
	some r in resources
	r.type == "aws_s3_bucket_versioning"
	some ref in r.expressions.bucket.references
	ref in uploads_refs
}

versioning_enabled(r) if {
	some vc in r.expressions.versioning_configuration
	vc.status.constant_value == "Enabled"
}

deny contains msg if {
	uploads_present
	count(versioning_configs) == 0
	msg := "[HIPAA 164.308(a)(7)] GAP-04 aws_s3_bucket.uploads: versioning not configured, so overwritten or deleted PHI is unrecoverable. Remediation: add aws_s3_bucket_versioning with status = \"Enabled\"."
}

deny contains msg if {
	some r in versioning_configs
	not versioning_enabled(r)
	msg := sprintf("[HIPAA 164.308(a)(7)] GAP-04 %s: versioning status is not Enabled. Remediation: set versioning_configuration { status = \"Enabled\" }.", [r.address])
}