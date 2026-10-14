package hipaa.gap04_uploads_versioning_test

import rego.v1

import data.hipaa.gap04_uploads_versioning as gap04

plan(resources) := {"configuration": {"root_module": {"resources": resources}}}

bucket := {"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "expressions": {}}

versioning(status) := {
	"address": "aws_s3_bucket_versioning.uploads",
	"type": "aws_s3_bucket_versioning",
	"expressions": {
		"bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]},
		"versioning_configuration": [{"status": {"constant_value": status}}],
	},
}

# Passing fixture
test_passes_when_enabled if {
	count(gap04.deny) == 0 with input as plan([bucket, versioning("Enabled")])
}

# Failing fixtures
test_denies_starter_without_versioning if {
	count(gap04.deny) == 1 with input as plan([bucket])
}

test_denies_suspended if {
	count(gap04.deny) == 1 with input as plan([bucket, versioning("Suspended")])
}

test_deny_message_cites_hipaa_control if {
	msgs := gap04.deny with input as plan([bucket])
	some msg in msgs
	contains(msg, "164.308(a)(7)")
}