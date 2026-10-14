package hipaa.gap01_uploads_cmk_test

import rego.v1

import data.hipaa.gap01_uploads_cmk as gap01

# Minimal fake plans: just the parts the policy reads

plan(resources) := {"configuration": {"root_module": {"resources": resources}}}

bucket := {"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "name": "uploads", "expressions": {}}

bucket_ref := {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]}

sse_cmk := {
	"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
	"type": "aws_s3_bucket_server_side_encryption_configuration",
	"expressions": {
		"bucket": bucket_ref,
		"rule": [{"apply_server_side_encryption_by_default": [{
			"sse_algorithm": {"constant_value": "aws:kms"},
			"kms_master_key_id": {"references": ["aws_kms_key.phi.arn", "aws_kms_key.phi"]},
		}]}],
	},
}

sse_s3 := {
	"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
	"type": "aws_s3_bucket_server_side_encryption_configuration",
	"expressions": {
		"bucket": bucket_ref,
		"rule": [{"apply_server_side_encryption_by_default": [{
			"sse_algorithm": {"constant_value": "AES256"},
		}]}],
	},
}

sse_kms_no_key := {
	"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
	"type": "aws_s3_bucket_server_side_encryption_configuration",
	"expressions": {
		"bucket": bucket_ref,
		"rule": [{"apply_server_side_encryption_by_default": [{
			"sse_algorithm": {"constant_value": "aws:kms"},
		}]}],
	},
}

# Passing fixture: the fixed capstone
test_passes_with_cmk if {
	count(gap01.deny) == 0 with input as plan([bucket, sse_cmk])
}

# Failing fixtures: each way the gap can exist
test_denies_starter_without_encryption_config if {
	count(gap01.deny) == 1 with input as plan([bucket])
}

test_denies_sse_s3 if {
	count(gap01.deny) == 1 with input as plan([bucket, sse_s3])
}

test_denies_kms_without_customer_key if {
	count(gap01.deny) == 1 with input as plan([bucket, sse_kms_no_key])
}

test_deny_message_cites_hipaa_control if {
	msgs := gap01.deny with input as plan([bucket])
	some msg in msgs
	contains(msg, "164.312(a)(2)(iv)")
}