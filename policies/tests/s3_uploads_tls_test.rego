package hipaa.gap03_uploads_tls_test

import rego.v1

import data.hipaa.gap03_uploads_tls as gap03

plan(resources) := {"configuration": {"root_module": {"resources": resources}}}

bucket := {"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "expressions": {}}

bucket_ref := {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]}

# Bucket policy that points at a policy document data source
bucket_policy := {
	"address": "aws_s3_bucket_policy.uploads",
	"type": "aws_s3_bucket_policy",
	"expressions": {
		"bucket": bucket_ref,
		"policy": {"references": ["data.aws_iam_policy_document.uploads_tls.json", "data.aws_iam_policy_document.uploads_tls"]},
	},
}

# Bucket policy written with jsonencode: content is opaque at plan time
bucket_policy_jsonencode := {
	"address": "aws_s3_bucket_policy.uploads",
	"type": "aws_s3_bucket_policy",
	"expressions": {
		"bucket": bucket_ref,
		"policy": {"references": ["aws_s3_bucket.uploads.arn", "aws_s3_bucket.uploads"]},
	},
}

policy_doc(statements) := {
	"address": "data.aws_iam_policy_document.uploads_tls",
	"mode": "data",
	"type": "aws_iam_policy_document",
	"expressions": {"statement": statements},
}

tls_statement := {
	"effect": {"constant_value": "Deny"},
	"actions": {"constant_value": ["s3:*"]},
	"principals": [{"type": {"constant_value": "*"}, "identifiers": {"constant_value": ["*"]}}],
	"condition": [{
		"test": {"constant_value": "Bool"},
		"variable": {"constant_value": "aws:SecureTransport"},
		"values": {"constant_value": ["false"]},
	}],
}

# Same statement, but the condition was flipped to "true"
weakened_statement := object.union(tls_statement, {"condition": [{
	"test": {"constant_value": "Bool"},
	"variable": {"constant_value": "aws:SecureTransport"},
	"values": {"constant_value": ["true"]},
}]})

# Passing fixture: the fixed capstone
test_passes_with_tls_deny if {
	count(gap03.deny) == 0 with input as plan([bucket, bucket_policy, policy_doc([tls_statement])])
}

# Failing fixtures
test_denies_starter_without_bucket_policy if {
	count(gap03.deny) == 1 with input as plan([bucket])
}

test_denies_weakened_condition if {
	count(gap03.deny) == 1 with input as plan([bucket, bucket_policy, policy_doc([weakened_statement])])
}

test_denies_opaque_jsonencode_policy if {
	count(gap03.deny) == 1 with input as plan([bucket, bucket_policy_jsonencode])
}

test_deny_message_cites_hipaa_control if {
	msgs := gap03.deny with input as plan([bucket])
	some msg in msgs
	contains(msg, "164.312(e)(1)")
}