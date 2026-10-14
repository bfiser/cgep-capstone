package hipaa.gap02_dynamodb_cmk_test

import rego.v1

import data.hipaa.gap02_dynamodb_cmk as gap02

plan(resources) := {"configuration": {"root_module": {"resources": resources}}}

table(expressions) := {
	"address": "aws_dynamodb_table.intake",
	"type": "aws_dynamodb_table",
	"expressions": expressions,
}

cmk_sse := {"server_side_encryption": [{
	"enabled": {"constant_value": true},
	"kms_key_arn": {"references": ["aws_kms_key.phi.arn", "aws_kms_key.phi"]},
}]}

aws_managed_sse := {"server_side_encryption": [{
	"enabled": {"constant_value": true},
}]}

disabled_sse := {"server_side_encryption": [{
	"enabled": {"constant_value": false},
	"kms_key_arn": {"references": ["aws_kms_key.phi.arn", "aws_kms_key.phi"]},
}]}

# Passing fixture: the fixed capstone
test_passes_with_cmk if {
	count(gap02.deny) == 0 with input as plan([table(cmk_sse)])
}

# Failing fixtures
test_denies_starter_without_sse_block if {
	count(gap02.deny) == 1 with input as plan([table({})])
}

test_denies_aws_managed_key if {
	count(gap02.deny) == 1 with input as plan([table(aws_managed_sse)])
}

test_denies_encryption_disabled if {
	count(gap02.deny) == 1 with input as plan([table(disabled_sse)])
}

test_deny_message_cites_hipaa_control if {
	msgs := gap02.deny with input as plan([table({})])
	some msg in msgs
	contains(msg, "164.312(a)(2)(iv)")
}