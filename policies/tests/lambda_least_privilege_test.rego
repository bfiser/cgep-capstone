package hipaa.gap07_lambda_least_privilege_test

import rego.v1

import data.hipaa.gap07_lambda_least_privilege as gap07

plan(resources) := {"configuration": {"root_module": {"resources": resources}}}

role := {"address": "aws_iam_role.lambda", "type": "aws_iam_role", "expressions": {}}

role_ref := {"references": ["aws_iam_role.lambda.id", "aws_iam_role.lambda"]}

role_policy := {
	"address": "aws_iam_role_policy.lambda_inline",
	"type": "aws_iam_role_policy",
	"expressions": {
		"role": role_ref,
		"policy": {"references": ["data.aws_iam_policy_document.lambda_inline.json", "data.aws_iam_policy_document.lambda_inline"]},
	},
}

role_policy_jsonencode := {
	"address": "aws_iam_role_policy.lambda_inline",
	"type": "aws_iam_role_policy",
	"expressions": {
		"role": role_ref,
		"policy": {"references": ["aws_dynamodb_table.intake.arn", "aws_dynamodb_table.intake"]},
	},
}

doc(statements) := {
	"address": "data.aws_iam_policy_document.lambda_inline",
	"mode": "data",
	"type": "aws_iam_policy_document",
	"expressions": {"statement": statements},
}

stmt(effect, actions) := {
	"effect": {"constant_value": effect},
	"actions": {"constant_value": actions},
	"resources": {"references": ["aws_dynamodb_table.intake.arn"]},
}

least_privilege := [
	stmt("Allow", ["dynamodb:PutItem"]),
	stmt("Allow", ["s3:PutObject"]),
	stmt("Allow", ["kms:Decrypt", "kms:GenerateDataKey"]),
]

# Passing fixtures
test_passes_least_privilege if {
	count(gap07.deny) == 0 with input as plan([role, role_policy, doc(least_privilege)])
}

test_allows_wildcard_in_deny_statement if {
	count(gap07.deny) == 0 with input as plan([role, role_policy, doc([stmt("Deny", ["s3:*"])])])
}

# Failing fixtures
test_denies_starter_wildcard_actions if {
	count(gap07.deny) == 2 with input as plan([role, role_policy, doc([stmt("Allow", ["dynamodb:*"]), stmt("Allow", ["s3:*"])])])
}

test_denies_partial_wildcard if {
	count(gap07.deny) == 1 with input as plan([role, role_policy, doc([stmt("Allow", ["s3:Put*"])])])
}

test_denies_wildcard_when_effect_omitted if {
	no_effect := {"actions": {"constant_value": ["dynamodb:*"]}, "resources": {"references": ["aws_dynamodb_table.intake.arn"]}}
	count(gap07.deny) == 1 with input as plan([role, role_policy, doc([no_effect])])
}

test_denies_wildcard_resource if {
	star_resource := {"effect": {"constant_value": "Allow"}, "actions": {"constant_value": ["dynamodb:PutItem"]}, "resources": {"constant_value": ["*"]}}
	count(gap07.deny) == 1 with input as plan([role, role_policy, doc([star_resource])])
}

test_denies_opaque_jsonencode_policy if {
	count(gap07.deny) == 1 with input as plan([role, role_policy_jsonencode])
}

test_deny_message_cites_hipaa_control if {
	msgs := gap07.deny with input as plan([role, role_policy, doc([stmt("Allow", ["s3:*"])])])
	some msg in msgs
	contains(msg, "164.312(a)(1)")
}