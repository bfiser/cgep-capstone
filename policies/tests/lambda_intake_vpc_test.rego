package hipaa.gap05_lambda_vpc_test

import rego.v1

import data.hipaa.gap05_lambda_vpc as gap05

plan(resources) := {"configuration": {"root_module": {"resources": resources}}}

lambda(expressions) := {
	"address": "aws_lambda_function.intake",
	"type": "aws_lambda_function",
	"expressions": expressions,
}

sg_ref := {"references": ["aws_security_group.lambda.id", "aws_security_group.lambda"]}

private_vpc := {"vpc_config": [{
	"subnet_ids": {"references": ["aws_subnet.private"]},
	"security_group_ids": sg_ref,
}]}

public_vpc := {"vpc_config": [{
	"subnet_ids": {"references": ["aws_subnet.public"]},
	"security_group_ids": sg_ref,
}]}

no_subnets_vpc := {"vpc_config": [{
	"subnet_ids": {"constant_value": []},
	"security_group_ids": sg_ref,
}]}

# Passing fixture
test_passes_in_private_subnets if {
	count(gap05.deny) == 0 with input as plan([lambda(private_vpc)])
}

# Failing fixtures
test_denies_starter_without_vpc_config if {
	count(gap05.deny) == 1 with input as plan([lambda({})])
}

test_denies_empty_subnet_list if {
	count(gap05.deny) == 1 with input as plan([lambda(no_subnets_vpc)])
}

test_denies_public_subnets if {
	count(gap05.deny) == 1 with input as plan([lambda(public_vpc)])
}

test_deny_message_cites_hipaa_control if {
	msgs := gap05.deny with input as plan([lambda({})])
	some msg in msgs
	contains(msg, "164.312(e)(1)")
}