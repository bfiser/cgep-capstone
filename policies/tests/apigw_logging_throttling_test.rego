package hipaa.gap08_api_logging_test

import rego.v1

import data.hipaa.gap08_api_logging as gap08

plan(resources) := {"configuration": {"root_module": {"resources": resources}}}

stage(expressions) := {
	"address": "aws_apigatewayv2_stage.default",
	"type": "aws_apigatewayv2_stage",
	"expressions": expressions,
}

logging := {"access_log_settings": [{
	"destination_arn": {"references": ["aws_cloudwatch_log_group.api_access.arn", "aws_cloudwatch_log_group.api_access"]},
}]}

throttling(burst, rate) := {"default_route_settings": [{
	"throttling_burst_limit": {"constant_value": burst},
	"throttling_rate_limit": {"constant_value": rate},
}]}

# Passing fixture: the fixed capstone
test_passes_with_logging_and_throttling if {
	count(gap08.deny) == 0 with input as plan([stage(object.union(logging, throttling(20, 10)))])
}

# Failing fixtures
test_denies_starter_without_either if {
	count(gap08.deny) == 2 with input as plan([stage({})])
}

test_denies_logging_without_throttling if {
	count(gap08.deny) == 1 with input as plan([stage(logging)])
}

test_denies_zero_throttling if {
	count(gap08.deny) == 1 with input as plan([stage(object.union(logging, throttling(0, 0)))])
}

test_deny_message_cites_hipaa_control if {
	msgs := gap08.deny with input as plan([stage({})])
	some msg in msgs
	contains(msg, "164.312(b)")
}