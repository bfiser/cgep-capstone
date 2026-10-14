# METADATA
# title: GAP-08 - API stage access logging and throttling
# description: "aws_apigatewayv2_stage.default must send access logs to a destination and set throttling limits. WAF is out of scope (deferred; not attachable to HTTP APIs without CloudFront)."
# custom:
#   gap_id: GAP-08
#   control_id: "164.312(b)"
#   framework: hipaa-security-rule
#   severity: medium
#   remediation: "Add access_log_settings { destination_arn = <log group ARN> } and default_route_settings with throttling_burst_limit and throttling_rate_limit > 0 to aws_apigatewayv2_stage.default."
package hipaa.gap08_api_logging

import rego.v1

stage := "aws_apigatewayv2_stage.default"

resources := input.configuration.root_module.resources

stage_resource := r if {
	some r in resources
	r.address == stage
}

has_value(field) if count(field.references) > 0

has_value(field) if field.constant_value != ""

logging_configured if {
	some s in stage_resource.expressions.access_log_settings
	has_value(s.destination_arn)
}

throttling_configured if {
	some s in stage_resource.expressions.default_route_settings
	s.throttling_burst_limit.constant_value > 0
	s.throttling_rate_limit.constant_value > 0
}

deny contains msg if {
	stage_resource
	not logging_configured
	msg := "[HIPAA 164.312(b)] GAP-08 aws_apigatewayv2_stage.default: no access logging, so API activity is not recorded. Remediation: add access_log_settings with a CloudWatch log group destination."
}

deny contains msg if {
	stage_resource
	not throttling_configured
	msg := "[HIPAA 164.312(b)] GAP-08 aws_apigatewayv2_stage.default: no throttling limits. Remediation: set throttling_burst_limit and throttling_rate_limit > 0 in default_route_settings."
}