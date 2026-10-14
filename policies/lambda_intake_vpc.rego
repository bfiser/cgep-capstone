# METADATA
# title: GAP-05 - Intake Lambda runs in the starter's private subnets
# description: "aws_lambda_function.intake must have a vpc_config with subnets and security groups, and must not use public subnets."
# custom:
#   gap_id: GAP-05
#   control_id: "164.312(e)(1)"
#   framework: hipaa-security-rule
#   severity: high
#   remediation: "Add vpc_config to aws_lambda_function.intake with subnet_ids = aws_subnet.private[*].id and a restrictive security group."
package hipaa.gap05_lambda_vpc

import rego.v1

lambda := "aws_lambda_function.intake"

resources := input.configuration.root_module.resources

lambda_resource := r if {
	some r in resources
	r.address == lambda
}

non_empty(field) if count(field.references) > 0

non_empty(field) if count(field.constant_value) > 0

# vpc_config blocks with both subnets and security groups set
vpc_configs contains vc if {
	some vc in lambda_resource.expressions.vpc_config
	non_empty(vc.subnet_ids)
	non_empty(vc.security_group_ids)
}

uses_public_subnets if {
	some vc in vpc_configs
	some ref in vc.subnet_ids.references
	startswith(ref, "aws_subnet.public")
}

deny contains msg if {
	lambda_resource
	count(vpc_configs) == 0
	msg := "[HIPAA 164.312(e)(1)] GAP-05 aws_lambda_function.intake: not deployed in the VPC (no vpc_config with subnets and security groups). Remediation: add vpc_config with the starter's private subnets and a security group."
}

deny contains msg if {
	uses_public_subnets
	msg := "[HIPAA 164.312(e)(1)] GAP-05 aws_lambda_function.intake: attached to public subnets. Remediation: use aws_subnet.private[*].id so the function has no internet route."
}