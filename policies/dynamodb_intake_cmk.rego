# METADATA
# title: GAP-02 - DynamoDB submissions table encrypted with a customer-managed KMS key
# description: "aws_dynamodb_table.intake must enable server-side encryption with a customer-managed key, not the AWS-owned or AWS-managed default."
# custom:
#   gap_id: GAP-02
#   control_id: "164.312(a)(2)(iv)"
#   framework: hipaa-security-rule
#   severity: high
#   remediation: "Add a server_side_encryption block to aws_dynamodb_table.intake with enabled = true and kms_key_arn set to a customer-managed key."
package hipaa.gap02_dynamodb_cmk

import rego.v1

table := "aws_dynamodb_table.intake"

resources := input.configuration.root_module.resources

table_present if {
	some r in resources
	r.address == table
}

# Encryption enabled with a key referenced from Terraform
table_uses_cmk if {
	some r in resources
	r.address == table
	some sse in r.expressions.server_side_encryption
	sse.enabled.constant_value == true
	count(sse.kms_key_arn.references) > 0
}

# Encryption enabled with a key ARN typed in directly
table_uses_cmk if {
	some r in resources
	r.address == table
	some sse in r.expressions.server_side_encryption
	sse.enabled.constant_value == true
	sse.kms_key_arn.constant_value != ""
}

deny contains msg if {
	table_present
	not table_uses_cmk
	msg := "[HIPAA 164.312(a)(2)(iv)] GAP-02 aws_dynamodb_table.intake: not encrypted with a customer-managed key (AWS-owned or AWS-managed key in use). Remediation: add server_side_encryption { enabled = true, kms_key_arn = <customer-managed key> }."
}