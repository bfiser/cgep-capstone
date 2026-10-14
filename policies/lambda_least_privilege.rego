# METADATA
# title: GAP-07 - Intake Lambda role uses least-privilege permissions
# description: "Allow statements in policies attached to aws_iam_role.lambda must not use wildcard actions or wildcard resources, and must be verifiable at plan time."
# custom:
#   gap_id: GAP-07
#   framework: hipaa
#   control_id: "164.312(a)(1)"
#   controls:
#     - "164.312(a)(1)"
#   severity: critical
#   remediation: "Grant only the specific actions handler.py performs (e.g. dynamodb:PutItem, s3:PutObject) on specific resource ARNs, written as an aws_iam_policy_document."
package hipaa.gap07_lambda_least_privilege

import rego.v1

role := "aws_iam_role.lambda"

role_refs := {role, sprintf("%s.id", [role]), sprintf("%s.name", [role])}

resources := input.configuration.root_module.resources

# Inline policies attached to the Lambda's role
role_policies contains r if {
	some r in resources
	r.type == "aws_iam_role_policy"
	some ref in r.expressions.role.references
	ref in role_refs
}

# The policy document data source a role policy points at
policy_doc(rp) := doc if {
	some ref in rp.expressions.policy.references
	some doc in resources
	doc.type == "aws_iam_policy_document"
	doc.address == ref
}

# A statement is an Allow if it says so, or if effect is omitted (Terraform's default)
is_allow(st) if st.effect.constant_value == "Allow"

is_allow(st) if not st.effect

# 1. Wildcard actions in Allow statements
deny contains msg if {
	some rp in role_policies
	doc := policy_doc(rp)
	some st in doc.expressions.statement
	is_allow(st)
	some action in st.actions.constant_value
	contains(action, "*")
	msg := sprintf("[HIPAA 164.312(a)(1)] GAP-07 %s: Allow statement uses wildcard action %q. Remediation: grant only the specific actions the function performs.", [rp.address, action])
}

# 2. Wildcard resources in Allow statements
deny contains msg if {
	some rp in role_policies
	doc := policy_doc(rp)
	some st in doc.expressions.statement
	is_allow(st)
	"*" in st.resources.constant_value
	msg := sprintf("[HIPAA 164.312(a)(1)] GAP-07 %s: Allow statement applies to all resources (\"*\"). Remediation: scope to specific resource ARNs.", [rp.address])
}

# 3. Allow statements whose actions can't be read at plan time
deny contains msg if {
	some rp in role_policies
	doc := policy_doc(rp)
	some st in doc.expressions.statement
	is_allow(st)
	not st.actions.constant_value
	msg := sprintf("[HIPAA 164.312(a)(1)] GAP-07 %s: Allow statement actions are not verifiable at plan time. Remediation: list actions as literal values.", [rp.address])
}

# 4. Role policies not written as a policy document data source
deny contains msg if {
	some rp in role_policies
	not policy_doc(rp)
	msg := sprintf("[HIPAA 164.312(a)(1)] GAP-07 %s: policy content is not verifiable at plan time. Remediation: author the policy as an aws_iam_policy_document data source.", [rp.address])
}