package kimtest2

import rego.v1

# METADATA
# title: Root user is denied all actions
# description: The Sensitive SCP denies all actions for the root user of every account it is attached to.
# custom:
#   message: Add a Deny statement for all actions with a StringLike condition on aws:PrincipalArn matching the root user ARN.
#   control: AWS-SCP-01
#   scp: Accelerator-Guardrails-Sensitive
#   action: "*"
#   operator: StringLike
#   key: "aws:PrincipalArn"
#   principal: "arn:aws:iam::*:root"
stack_deny_scp_root_deny contains msg if {
	p := rego.metadata.rule().custom
	some msg in scp_root_deny_violations(p)
}

scp_root_deny_violations(p) := {sprintf("[%s] SCP '%s' is required but not present in the stack", [p.control, p.scp])} if {
	scp_in_stack
	not scp_named(p.scp)
} else := {msg |
	some r in input.resources
	is_scp(r)
	r.properties.name == p.scp
	not scp_denies_root(r, p)
	msg := sprintf("[%s] SCP '%s' does not deny '%s' for '%s'", [p.control, p.scp, p.action, p.principal])
}

scp_denies_root(r, p) if {
	doc := json.unmarshal(r.properties.content)
	some stmt in as_array(doc.Statement)
	stmt.Effect == "Deny"
	p.action in as_array(stmt.Action)
	p.principal in as_array(stmt.Condition[p.operator][p.key])
}

scp_in_stack if {
	some r in input.resources
	is_scp(r)
}

scp_named(name) if {
	some r in input.resources
	is_scp(r)
	r.properties.name == name
}

is_scp(r) if {
	r.__type == "aws:organizations/policy:Policy"
	r.properties.type == "SERVICE_CONTROL_POLICY"
}

as_array(x) := x if is_array(x)

as_array(x) := [x] if not is_array(x)
