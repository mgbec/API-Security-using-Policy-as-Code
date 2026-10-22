# Conftest (OPA/Rego) policy evaluated against the Terraform plan JSON.
#
# Unlike Checkov (which scans source), this evaluates the resolved resource
# graph from `terraform show -json tfplan.binary`, so it sees computed and
# module-wired values. Good for cross-resource org rules.
#
# Run:
#   terraform plan -out=tfplan.binary
#   terraform show -json tfplan.binary > tfplan.json
#   conftest test tfplan.json --policy policies/opa --all-namespaces
#
# Covers:
#   API4 - API Gateway stages must set throttling
#   API6 - Public-facing HTTP APIs must be fronted by a WAFv2 web ACL
#   API7 - EC2 must require IMDSv2
#   API8 - API Gateway stages must enable access logging
#   API9 - Every resource must carry owner/environment tags (inventory)

package main

import rego.v1

# Pull planned resources of a given type out of the plan JSON.
resources_of(type) := [r |
	some r in input.planned_values.root_module.resources
	r.type == type
]

# ---------------------------------------------------------------------------
# API4:2023 - Unrestricted Resource Consumption
# ---------------------------------------------------------------------------
deny contains msg if {
	some stage in resources_of("aws_apigatewayv2_stage")
	not stage.values.default_route_settings
	msg := sprintf(
		"API4: API Gateway stage '%s' has no default_route_settings throttling",
		[stage.address],
	)
}

deny contains msg if {
	some stage in resources_of("aws_apigatewayv2_stage")
	settings := stage.values.default_route_settings[_]
	not settings.throttling_rate_limit
	msg := sprintf(
		"API4: API Gateway stage '%s' missing throttling_rate_limit",
		[stage.address],
	)
}

# ---------------------------------------------------------------------------
# API8:2023 - Security Misconfiguration (access logging)
# ---------------------------------------------------------------------------
deny contains msg if {
	some stage in resources_of("aws_apigatewayv2_stage")
	not stage.values.access_log_settings
	msg := sprintf(
		"API8: API Gateway stage '%s' has no access_log_settings",
		[stage.address],
	)
}

# ---------------------------------------------------------------------------
# API7:2023 - SSRF (IMDSv2 required)
# ---------------------------------------------------------------------------
deny contains msg if {
	some inst in resources_of("aws_instance")
	opts := inst.values.metadata_options[_]
	opts.http_tokens != "required"
	msg := sprintf(
		"API7: EC2 instance '%s' does not require IMDSv2 (http_tokens != required)",
		[inst.address],
	)
}

deny contains msg if {
	some inst in resources_of("aws_instance")
	not inst.values.metadata_options
	msg := sprintf(
		"API7: EC2 instance '%s' has no metadata_options; IMDSv1 is allowed",
		[inst.address],
	)
}

# ---------------------------------------------------------------------------
# API9:2023 - Improper Inventory Management (ownership tags)
# Resources must be tagged so the API inventory is traceable.
# ---------------------------------------------------------------------------
required_tags := {"owner", "environment"}

taggable := {"aws_apigatewayv2_api", "aws_instance", "aws_lambda_function"}

deny contains msg if {
	some r in input.planned_values.root_module.resources
	taggable[r.type]
	some t in required_tags
	not r.values.tags[t]
	msg := sprintf(
		"API9: resource '%s' is missing required tag '%s'",
		[r.address, t],
	)
}

# ---------------------------------------------------------------------------
# API6:2023 - Unrestricted Access to Sensitive Business Flows
# Warn (not deny) if no WAFv2 web ACL association exists in the plan at all.
# ---------------------------------------------------------------------------
warn contains msg if {
	count(resources_of("aws_apigatewayv2_api")) > 0
	count(resources_of("aws_wafv2_web_acl")) == 0
	msg := "API6: HTTP API present but no aws_wafv2_web_acl found (bot/abuse protection)"
}
