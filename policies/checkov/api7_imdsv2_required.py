"""
Custom Checkov policy (Python-based custom check)
OWASP API7:2023 - Server-Side Request Forgery (SSRF)

An SSRF against an EC2 instance is most dangerous when it can reach the
instance metadata service (IMDSv1) and steal instance-role credentials.
Enforcing IMDSv2 (token-required) and a low hop limit defangs that path.

This check fails any aws_instance or launch template that does not require
IMDSv2 via metadata_options { http_tokens = "required" }.
"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


class IMDSv2Required(BaseResourceCheck):
    def __init__(self):
        name = "EC2 must require IMDSv2 to limit SSRF credential theft (OWASP API7)"
        id = "CKV_OWASP_API7_1"
        supported_resources = [
            "aws_instance",
            "aws_launch_template",
        ]
        categories = [CheckCategories.NETWORKING]
        super().__init__(
            name=name,
            id=id,
            categories=categories,
            supported_resources=supported_resources,
        )

    def scan_resource_conf(self, conf):
        metadata_options = conf.get("metadata_options")
        if not metadata_options or not isinstance(metadata_options, list):
            # No metadata_options block -> IMDSv1 allowed by default -> fail.
            return CheckResult.FAILED

        options = metadata_options[0]
        http_tokens = options.get("http_tokens")
        # Terraform nests attribute values in a list.
        if isinstance(http_tokens, list):
            http_tokens = http_tokens[0] if http_tokens else None

        if http_tokens == "required":
            return CheckResult.PASSED
        return CheckResult.FAILED


check = IMDSv2Required()
