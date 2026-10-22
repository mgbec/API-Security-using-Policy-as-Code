"""
Custom Checkov policy (Python-based custom check)
OWASP API2:2023 - Broken Authentication
OWASP API5:2023 - Broken Function Level Authorization

Fails any API Gateway v2 route that uses authorization_type NONE, i.e.
an unauthenticated route. Public routes should be explicit exceptions
reviewed via a suppression comment, not the default.
"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


class ApiGwRouteRequiresAuth(BaseResourceCheck):
    def __init__(self):
        name = "API Gateway route must require authorization (OWASP API2/API5)"
        id = "CKV_OWASP_API2_1"
        supported_resources = ["aws_apigatewayv2_route"]
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(
            name=name,
            id=id,
            categories=categories,
            supported_resources=supported_resources,
        )

    def scan_resource_conf(self, conf):
        auth_type = conf.get("authorization_type")
        if isinstance(auth_type, list):
            auth_type = auth_type[0] if auth_type else None

        # Missing attribute defaults to NONE in Terraform -> fail.
        if auth_type is None or auth_type == "NONE":
            return CheckResult.FAILED
        return CheckResult.PASSED


check = ApiGwRouteRequiresAuth()
