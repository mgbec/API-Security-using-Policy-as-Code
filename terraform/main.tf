terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

locals {
  # Common tags satisfy OWASP API9 (inventory management) policy checks.
  common_tags = {
    owner       = var.owner
    environment = var.environment
    project     = "owasp-api-policy-as-code"
  }
}

# ---------------------------------------------------------------------------
# Identity: Cognito user pool -> OWASP API2 Broken Authentication
# Short-lived tokens, strong password policy, MFA-capable.
# ---------------------------------------------------------------------------
resource "aws_cognito_user_pool" "this" {
  name = "${var.api_name}-pool"

  password_policy {
    minimum_length                   = 12
    require_lowercase                = true
    require_uppercase                = true
    require_numbers                  = true
    require_symbols                  = true
    temporary_password_validity_days = 1
  }

  mfa_configuration = "OPTIONAL"

  software_token_mfa_configuration {
    enabled = true
  }

  tags = local.common_tags
}

resource "aws_cognito_user_pool_client" "this" {
  name            = "${var.api_name}-client"
  user_pool_id    = aws_cognito_user_pool.this.id
  generate_secret = true

  # Short-lived access tokens reduce blast radius of leaked tokens (API2).
  access_token_validity  = 1
  id_token_validity      = 1
  refresh_token_validity = 30
  token_validity_units {
    access_token  = "hours"
    id_token      = "hours"
    refresh_token = "days"
  }

  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email"]
  allowed_oauth_flows_user_pool_client = true
  supported_identity_providers         = ["COGNITO"]
  callback_urls                        = ["https://example.com/callback"]
}

# ---------------------------------------------------------------------------
# HTTP API (API Gateway v2) -> OWASP API9 (tagged, inventoried)
# ---------------------------------------------------------------------------
resource "aws_apigatewayv2_api" "this" {
  name          = var.api_name
  protocol_type = "HTTP"

  # Restrict CORS explicitly -> OWASP API8 (no wildcard origins).
  cors_configuration {
    allow_origins = ["https://example.com"]
    allow_methods = ["GET", "POST"]
    allow_headers = ["authorization", "content-type"]
    max_age       = 600
  }

  tags = local.common_tags
}

# JWT authorizer backed by Cognito -> OWASP API2/API5
resource "aws_apigatewayv2_authorizer" "jwt" {
  api_id           = aws_apigatewayv2_api.this.id
  authorizer_type  = "JWT"
  identity_sources = ["$request.header.Authorization"]
  name             = "${var.api_name}-jwt"

  jwt_configuration {
    audience = [aws_cognito_user_pool_client.this.id]
    issuer   = "https://${aws_cognito_user_pool.this.endpoint}"
  }
}

# Authenticated route -> OWASP API2/API5 (authorization_type = JWT, not NONE)
resource "aws_apigatewayv2_route" "get_item" {
  api_id             = aws_apigatewayv2_api.this.id
  route_key          = "GET /items/{id}"
  target             = "integrations/${aws_apigatewayv2_integration.lambda.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.jwt.id
}

resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = aws_apigatewayv2_api.this.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.api.invoke_arn
  payload_format_version = "2.0"
}

# Stage with throttling (API4) + access logging (API8)
resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.this.id
  name        = "$default"
  auto_deploy = true

  default_route_settings {
    throttling_rate_limit  = 100
    throttling_burst_limit = 50
  }

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      routeKey       = "$context.routeKey"
      status         = "$context.status"
      responseLength = "$context.responseLength"
    })
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_log_group" "api" {
  name              = "/aws/apigw/${var.api_name}"
  retention_in_days = 365
  tags              = local.common_tags
}

# ---------------------------------------------------------------------------
# Lambda backend (tagged for inventory -> API9)
# ---------------------------------------------------------------------------
resource "aws_iam_role" "lambda" {
  name = "${var.api_name}-lambda-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "lambda_logs" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_lambda_function" "api" {
  function_name = "${var.api_name}-handler"
  role          = aws_iam_role.lambda.arn
  runtime       = "python3.12"
  handler       = "handler.lambda_handler"
  filename      = "${path.module}/lambda/handler.zip"

  # Bound resource usage -> API4
  timeout                        = 10
  memory_size                    = 256
  reserved_concurrent_executions = 50

  tags = local.common_tags
}

resource "aws_lambda_permission" "apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.api.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.this.execution_arn}/*/*"
}

# ---------------------------------------------------------------------------
# WAFv2 web ACL -> OWASP API6 (bot/abuse) + API8
# Associated with the API Gateway stage.
# ---------------------------------------------------------------------------
resource "aws_wafv2_web_acl" "this" {
  name        = "${var.api_name}-waf"
  scope       = "REGIONAL"
  description = "Protects the HTTP API from common attacks and abuse."

  default_action {
    allow {}
  }

  # Rate-based rule -> API4/API6
  rule {
    name     = "rate-limit"
    priority = 1
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rate-limit"
      sampled_requests_enabled   = true
    }
  }

  # AWS managed common rule set -> API8
  rule {
    name     = "common-rules"
    priority = 2
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "common-rules"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.api_name}-waf"
    sampled_requests_enabled   = true
  }

  tags = local.common_tags
}

resource "aws_wafv2_web_acl_association" "this" {
  resource_arn = aws_apigatewayv2_stage.default.arn
  web_acl_arn  = aws_wafv2_web_acl.this.arn
}
