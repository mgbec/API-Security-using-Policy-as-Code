variable "aws_region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment (used for the required 'environment' tag)."
  type        = string
  default     = "dev"
}

variable "owner" {
  description = "Owning team or individual (used for the required 'owner' tag)."
  type        = string
  default     = "platform-security"
}

variable "api_name" {
  description = "Name of the HTTP API."
  type        = string
  default     = "secure-example-api"
}
