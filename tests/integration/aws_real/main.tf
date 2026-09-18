terraform {
  required_version = "= 1.16.2"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.65.0"
    }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  description = "AWS region used by the disposable provider-native drift proof."
  type        = string
  default     = "us-east-1"
}

variable "parameter_name" {
  description = "Unique SSM parameter path for one proof run."
  type        = string

  validation {
    condition     = startswith(var.parameter_name, "/driftguard/proof/")
    error_message = "parameter_name must stay under /driftguard/proof/."
  }
}

resource "aws_ssm_parameter" "proof" {
  name  = var.parameter_name
  type  = "String"
  value = "driftguard-baseline-value"
  tier  = "Standard"

  tags = {
    Project = "DriftGuard"
    Purpose = "ProviderNativeProof"
  }
}
