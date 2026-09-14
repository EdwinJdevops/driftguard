terraform {
  required_version = ">= 1.6.0"

  required_providers {
    local = {
      source  = "hashicorp/local"
      version = "2.9.0"
    }
  }
}

variable "secret_content" {
  description = "Sentinel value used only to prove that DriftGuard evidence never persists sensitive plan values."
  type        = string
  sensitive   = true
  default     = "driftguard-fixture-secret-v1"
}

module "files" {
  source = "./modules/files"

  base_dir       = abspath("${path.root}/runtime")
  secret_content = var.secret_content
}
