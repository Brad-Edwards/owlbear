variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-2"
}

variable "state_bucket_name" {
  description = "S3 bucket for Terraform state"
  type        = string
  default     = "owlbear-terraform-state-catalyst-dev"
}

variable "lock_table_name" {
  description = "DynamoDB table for state locking"
  type        = string
  default     = "owlbear-terraform-lock"
}

variable "github_repo" {
  description = "GitHub repository (org/repo format)"
  type        = string
  default     = "KeplerOps/owlbear"
}
