variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "owlbear"
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-2"
}

variable "events_ttl_days" {
  description = "TTL in days for event records in DynamoDB"
  type        = number
  default     = 7
}

variable "lambda_source_dir" {
  description = "Path to the Lambda handler source directory"
  type        = string
}
