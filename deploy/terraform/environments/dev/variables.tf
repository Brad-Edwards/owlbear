variable "aws_region" {
  type    = string
  default = "us-east-2"
}

variable "instance_type" {
  description = "Graviton instance type"
  type        = string
  default     = "c7g.large"
}

variable "auto_shutdown_hour" {
  description = "UTC hour to auto-shutdown dev instance (-1 to disable)"
  type        = number
  default     = 7 # 11pm Pacific
}
