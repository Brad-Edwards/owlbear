variable "instance_type" {
  description = "EC2 instance type (must be ARM64/Graviton)"
  type        = string
  default     = "c7g.large"
}

variable "auto_shutdown_hour" {
  description = "UTC hour to auto-shutdown (0-23). Set to -1 to disable."
  type        = number
  default     = 7 # 11pm Pacific = 7am UTC next day
}

variable "project_name" {
  description = "Project name for resource tagging"
  type        = string
  default     = "owlbear"
}

variable "github_repo_url" {
  description = "Git repo URL to clone on instance startup"
  type        = string
  default     = "https://github.com/Brad-Edwards/owlbear.git"
}
