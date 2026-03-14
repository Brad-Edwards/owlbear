output "instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.dev.id
}

output "instance_arn" {
  description = "EC2 instance ARN"
  value       = aws_instance.dev.arn
}

output "ami_id" {
  description = "AMI used"
  value       = data.aws_ami.al2023_arm64.id
}

output "ssm_command" {
  description = "SSM Session Manager connect command"
  value       = "aws ssm start-session --target ${aws_instance.dev.id}"
}

output "artifacts_bucket" {
  description = "S3 bucket for verification artifacts"
  value       = aws_s3_bucket.artifacts.bucket
}

output "artifacts_bucket_arn" {
  description = "S3 bucket ARN for verification artifacts"
  value       = aws_s3_bucket.artifacts.arn
}
