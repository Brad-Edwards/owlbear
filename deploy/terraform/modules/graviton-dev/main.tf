# -----------------------------------------------------------------------------
# Graviton ARM64 Development Instance
#
# c7g.large (Graviton3) for PAC support.
# SSM Session Manager access — no SSH keys, no public IP.
# Auto-shutdown via CloudWatch Events + Lambda.
# -----------------------------------------------------------------------------

data "aws_ami" "al2023_arm64" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-arm64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "architecture"
    values = ["arm64"]
  }
}

# -----------------------------------------------------------------------------
# IAM — instance profile for SSM access
# -----------------------------------------------------------------------------

resource "aws_iam_role" "instance" {
  name = "${var.project_name}-graviton-dev"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "instance" {
  name = "${var.project_name}-graviton-dev"
  role = aws_iam_role.instance.name
}

# -----------------------------------------------------------------------------
# S3 — verification artifact storage
# -----------------------------------------------------------------------------

resource "aws_s3_bucket" "artifacts" {
  bucket = "${var.project_name}-verification-artifacts"

  tags = {
    Name = "${var.project_name}-verification-artifacts"
  }
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    id     = "expire-old-runs"
    status = "Enabled"

    filter {} # Match all objects

    expiration {
      days = 90
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

# Grant instance profile write access to artifacts bucket
resource "aws_iam_role_policy" "artifacts_upload" {
  name = "verification-artifacts-upload"
  role = aws_iam_role.instance.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ArtifactsBucketWrite"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket",
        ]
        Resource = [
          aws_s3_bucket.artifacts.arn,
          "${aws_s3_bucket.artifacts.arn}/*",
        ]
      }
    ]
  })
}

# -----------------------------------------------------------------------------
# Security Group — egress only (SSM needs no inbound)
# -----------------------------------------------------------------------------

resource "aws_security_group" "instance" {
  name_prefix = "${var.project_name}-graviton-dev-"
  description = "Owlbear Graviton dev instance - egress only"

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound"
  }

  tags = {
    Name = "${var.project_name}-graviton-dev"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# -----------------------------------------------------------------------------
# EC2 Instance
# -----------------------------------------------------------------------------

resource "aws_instance" "dev" {
  ami                    = data.aws_ami.al2023_arm64.id
  instance_type          = var.instance_type
  iam_instance_profile   = aws_iam_instance_profile.instance.name
  vpc_security_group_ids = [aws_security_group.instance.id]

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
    encrypted   = true
  }

  user_data = templatefile("${path.module}/userdata.sh", {
    github_repo_url = var.github_repo_url
  })

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 only
    http_put_response_hop_limit = 1
  }

  tags = {
    Name         = "${var.project_name}-graviton-dev"
    AutoShutdown = var.auto_shutdown_hour >= 0 ? "true" : "false"
  }
}

# -----------------------------------------------------------------------------
# Auto-shutdown via EventBridge + SSM
# Uses SSM RunCommand to stop the instance — no Lambda needed.
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "auto_shutdown" {
  count = var.auto_shutdown_hour >= 0 ? 1 : 0

  name                = "${var.project_name}-auto-shutdown"
  description         = "Stop Graviton dev instance at ${var.auto_shutdown_hour}:00 UTC"
  schedule_expression = "cron(0 ${var.auto_shutdown_hour} * * ? *)"
}

resource "aws_iam_role" "eventbridge_ec2" {
  count = var.auto_shutdown_hour >= 0 ? 1 : 0

  name = "${var.project_name}-eventbridge-ec2-stop"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "eventbridge_ec2" {
  count = var.auto_shutdown_hour >= 0 ? 1 : 0

  name = "stop-instance"
  role = aws_iam_role.eventbridge_ec2[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "ec2:StopInstances"
        Resource = aws_instance.dev.arn
      }
    ]
  })
}

resource "aws_cloudwatch_event_target" "stop_instance" {
  count = var.auto_shutdown_hour >= 0 ? 1 : 0

  rule     = aws_cloudwatch_event_rule.auto_shutdown[0].name
  arn      = "arn:aws:events:${data.aws_region.current.name}::ec2:StopInstances"
  role_arn = aws_iam_role.eventbridge_ec2[0].arn

  input = jsonencode({
    InstanceIds = [aws_instance.dev.id]
  })
}

data "aws_region" "current" {}
