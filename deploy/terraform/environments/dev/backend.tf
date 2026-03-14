terraform {
  backend "s3" {
    bucket         = "owlbear-terraform-state-catalyst-dev"
    key            = "environments/dev/terraform.tfstate"
    region         = "us-east-2"
    dynamodb_table = "owlbear-terraform-lock"
    encrypt        = true
  }
}
