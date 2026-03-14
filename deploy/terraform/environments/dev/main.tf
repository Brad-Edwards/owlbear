# -----------------------------------------------------------------------------
# Owlbear dev environment — catalyst-dev account
# -----------------------------------------------------------------------------

module "graviton_dev" {
  source = "../../modules/graviton-dev"

  instance_type      = var.instance_type
  auto_shutdown_hour = var.auto_shutdown_hour
  project_name       = "owlbear"
}

module "telemetry" {
  source = "../../modules/telemetry-api"

  project_name      = "owlbear"
  aws_region        = var.aws_region
  events_ttl_days   = 7
  lambda_source_dir = "${path.module}/../../../../platform/api"
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "graviton_instance_id" {
  value = module.graviton_dev.instance_id
}

output "graviton_ssm_command" {
  value = module.graviton_dev.ssm_command
}

output "telemetry_api_endpoint" {
  value = module.telemetry.api_endpoint
}

output "telemetry_api_key_ssm" {
  value = module.telemetry.api_key_ssm_name
}

output "events_table" {
  value = module.telemetry.events_table_name
}

output "artifacts_bucket" {
  value = module.graviton_dev.artifacts_bucket
}
