#!/usr/bin/env bash
# Provision or update the Graviton dev instance via Terraform.
# Requires: AWS credentials configured (SSO or env vars), terraform installed.
#
# Usage: ./scripts/provision-graviton.sh [plan|apply|destroy]

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly TF_DIR="${SCRIPT_DIR}/../deploy/terraform/environments/dev"
readonly ACTION="${1:-plan}"

log() { echo "[provision] $*"; }

if ! command -v terraform &>/dev/null; then
    log "ERROR: terraform not found. Run scripts/setup-dev.sh first."
    exit 1
fi

if ! aws sts get-caller-identity &>/dev/null 2>&1; then
    log "ERROR: AWS credentials not configured."
    log "  Run: aws sso login --profile catalyst-dev"
    exit 1
fi

cd "${TF_DIR}"

log "Initializing Terraform..."
terraform init -input=false

case "${ACTION}" in
    plan)
        log "Running terraform plan..."
        terraform plan
        ;;
    apply)
        log "Applying infrastructure..."
        terraform apply -auto-approve
        echo ""
        log "Graviton instance ready:"
        terraform output -raw graviton_ssm_command
        echo ""
        log "Telemetry API:"
        terraform output -raw telemetry_api_endpoint
        echo ""
        ;;
    destroy)
        log "WARNING: This will destroy all infrastructure."
        terraform destroy
        ;;
    output)
        terraform output
        ;;
    *)
        echo "Usage: $0 [plan|apply|destroy|output]"
        exit 1
        ;;
esac
