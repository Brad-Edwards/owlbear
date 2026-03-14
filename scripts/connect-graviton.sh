#!/usr/bin/env bash
# Connect to the Graviton dev instance via SSM Session Manager.
#
# Usage: ./scripts/connect-graviton.sh

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly TF_DIR="${SCRIPT_DIR}/../deploy/terraform/environments/dev"

if ! aws sts get-caller-identity &>/dev/null 2>&1; then
    echo "ERROR: AWS credentials not configured."
    echo "  Run: aws sso login --profile catalyst-dev"
    exit 1
fi

cd "${TF_DIR}"

INSTANCE_ID=$(terraform output -raw graviton_instance_id 2>/dev/null)

if [ -z "${INSTANCE_ID}" ]; then
    echo "ERROR: No instance found. Run scripts/provision-graviton.sh apply first."
    exit 1
fi

echo "Connecting to ${INSTANCE_ID}..."
aws ssm start-session --target "${INSTANCE_ID}" --region us-east-2
