# Manual AWS deployment

CI validates the Terraform configuration without an AWS session or remote state.
It does not plan, apply, start an EC2 instance, or update a remote checkout.
Research builds and unit tests run on GitHub's ARM64 runners.

To provision or update the existing development environment, use an authorized
local AWS profile. Review the plan before applying it:

```sh
cd deploy/terraform/environments/dev
export AWS_PROFILE=catalyst-dev
terraform init
terraform plan -out=/tmp/owlbear-dev.tfplan
terraform show /tmp/owlbear-dev.tfplan
terraform apply /tmp/owlbear-dev.tfplan
```

The saved plan can contain credentials and other sensitive state. Keep it local
and delete it after use. Run deployment only when the target environment is free
for maintenance. A deployment or remote rebuild must not interrupt a study or
change the code or configuration of an active experiment.

The existing bootstrap configuration describes the older GitHub-to-AWS CI role.
It is not needed for manual deployment; do not apply bootstrap to restore CI
access as part of an ordinary deployment.
