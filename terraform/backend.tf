######################################################################
# Remote state: shared by local runs and the CI pipeline
#
# Bucket bootstrapped once via AWS CLI (versioned, public access
# blocked, SSE-S3). use_lockfile enables S3-native state locking
# (Terraform 1.10+), so concurrent runs can't corrupt state.
######################################################################
terraform {
  backend "s3" {
    bucket       = "acme-health-intake-tfstate-411232895450"
    key          = "capstone/terraform.tfstate"
    region       = "us-east-2"
    encrypt      = true
    use_lockfile = true
  }
}