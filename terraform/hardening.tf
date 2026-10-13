######################################################################
# Hardening: gap-closing overrides on the starter's resources
#
# The starter's main.tf is left as unchanged as possible. Fixes that
# can be expressed as separate resources live here, attached to the
# starter's resources by reference (e.g. aws_s3_bucket.uploads.id).
#
# Fixes that must live inside a starter resource block (DynamoDB
# encryption, Lambda vpc_config, IAM policy, API stage logging) are
# edited directly in main.tf and marked there with their GAP ID.
#
# Primary framework: HIPAA Security Rule
######################################################################

######################################################################
# GAP-01: Uploads bucket encrypted with Acme's CMK
# Control: HIPAA 164.312(a)(2)(iv), encryption and decryption
#
# Replaces the AWS-managed SSE-S3 default with SSE-KMS using the CMK
# from kms.tf. bucket_key_enabled reduces KMS request costs by reusing
# a bucket-level data key instead of calling KMS for every object.
######################################################################

# GAP-01: encrypt the uploads bucket with our CMK (HIPAA 164.312(a)(2)(iv))
resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
    bucket_key_enabled = true
  }
}