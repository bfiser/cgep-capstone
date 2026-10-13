#terraform/kms.terraform
# KMS: customer-managed key (CMK) for PHI at rest
#
# Closes:  GAP-01 (S3 uploads bucket encryption)
#          GAP-02 (DynamoDB submissions table encryption)
# Control: HIPAA 164.312(a)(2)(iv), encryption and decryption
#
#ACME Health controls key, not AWS.

resource "aws_kms_key" "phi" {
  description             = "Acme Health CMK for PHI at rest (GAP-01, GAP-02)"
  enable_key_rotation     = true
  deletion_window_in_days = 7
}

resource "aws_kms_alias" "phi" {
  name          = "alias/acme-health-phi"
  target_key_id = aws_kms_key.phi.key_id
}