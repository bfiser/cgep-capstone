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

######################################################################
# GAP-04: Versioning on the uploads bucket
# Control: HIPAA 164.308(a)(7), contingency plan (data backup)
#
# Keeps every prior version of each object, so an overwrite or
# delete of PHI is recoverable.
######################################################################
resource "aws_s3_bucket_versioning" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  versioning_configuration {
    status = "Enabled"
  }
}

######################################################################
# GAP-03: Deny non-TLS requests to the uploads bucket
# Control: HIPAA 164.312(e)(1), transmission security
#
# Refuses any request not made over TLS, for every caller,
# so ePHI in transit is always encrypted.
######################################################################
resource "aws_s3_bucket_policy" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        aws_s3_bucket.uploads.arn,
        "${aws_s3_bucket.uploads.arn}/*",
      ]
      Condition = {
        Bool = { "aws:SecureTransport" = "false" }
      }
    }]
  })
}

######################################################################
# GAP-05: Run the Lambda inside the starter's VPC
# Control: HIPAA 164.312(e)(1), transmission security
#
# Private subnets have no internet route. Gateway endpoints give the
# Lambda a private path to S3 and DynamoDB only, and its security
# group allows outbound HTTPS to those two services and nothing else.
######################################################################

# Lets Lambda create the network interfaces it uses inside the VPC
resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# Private paths to S3 and DynamoDB (gateway endpoints are free)
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_vpc.main.main_route_table_id]
}

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_vpc.main.main_route_table_id]
}

# Firewall: no inbound; outbound HTTPS only to S3 and DynamoDB
resource "aws_security_group" "lambda" {
  name        = "acme-health-intake-lambda"
  description = "Intake Lambda: egress to S3 and DynamoDB endpoints only"
  vpc_id      = aws_vpc.main.id

  egress {
    description     = "HTTPS to S3 via gateway endpoint"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    prefix_list_ids = [aws_vpc_endpoint.s3.prefix_list_id]
  }

  egress {
    description     = "HTTPS to DynamoDB via gateway endpoint"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    prefix_list_ids = [aws_vpc_endpoint.dynamodb.prefix_list_id]
  }
}

######################################################################
# GAP-08: API Gateway access logging destination
# Control: HIPAA 164.312(b), audit controls
#
# Records who called the API, when, and with what result. Logs
# request metadata only, never request bodies, so no PHI is
# written to logs.
######################################################################
resource "aws_cloudwatch_log_group" "api_access" {
  name              = "/aws/apigateway/acme-health-intake-access"
  retention_in_days = 365
}