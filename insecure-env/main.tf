terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-west-2"
}

# 1. S3 bucket with NO encryption (violates PCI DSS 3.5, FedRAMP SC-28, CIS 2.1.1)
resource "aws_s3_bucket" "insecure_bucket" {
  bucket = "compliance-lab-insecure-${random_id.suffix.hex}"
}

resource "random_id" "suffix" {
  byte_length = 4
}

# 2. S3 bucket with PUBLIC access (violates PCI DSS 1.3, FedRAMP AC-3, CIS 2.1.2)
resource "aws_s3_bucket_public_access_block" "allow_public" {
  bucket                  = aws_s3_bucket.insecure_bucket.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# 3. Security group open to the world (violates PCI DSS 1.2.1, FedRAMP SC-7, CIS 5.2.1)
resource "aws_security_group" "wide_open" {
  name        = "compliance-lab-wide-open"
  description = "Intentionally insecure - allows all inbound"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "compliance-lab-wide-open"
    Lab  = "insecure"
  }
}

# 4. CloudTrail is NOT enabled (violates PCI DSS 10.1, FedRAMP AU-2, CIS 3.1)
# (We intentionally skip creating CloudTrail)

# 5. IAM password policy is weak (violates PCI DSS 8.3.6, FedRAMP IA-5, CIS 1.8)
resource "aws_iam_account_password_policy" "weak" {
  minimum_password_length        = 6
  require_lowercase_characters   = false
  require_numbers                = false
  require_uppercase_characters   = false
  require_symbols                = false
  allow_users_to_change_password = true
  max_password_age               = 0
  password_reuse_prevention      = 0
}
# --- COMPLIANT RESOURCES (fixing what we broke) ---

# Enable CloudTrail (fixes AU-2, AU-3, PCI 10.1)
resource "aws_cloudtrail" "lab_trail" {
  name                       = "compliance-lab-trail"
  s3_bucket_name             = aws_s3_bucket.trail_logs.id
  is_multi_region_trail      = true
  enable_log_file_validation = true
  depends_on                 = [aws_s3_bucket_policy.trail_policy]
}

# S3 bucket for CloudTrail logs (with encryption)
resource "aws_s3_bucket" "trail_logs" {
  bucket = "compliance-lab-trail-${random_id.suffix.hex}"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail_encryption" {
  bucket = aws_s3_bucket.trail_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_policy" "trail_policy" {
  bucket = aws_s3_bucket.trail_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.trail_logs.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.trail_logs.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}