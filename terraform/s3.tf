resource "aws_s3_bucket" "nyu-tdr-s3-cloudtrail-logs-bucket" {
  bucket        = "nyu-tdr-cloudtrail-logs-bucket"
  force_destroy = true  # safe for dev/demo; remove for production (forces deletion even with files)
}

resource "aws_s3_bucket_public_access_block" "nyu-tdr-s3-cloudtrail-logs-bucket-pubaccblock" {
  bucket                  = aws_s3_bucket.nyu-tdr-s3-cloudtrail-logs-bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "nyu-tdr-s3-cloudtrail-logs-bucket-policy" {
  bucket = aws_s3_bucket.nyu-tdr-s3-cloudtrail-logs-bucket.id
  policy = data.aws_iam_policy_document.cloudtrail_s3.json
}

data "aws_iam_policy_document" "cloudtrail_s3" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.nyu-tdr-s3-cloudtrail-logs-bucket.arn]
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.nyu-tdr-s3-cloudtrail-logs-bucket.arn}/AWSLogs/*"]

    # Ensures that any log files CloudTrail writes are automatically owned by the AWS account rather than by CloudTrail itself
    # Cloudtrail includes this in the headers, this is just a safety check
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}