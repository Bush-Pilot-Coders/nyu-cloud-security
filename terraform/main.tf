# CloudTrail Configuration
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "nyu-cloudsec-cloudtrail-logs-${random_id.bucket_suffix.hex}"
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "random_id" "bucket_suffix" {
  byte_length = 8
}

resource "aws_cloudtrail" "main" {
  name                          = "nyu-cloudsec-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  s3_key_prefix                 = "cloudtrail"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }
}

# EventBridge Rules for High-Risk API Calls
resource "aws_cloudwatch_event_rule" "high_risk_api_calls" {
  name        = "nyu-cloudsec-high-risk-api-calls"
  description = "Detect high-risk IAM API calls"

  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["iam.amazonaws.com"]
      eventName = [
        "AttachUserPolicy",
        "CreateAccessKey",
        "AddUserToGroup",
        "PutUserPolicy"
      ]
    }
  })
}

resource "aws_cloudwatch_event_rule" "root_console_login" {
  name        = "nyu-cloudsec-root-console-login"
  description = "Detect any root console login"

  event_pattern = jsonencode({
    source      = ["aws.signin"]
    detail-type = ["AWS Console Sign In via CloudTrail"]
    detail = {
      userIdentity = {
        type = ["Root"]
      }
      eventName = ["ConsoleLogin"]
    }
  })
}

# EventBridge Targets (placeholders for now - will connect to Lambda later)
resource "aws_cloudwatch_event_target" "high_risk_api_target" {
  rule      = aws_cloudwatch_event_rule.high_risk_api_calls.name
  arn       = aws_lambda_function.responder.arn # Placeholder - Lambda not defined yet
  target_id = "HighRiskAPITarget"
}

resource "aws_cloudwatch_event_target" "root_login_target" {
  rule      = aws_cloudwatch_event_rule.root_console_login.name
  arn       = aws_sns_topic.alerts.arn # Direct to SNS for emergency
  target_id = "RootLoginTarget"
}

# SNS Topic for Alerts
resource "aws_sns_topic" "alerts" {
  name = "nyu-cloudsec-alerts"
}

# Placeholder for Lambda (to be implemented)
resource "aws_lambda_function" "responder" {
  # This is a placeholder - actual implementation needed
  function_name = "nyu-cloudsec-responder"
  runtime       = "python3.13"
  handler       = "lambda_function.lambda_handler"
  # Other configurations...
}
