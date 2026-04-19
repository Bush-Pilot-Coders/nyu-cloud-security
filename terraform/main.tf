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

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.nyu-cloudwatch-log-group.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cloudwatch.arn

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
data "aws_iam_policy_document" "responder_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "responder" {
  name               = "nyu-cloudsec-responder-role"
  assume_role_policy = data.aws_iam_policy_document.responder_assume_role.json
}

resource "aws_iam_role_policy_attachment" "responder_basic_logs" {
  role       = aws_iam_role.responder.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "archive_file" "responder_stub" {
  type        = "zip"
  output_path = "${path.module}/.build/responder_stub.zip"

  source {
    filename = "lambda_function.py"
    content  = <<-EOT
      def lambda_handler(event, context):
          return {"statusCode": 200, "body": "stub"}
    EOT
  }
}

resource "aws_lambda_function" "responder" {
  function_name    = "nyu-cloudsec-responder"
  role             = aws_iam_role.responder.arn
  runtime          = "python3.13"
  handler          = "lambda_function.lambda_handler"
  filename         = data.archive_file.responder_stub.output_path
  source_code_hash = data.archive_file.responder_stub.output_base64sha256
}