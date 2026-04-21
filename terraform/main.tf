data "aws_caller_identity" "current" {}

# CloudTrail Configuration
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket        = "nyu-cloudsec-cloudtrail-logs-${random_id.bucket_suffix.hex}"
  force_destroy = false
  tags          = {}
}

resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail_logs.arn
        Condition = {
          StringEquals = {
            "aws:SourceArn" = "arn:aws:cloudtrail:us-east-1:${data.aws_caller_identity.current.account_id}:trail/nyu-cloudsec-trail"
          }
        }
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail_logs.arn}/cloudtrail/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "aws:SourceArn" = "arn:aws:cloudtrail:us-east-1:${data.aws_caller_identity.current.account_id}:trail/nyu-cloudsec-trail"
          }
        }
      }
    ]
  })
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
  is_organization_trail         = false
  enable_log_file_validation    = true
  enable_logging                = true

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.nyu-cloudwatch-log-group.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cloudwatch.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail_logs]
}

# EventBridge Rules for High-Risk API Calls
resource "aws_cloudwatch_event_rule" "high_risk_api_calls" {
  name           = "nyu-cloudsec-high-risk-api-calls"
  description    = "Detect high-risk IAM API calls"
  event_bus_name = "default"

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
  name           = "nyu-cloudsec-root-console-login"
  description    = "Detect any root console login"
  event_bus_name = "default"

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
  rule           = aws_cloudwatch_event_rule.high_risk_api_calls.name
  event_bus_name = "default"
  arn            = aws_lambda_function.responder.arn # Placeholder - Lambda not defined yet
  target_id      = "HighRiskAPITarget"
}

resource "aws_cloudwatch_event_target" "root_login_target" {
  rule           = aws_cloudwatch_event_rule.root_console_login.name
  event_bus_name = "default"
  arn            = aws_sns_topic.alerts.arn # Direct to SNS for emergency
  target_id      = "RootLoginTarget"
}

# SNS Topic for Alerts
resource "aws_sns_topic" "alerts" {
  name                        = "nyu-cloudsec-alerts"
  fifo_topic                  = false
  content_based_deduplication = false
}

resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowEventBridgePublish"
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.alerts.arn
      },
      {
        Sid       = "AllowCloudWatchAlarmsPublish"
        Effect    = "Allow"
        Principal = { Service = "cloudwatch.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.alerts.arn
      }
    ]
  })
}

resource "aws_iam_role" "responder" {
  name                  = "nyu-cloudsec-responder-role"
  path                  = "/"
  force_detach_policies = false
  max_session_duration  = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
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
  function_name                  = "nyu-cloudsec-responder"
  role                           = aws_iam_role.responder.arn
  runtime                        = "python3.13"
  handler                        = "lambda_function.lambda_handler"
  filename                       = data.archive_file.responder_stub.output_path
  source_code_hash               = data.archive_file.responder_stub.output_base64sha256
  memory_size                    = 128
  timeout                        = 3
  package_type                   = "Zip"
  publish                        = false
  reserved_concurrent_executions = -1
  skip_destroy                   = false
}

resource "aws_lambda_permission" "allow_eventbridge_high_risk" {
  statement_id  = "AllowExecutionFromEventBridgeHighRisk"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.responder.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.high_risk_api_calls.arn
}