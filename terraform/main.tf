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

# EventBridge Rule — filters IAM-related activity to send to SQS
resource "aws_cloudwatch_event_rule" "iam_activity" {
  name           = "nyu-cloudsec-iam-activity"
  description    = "Capture IAM/STS/Signin events for responder processing"
  event_bus_name = "default"

  event_pattern = jsonencode({
    source      = ["aws.signin", "aws.iam", "aws.sts"]
    detail-type = ["AWS Console Sign In via CloudTrail", "AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "ConsoleLogin",
        "CreateAccessKey",
        "DeleteAccessKey",
        "AttachUserPolicy",
        "PutUserPolicy",
        "CreateLoginProfile"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "iam_activity_to_sqs" {
  rule           = aws_cloudwatch_event_rule.iam_activity.name
  event_bus_name = "default"
  arn            = aws_sqs_queue.iam_activity.arn
  target_id      = "IAMActivityQueueTarget"
}

# SQS Queue — buffers events between EventBridge and Lambda
resource "aws_sqs_queue" "iam_activity" {
  name                       = "iam-activity-queue"
  visibility_timeout_seconds = 60
  message_retention_seconds  = 345600
}

resource "aws_sqs_queue_policy" "iam_activity" {
  queue_url = aws_sqs_queue.iam_activity.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgeSendMessage"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.iam_activity.arn
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.iam_activity.arn
        }
      }
    }]
  })
}

locals {
  alert_emails = [
    "kat9331@nyu.edu",
    "dm6256@nyu.edu",
    "kt1661@nyu.edu",
    "jf4440@nyu.edu",
  ]
}

# SNS Topic for Alerts
resource "aws_sns_topic" "alerts" {
  name                        = "nyu-cloudsec-alerts"
  fifo_topic                  = false
  content_based_deduplication = false
}

resource "aws_sns_topic_subscription" "alerts_email" {
  for_each  = toset(local.alert_emails)
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = each.value
}

resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchAlarmsPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
    }]
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

resource "aws_iam_role_policy_attachment" "responder_sqs_exec" {
  role       = aws_iam_role.responder.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaSQSQueueExecutionRole"
}

resource "aws_iam_role_policy" "responder_inline" {
  name = "nyu-cloudsec-responder-inline"
  role = aws_iam_role.responder.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DynamoDBActivityWrite"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem"]
        Resource = aws_dynamodb_table.iam_activity.arn
      },
      {
        Sid    = "DynamoDBBaselineRW"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem"
        ]
        Resource = aws_dynamodb_table.iam_ip_baseline.arn
      },
      {
        Sid      = "SNSPublishAlerts"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.alerts.arn
      },
      {
        Sid    = "IAMKeyRevocationAndQuarantine"
        Effect = "Allow"
        Action = [
          "iam:ListAccessKeys",
          "iam:UpdateAccessKey",
          "iam:AttachUserPolicy"
        ]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/*"
      }
    ]
  })
}

data "archive_file" "responder" {
  type        = "zip"
  source_file = "${path.module}/lambda/lambda.py"
  output_path = "${path.module}/.build/responder.zip"
}

resource "aws_lambda_function" "responder" {
  function_name                  = "nyu-cloudsec-responder"
  role                           = aws_iam_role.responder.arn
  runtime                        = "python3.13"
  handler                        = "lambda.lambda_handler"
  filename                       = data.archive_file.responder.output_path
  source_code_hash               = data.archive_file.responder.output_base64sha256
  memory_size                    = 128
  timeout                        = 30
  package_type                   = "Zip"
  publish                        = false
  reserved_concurrent_executions = -1
  skip_destroy                   = false

  environment {
    variables = {
      SNS_TOPIC_ARN         = aws_sns_topic.alerts.arn
      IAM_ACTIVITY_TABLE    = aws_dynamodb_table.iam_activity.name
      IAM_IP_BASELINE_TABLE = aws_dynamodb_table.iam_ip_baseline.name
      QUARANTINE_POLICY_ARN = "arn:aws:iam::aws:policy/AWSCompromisedKeyQuarantineV3"
    }
  }
}

resource "aws_lambda_event_source_mapping" "responder_sqs" {
  event_source_arn = aws_sqs_queue.iam_activity.arn
  function_name    = aws_lambda_function.responder.arn
  batch_size       = 10
  enabled          = true
}

# DynamoDB — audit log of all IAM activity (user_id hash, timestamp range)
resource "aws_dynamodb_table" "iam_activity" {
  name         = "IAMActivityTable"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "user_id"
  range_key    = "timestamp"

  attribute {
    name = "user_id"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "N"
  }
}

# DynamoDB — per-user IP baseline (trusted + known IPs)
resource "aws_dynamodb_table" "iam_ip_baseline" {
  name         = "IAMIPBaselineTable"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "user_id"

  attribute {
    name = "user_id"
    type = "S"
  }
}