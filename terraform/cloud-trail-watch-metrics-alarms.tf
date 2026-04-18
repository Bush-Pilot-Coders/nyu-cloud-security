# -----------------------------------------------------------
# TDR - Threat Detection and Response
# -----------------------------------------------------------


# -----------------------------------------------------------
# CloudTrail - captures all API calls and ships to CloudWatch
# -----------------------------------------------------------
resource "aws_cloudtrail" "nyu-tdr-cloudtrail-main" {
  name                          = "nyu-tdr-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.nyu-tdr-s3-cloudtrail-logs-bucket.id # Bucket to send logs to (defined in s3.tf)
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true # attach hashes to validate no one has messed with log files

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.nyu-tdr-cloudwatch-log-group.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cloudwatch.arn

  depends_on = [aws_s3_bucket_policy.nyu-tdr-s3-cloudtrail-logs-bucket-policy] # Create bucket policy before creating cloudtrail so no conflict on inserting in to bucket
}

# -----------------------------------------------------------
# CloudWatch Log Group - where CloudTrail ships its logs
# -----------------------------------------------------------
resource "aws_cloudwatch_log_group" "nyu-tdr-cloudwatch-log-group" {
  name              = "/aws/cloudtrail/nyu-tdr-log-group"
  retention_in_days = 90
}

# -----------------------------------------------------------
# Metric Filter - counts every API call passing through
# -----------------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "api_call_volume" {
  name           = "APICallVolumeFilter"
  log_group_name = aws_cloudwatch_log_group.nyu-tdr-cloudwatch-log-group.name
  pattern        = "{ $.eventType = \"AwsApiCall\" }" # match any log entry where the eventType field equals AwsApiCall

  # Each time an event is detected increment the metric value by 1  
  metric_transformation {
    name      = "APICallCount"
    namespace = "NYU_TDR/CloudTrailMetrics"
    value     = "1"
  }
}

# -----------------------------------------------------------
# Metric Filter - flags high-risk IAM privilege escalation calls
# -----------------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "privilege_escalation" {
  name           = "PrivilegeEscalationFilter"
  log_group_name = aws_cloudwatch_log_group.nyu-tdr-cloudwatch-log-group.name
  pattern        = "{ ($.eventName = \"AttachUserPolicy\") || ($.eventName = \"CreateAccessKey\") || ($.eventName = \"AddUserToGroup\") || ($.eventName = \"PutUserPolicy\") || ($.eventName = \"ConsoleLogin\") }"

  metric_transformation {
    name      = "PrivilegeEscalationEventCount"
    namespace = "NYU_TDR/CloudTrailMetrics"
    value     = "1"
  }
}

# -----------------------------------------------------------
# Metric Filter - root login (should NEVER happen)
# -----------------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "root_login" {
  name           = "RootLoginFilter"
  log_group_name = aws_cloudwatch_log_group.nyu-tdr-cloudwatch-log-group.name
  pattern        = "{ $.userIdentity.type = \"Root\" && $.eventName = \"ConsoleLogin\" }"

  metric_transformation {
    name      = "RootLoginCount"
    namespace = "NYU_TDR/CloudTrailMetrics"
    value     = "1"
  }
}

# -----------------------------------------------------------
# Alarms
# -----------------------------------------------------------
resource "aws_cloudwatch_metric_alarm" "high_api_volume" {
  alarm_name          = "HighAPICallVolume"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1                               # If metric crosses threshold even 1 time trigger alaram (this can be configured for multiple crosses before triggering)
  metric_name         = "APICallCount"
  namespace           = "NYU_TDR/CloudTrailMetrics"
  period              = 300                             # 5-minute window of checking time
  statistic           = "Sum"                           # Sum needed since we are counting events
  threshold           = 100                             # Tuned against baselines
  alarm_description   = "Triggered when API call volume exceeds threshold in a 5-minute window"
  alarm_actions       = [aws_sns_topic.nyu-tdr-security_alerts.arn]
  treat_missing_data  = "notBreaching"                  # Don't raise alerts if no data points come in
}

resource "aws_cloudwatch_metric_alarm" "privilege_escalation" {
  alarm_name          = "PrivilegeEscalationDetected"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "PrivilegeEscalationEventCount"
  namespace           = "NYU_TDR/CloudTrailMetrics"
  period              = 60
  statistic           = "Sum"
  threshold           = 0                               # Raise privelege escalation immediately. Even if legitimate it should be verified
  alarm_description   = "Triggered on any privilege escalation API call"
  alarm_actions       = [aws_sns_topic.nyu-tdr-security_alerts.arn]
  treat_missing_data  = "notBreaching"
}

resource "aws_cloudwatch_metric_alarm" "root_login" {
  alarm_name          = "RootConsoleLogin"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "RootLoginCount"
  namespace           = "TDR/CloudTrailMetrics"
  period              = 60
  statistic           = "Sum"
  threshold           = 0                               # Raise root login alarm immediately as this shoudl never happen
  alarm_description   = "Emergency: root account console login detected"
  alarm_actions       = [aws_sns_topic.nyu-tdr-security_alerts.arn]
  treat_missing_data  = "notBreaching"
}
