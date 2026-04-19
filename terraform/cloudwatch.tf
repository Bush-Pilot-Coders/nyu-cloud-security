# --------------------------------------------------------
# Cloud Watch + Metrcis / Alarms Setup
# --------------------------------------------------------

resource "aws_cloudwatch_log_group" "nyu-cloudwatch-log-group" {
  name              = "/aws/cloudtrail/nyu-log-group"
  retention_in_days = 90
}


resource "aws_cloudwatch_log_metric_filter" "api_call_volume" {
  name           = "APICallVolumeFilter"
  log_group_name = aws_cloudwatch_log_group.nyu-cloudwatch-log-group.name
  pattern        = "{ $.eventType = \"AwsApiCall\" }" # match any log entry where the eventType field equals AwsApiCall


  # Each time an event is detected increment the metric value by 1 
  metric_transformation {
    name      = "APICallCount"
    namespace = "NYU/CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "privilege_escalation" {
  name           = "PrivilegeEscalationFilter"
  log_group_name = aws_cloudwatch_log_group.nyu-cloudwatch-log-group.name
  pattern        = "{ ($.eventName = \"AttachUserPolicy\") || ($.eventName = \"CreateAccessKey\") || ($.eventName = \"AddUserToGroup\") || ($.eventName = \"PutUserPolicy\") || ($.eventName = \"ConsoleLogin\") }"


  metric_transformation {
    name      = "PrivilegeEscalationEventCount"
    namespace = "NYU/CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "root_login" {
  name           = "RootLoginFilter"
  log_group_name = aws_cloudwatch_log_group.nyu-cloudwatch-log-group.name
  pattern        = "{ $.userIdentity.type = \"Root\" && $.eventName = \"ConsoleLogin\" }"


  metric_transformation {
    name      = "RootLoginCount"
    namespace = "NYU/CloudTrailMetrics"
    value     = "1"
  }
}


resource "aws_cloudwatch_metric_alarm" "high_api_volume" {
  alarm_name          = "HighAPICallVolume"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1 # If metric crosses threshold even 1 time trigger alaram (this can be configured for multiple crosses before triggering)
  metric_name         = "APICallCount"
  namespace           = "NYU/CloudTrailMetrics"
  period              = 300   # 5-minute window of checking time
  statistic           = "Sum" # Sum needed since we are counting events
  threshold           = 100   # Tuned against baselines
  alarm_description   = "Triggered when API call volume exceeds threshold in a 5-minute window"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching" # Don't raise alerts if no data points come in
}


resource "aws_cloudwatch_metric_alarm" "privilege_escalation" {
  alarm_name          = "PrivilegeEscalationDetected"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "PrivilegeEscalationEventCount"
  namespace           = "NYU/CloudTrailMetrics"
  period              = 60
  statistic           = "Sum"
  threshold           = 0 # Raise privelege escalation immediately. Even if legitimate it should be verified
  alarm_description   = "Triggered on any privilege escalation API call"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}


resource "aws_cloudwatch_metric_alarm" "root_login" {
  alarm_name          = "RootConsoleLogin"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "RootLoginCount"
  namespace           = "NYU/CloudTrailMetrics"
  period              = 60
  statistic           = "Sum"
  threshold           = 0 # Raise root login alarm immediately as this shoudl never happen
  alarm_description   = "Emergency: root account console login detected"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}
