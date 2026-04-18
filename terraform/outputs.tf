output "sns_topic_arn" {
  description = "ARN of the security alerts SNS topic"
  value       = aws_sns_topic.nyu-tdr-security_alerts.arn
}

output "cloudtrail_log_group" {
  description = "CloudWatch Log Group receiving CloudTrail events"
  value       = aws_cloudwatch_log_group.nyu-tdr-cloudwatch-log-group.name
}

output "cloudtrail_s3_bucket" {
  description = "S3 bucket storing raw CloudTrail logs"
  value       = aws_s3_bucket.nyu-tdr-s3-cloudtrail-logs-bucket.bucket
}