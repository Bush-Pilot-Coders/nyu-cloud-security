resource "aws_sns_topic" "nyu-tdr-security_alerts" {
  name = "nyu-tdr-security-alerts"
}

# Email subscription - replace with your team's address
resource "aws_sns_topic_subscription" "nyu-tdr-security_alerts_email" {
  topic_arn = aws_sns_topic.nyu-tdr-security_alerts.arn
  protocol  = "email"
  endpoint  = "kt1661@nyu.edu"
}