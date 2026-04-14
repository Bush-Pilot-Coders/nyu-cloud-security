# Automated Credential Compromise Detection & Containment

## Problem

Leaked AWS credentials are the #1 cloud breach vector (CSA Top Threats 2025). We detect and contain compromise automatically.

## Attack Scenario

Developer commits AWS keys to GitHub → attacker scans & finds them → runs CLI from foreign IP → enumerates IAM → escalates privileges → launches EC2 for mining → attempts S3 exfiltration.

## Architecture

```
                 ┌──────────────┐
 AWS API calls → │  CloudTrail  │
                 └──────┬───────┘
                        │ (events)
          ┌─────────────┴─────────────┐
          ▼                           ▼
   ┌─────────────┐            ┌───────────────┐
   │ CloudWatch  │            │  EventBridge  │
   │ Metric Flt  │            │ Rules (IAM/   │
   │ + Alarms    │            │  root login)  │
   └──────┬──────┘            └───────┬───────┘
          │                           │
          └─────────────┬─────────────┘
                        ▼
                 ┌──────────────┐      ┌──────────────┐
                 │    Lambda    │<────>│   DynamoDB   │
                 │  Responder   │      │  baselines   │
                 └──────┬───────┘      └──────────────┘
                        │
          ┌─────────────┼─────────────┐
          ▼             ▼             ▼
     RevokeKeys   AttachQuarantine   SNS Alert
```

## Components

| Layer | Service | Purpose |
|-------|---------|---------|
| Audit | CloudTrail | Capture all API calls |
| Baseline | DynamoDB | Store per-user IPs, call rates, patterns |
| Detect (volume) | CloudWatch metric filter + alarm | Flag API call spikes |
| Detect (risk) | EventBridge rule | Match high-risk calls: `AttachUserPolicy`, `CreateAccessKey`, `AddUserToGroup`, `PutUserPolicy`, `ConsoleLogin` |
| Detect (root) | EventBridge rule | Any root `ConsoleLogin` → emergency SNS |
| Respond | Lambda | Compare vs. baseline, contain, notify |
| Notify | SNS | Page security team |

## Lambda Response Flow

1. Receive event from EventBridge / CloudWatch.
2. Look up user baseline in DynamoDB (known IPs, country, typical call rate).
3. Score: unknown IP + risk action → **compromised**.
4. Containment:
   - `iam:UpdateAccessKey` → deactivate keys
   - `iam:AttachUserPolicy` → attach `DenyAll` quarantine policy
5. Publish incident to SNS topic.

## Quarantine Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Action": "*",
    "Resource": "*"
  }]
}
```

## Deployment

Terraform modules in [terraform/](terraform/):
- `cloudtrail/` — trail + S3 bucket
- `detection/` — CloudWatch + EventBridge rules
- `dynamodb/` — baseline table
- `lambda/` — responder function + IAM role
- `sns/` — alert topic

## Demo Plan

1. Create test IAM user with keys.
2. Seed baseline in DynamoDB (home IP/region).
3. From a different IP, run: `aws iam create-access-key`.
4. Observe: EventBridge fires → Lambda runs → keys deactivated → SNS email received.
5. Simulate root login → emergency alert.

## CSA Threats Addressed

- T1: IAM failures
- T2: Misconfiguration & inadequate change control
- T3: Insecure software development (leaked secrets)
