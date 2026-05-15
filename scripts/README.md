# Detection test script

`test_detections.py` exercises the EventBridge rule, metric-filter alarms,
and the Lambda responder, then verifies each pipeline caught the events.

## What it tests

| Detection | How it's tested |
|---|---|
| EventBridge rule `nyu-cloudsec-iam-activity` -> SQS -> Lambda | Runs `CreateAccessKey`, `AttachUserPolicy`, `PutUserPolicy`, `CreateLoginProfile`, `DeleteAccessKey` on a throwaway user. Verifies rows land in `IAMActivityTable` and Lambda `Invocations` metric is > 0. |
| `PrivilegeEscalationDetected` alarm | Above events (plus `AddUserToGroup`) all match the metric filter. Verifies alarm in `ALARM` state. |
| `HighAPICallVolume` alarm | Bursts 110 `list_users` calls. Verifies alarm in `ALARM` state. |
| `RootConsoleLogin` alarm | **Manual** — log into the root account. |

## Requirements

- Python 3.8+.
- AWS credentials for a principal with `AdministratorAccess` (or equivalent IAM admin + DynamoDB read/write + CloudWatch read).
- The stack from `terraform/` already applied in `us-east-1`.

## Setup (one-time)

A virtualenv lives at `.venv/` in the repo root.

```
# if not already created:
virtualenv -p /usr/bin/python3 .venv

source .venv/bin/activate
pip install -r scripts/requirements.txt
```

## Usage

```
source .venv/bin/activate
python scripts/test_detections.py
```

Common flags:

```
--region us-east-1        # default
--wait 180                # seconds to wait for CloudTrail propagation
--burst 110               # list_users calls; needs >100 in 5min for HighAPICallVolume
--skip-burst              # skip the high-volume portion
--skip-seed               # do NOT pre-seed admin baseline (see warning below)
--no-cleanup              # keep test user, group, seeded baseline
```

## Why the script pre-seeds the admin baseline

The Lambda looks up the baseline using the CloudTrail caller's identity. When
**you** (admin) run `iam:CreateAccessKey test-user`, CloudTrail records the
caller as your admin role, not the test user. Without a pre-seeded baseline
the Lambda would flag the 2nd sensitive action as coming from an untrusted IP
and attempt to quarantine the admin role -- the IAM calls fail (role ARN, not
user ARN) but an SNS alert would still fire.

Pre-seeding inserts the admin's `user_id` into `IAMIPBaselineTable` with your
current public IP marked as trusted, then removes the entry on cleanup.

If you *want* to exercise the quarantine response path, use `--skip-seed`
against a disposable environment, or test it separately with the demo from
`DESIGN.md` (seeded test user + that user's own keys from a different IP).

## Reading the output

The script prints a summary like:

```
========== DETECTION TEST RESULTS ==========
run_id:                a9k3x1
admin user_id (seen):  kevtar-session
test user:             nyu-cloudsec-detectiontest-a9k3x1
public IP:             1.2.3.4

Triggers:
  [OK] CreateAccessKey
  [OK] AttachUserPolicy
  ...

Alarm states:
  HighAPICallVolume: ALARM
  PrivilegeEscalationDetected: ALARM
  RootConsoleLogin: OK  (manual test only)

Lambda invocations since ...: 5
IAMActivityTable rows (admin, this run): 5
  AttachUserPolicy: 1
  CreateAccessKey: 1
  ...
```

Exit code is `0` when all automated pipelines fired, `1` otherwise.

## Troubleshooting

- **Alarm still in `OK`**: CloudTrail -> CloudWatch Logs delivery is typically
  under 5 minutes but can lag. Re-run with `--skip-seed --skip-burst
  --no-cleanup --wait 420` to re-verify without re-triggering.
- **`AIDA...` style user_id instead of session name**: your caller may be an
  IAM user, not an assumed role. The script handles both; just confirm the
  `admin user_id (seen)` matches what CloudTrail is recording.
- **Test user stuck around after a crash**: delete it manually in IAM, or
  re-run with the same flags -- cleanup is idempotent.
