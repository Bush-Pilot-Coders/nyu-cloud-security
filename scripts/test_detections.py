#!/usr/bin/env python3
"""Trigger and verify the detection pipelines.

Covers:
  - EventBridge rule `nyu-cloudsec-iam-activity` (SQS -> Lambda)
  - CloudWatch metric alarms: HighAPICallVolume, PrivilegeEscalationDetected
  - Lambda responder write path (IAMActivityTable)

Does NOT cover:
  - RootConsoleLogin alarm (must be tested manually by logging into the root account)

Run with AdministratorAccess (non-root). See scripts/README.md.
"""
import argparse
import json
import logging
import random
import string
import sys
import time
import urllib.request
from datetime import datetime, timedelta, timezone

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

logger = logging.getLogger("detection-test")

BASELINE_TABLE = "IAMIPBaselineTable"
ACTIVITY_TABLE = "IAMActivityTable"
LAMBDA_NAME = "nyu-cloudsec-responder"
ALARMS = ["HighAPICallVolume", "PrivilegeEscalationDetected", "RootConsoleLogin"]
RESPONDER_BOGUS_IP = "192.0.2.1"  # RFC 5737 TEST-NET-1, unroutable
RESPONDER_GRANT_POLICY = "detection-test-responder-grant"
RESPONDER_TRIGGER_POLICY = "detection-test-responder-trigger"


# ---------- helpers ----------

def public_ip():
    with urllib.request.urlopen("https://checkip.amazonaws.com", timeout=5) as r:
        return r.read().decode().strip()


def caller_user_id(sts):
    """Mirror lambda.py::extract_user() using sts:GetCallerIdentity."""
    arn = sts.get_caller_identity()["Arn"]
    # arn:aws:sts::ACCT:assumed-role/ROLE/SESSION  or  arn:aws:iam::ACCT:user/NAME
    if "/" in arn:
        return arn.split("/")[-1]
    return arn


def rand_suffix(n=6):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


# ---------- seed / unseed baseline ----------

def seed_baseline(ddb, user_id, ip):
    now = int(time.time())
    ddb.Table(BASELINE_TABLE).put_item(
        Item={
            "user_id": user_id,
            "trusted_ips": [ip],
            "known_ips": [{"ip": ip, "timestamps": [now]}],
            "last_seen": now,
        }
    )
    logger.info("seeded baseline user_id=%s trusted_ip=%s", user_id, ip)


def remove_baseline(ddb, user_id):
    try:
        ddb.Table(BASELINE_TABLE).delete_item(Key={"user_id": user_id})
        logger.info("removed seeded baseline for %s", user_id)
    except ClientError as e:
        logger.warning("failed to remove baseline: %s", e)


# ---------- triggers ----------

def create_test_user(iam, name):
    iam.create_user(UserName=name)
    logger.info("created test user %s", name)


def delete_test_user(iam, name):
    try:
        for p in iam.list_attached_user_policies(UserName=name).get("AttachedPolicies", []):
            iam.detach_user_policy(UserName=name, PolicyArn=p["PolicyArn"])
        for p in iam.list_user_policies(UserName=name).get("PolicyNames", []):
            iam.delete_user_policy(UserName=name, PolicyName=p)
        for k in iam.list_access_keys(UserName=name).get("AccessKeyMetadata", []):
            iam.delete_access_key(UserName=name, AccessKeyId=k["AccessKeyId"])
        try:
            iam.delete_login_profile(UserName=name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise
        for g in iam.list_groups_for_user(UserName=name).get("Groups", []):
            iam.remove_user_from_group(GroupName=g["GroupName"], UserName=name)
        iam.delete_user(UserName=name)
        logger.info("deleted test user %s", name)
    except ClientError as e:
        logger.warning("cleanup issue for user %s: %s", name, e)


def trigger_events(iam, test_user, group_name):
    results = []
    access_key_id = None

    try:
        k = iam.create_access_key(UserName=test_user)["AccessKey"]
        access_key_id = k["AccessKeyId"]
        results.append(("CreateAccessKey", True, None))
    except ClientError as e:
        results.append(("CreateAccessKey", False, str(e)))

    try:
        iam.attach_user_policy(
            UserName=test_user,
            PolicyArn="arn:aws:iam::aws:policy/ReadOnlyAccess",
        )
        results.append(("AttachUserPolicy", True, None))
    except ClientError as e:
        results.append(("AttachUserPolicy", False, str(e)))

    try:
        iam.put_user_policy(
            UserName=test_user,
            PolicyName="detection-test-inline",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"}],
            }),
        )
        results.append(("PutUserPolicy", True, None))
    except ClientError as e:
        results.append(("PutUserPolicy", False, str(e)))

    try:
        iam.create_login_profile(
            UserName=test_user,
            Password="TempP@ss" + rand_suffix(10) + "!",
            PasswordResetRequired=True,
        )
        results.append(("CreateLoginProfile", True, None))
    except ClientError as e:
        results.append(("CreateLoginProfile", False, str(e)))

    group_ok = True
    try:
        iam.create_group(GroupName=group_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "EntityAlreadyExists":
            results.append(("AddUserToGroup", False, f"group create: {e}"))
            group_ok = False
    if group_ok:
        try:
            iam.add_user_to_group(GroupName=group_name, UserName=test_user)
            results.append(("AddUserToGroup", True, None))
        except ClientError as e:
            results.append(("AddUserToGroup", False, str(e)))

    if access_key_id:
        try:
            iam.delete_access_key(UserName=test_user, AccessKeyId=access_key_id)
            results.append(("DeleteAccessKey", True, None))
        except ClientError as e:
            results.append(("DeleteAccessKey", False, str(e)))
    else:
        results.append(("DeleteAccessKey", False, "no access key to delete"))

    return results


def setup_responder_test(session, iam, ddb, test_user, account_id):
    """Exercise lambda.revoke_user_keys against test_user.

    Grants test_user permission to PutUserPolicy on itself, creates a fresh
    programmatic key, seeds a baseline for test_user whose trusted IP is
    bogus, then invokes a sensitive action (PutUserPolicy) as test_user so
    the responder sees an untrusted-IP sensitive event and revokes the key.
    Returns True if the trigger call succeeded.
    """
    grant = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "iam:PutUserPolicy",
            "Resource": f"arn:aws:iam::{account_id}:user/{test_user}",
        }],
    }
    iam.put_user_policy(
        UserName=test_user,
        PolicyName=RESPONDER_GRANT_POLICY,
        PolicyDocument=json.dumps(grant),
    )

    key = iam.create_access_key(UserName=test_user)["AccessKey"]
    logger.info("responder-test: created key %s for %s", key["AccessKeyId"], test_user)

    seed_baseline(ddb, test_user, RESPONDER_BOGUS_IP)

    # IAM key + policy attach are eventually consistent; give them a moment.
    time.sleep(15)

    test_sess = boto3.Session(
        aws_access_key_id=key["AccessKeyId"],
        aws_secret_access_key=key["SecretAccessKey"],
        region_name=session.region_name,
    )
    test_iam = test_sess.client("iam")
    trigger_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"}],
    }
    last_err = None
    for attempt in range(6):
        try:
            test_iam.put_user_policy(
                UserName=test_user,
                PolicyName=RESPONDER_TRIGGER_POLICY,
                PolicyDocument=json.dumps(trigger_policy),
            )
            logger.info("responder-test: %s performed PutUserPolicy on self", test_user)
            return True
        except ClientError as e:
            last_err = e
            logger.info("responder-test: trigger attempt %d not yet usable: %s",
                        attempt, e.response["Error"]["Code"])
            time.sleep(5)
    logger.warning("responder-test: test_user never gained perms to trigger: %s", last_err)
    return False


def verify_responder_revoke(iam, test_user):
    """Returns (all_inactive, {key_id: status}) for test_user's keys."""
    keys = iam.list_access_keys(UserName=test_user).get("AccessKeyMetadata", [])
    statuses = {k["AccessKeyId"]: k["Status"] for k in keys}
    all_inactive = len(keys) > 0 and all(s == "Inactive" for s in statuses.values())
    return all_inactive, statuses


def get_quarantine_policy_arn(lam):
    """Read QUARANTINE_POLICY_ARN from the responder Lambda's env."""
    cfg = lam.get_function_configuration(FunctionName=LAMBDA_NAME)
    return (cfg.get("Environment", {}).get("Variables") or {}).get("QUARANTINE_POLICY_ARN")


def verify_responder_quarantine(iam, test_user, quarantine_arn):
    """True iff test_user has quarantine_arn attached."""
    attached = iam.list_attached_user_policies(UserName=test_user).get("AttachedPolicies", [])
    arns = [p["PolicyArn"] for p in attached]
    return quarantine_arn in arns, arns


def burst_api_calls(iam, count):
    logger.info("issuing %d list_users calls to drive HighAPICallVolume", count)
    for i in range(count):
        try:
            iam.list_users(MaxItems=1)
        except ClientError as e:
            logger.warning("list_users call %d failed: %s", i, e)
            return i
    return count


# ---------- verification ----------

def alarm_states(cw):
    resp = cw.describe_alarms(AlarmNames=ALARMS)
    return {a["AlarmName"]: a["StateValue"] for a in resp.get("MetricAlarms", [])}


def recent_activity_rows(ddb, since_epoch, user_id):
    table = ddb.Table(ACTIVITY_TABLE)
    resp = table.query(
        KeyConditionExpression=Key("user_id").eq(user_id) & Key("timestamp").gte(since_epoch),
    )
    return resp.get("Items", [])


def lambda_invocations(cw, since):
    resp = cw.get_metric_statistics(
        Namespace="AWS/Lambda",
        MetricName="Invocations",
        Dimensions=[{"Name": "FunctionName", "Value": LAMBDA_NAME}],
        StartTime=since,
        EndTime=datetime.now(timezone.utc),
        Period=60,
        Statistics=["Sum"],
    )
    return sum(int(p["Sum"]) for p in resp.get("Datapoints", []))


# ---------- main ----------

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--burst", type=int, default=110,
                   help="number of list_users calls (needs >100 in 5min for HighAPICallVolume)")
    p.add_argument("--wait", type=int, default=180,
                   help="seconds to wait between triggers and verification")
    p.add_argument("--no-cleanup", action="store_true",
                   help="keep test user, group, and seeded baseline after run")
    p.add_argument("--skip-seed", action="store_true",
                   help="do NOT pre-seed admin baseline (risks admin self-quarantine attempt)")
    p.add_argument("--skip-burst", action="store_true",
                   help="skip list_users burst (HighAPICallVolume will not fire)")
    p.add_argument("--skip-responder", action="store_true",
                   help="skip revoke_user_keys test (keys-go-Inactive verification)")
    args = p.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    session = boto3.Session(region_name=args.region)
    sts = session.client("sts")
    iam = session.client("iam")
    ddb = session.resource("dynamodb")
    cw = session.client("cloudwatch")
    lam = session.client("lambda")

    started = datetime.now(timezone.utc)
    started_epoch = int(started.timestamp())

    caller = sts.get_caller_identity()
    account_id = caller["Account"]
    admin_user_id = caller_user_id(sts)
    my_ip = public_ip()
    logger.info("caller user_id=%s public_ip=%s", admin_user_id, my_ip)

    if not args.skip_seed:
        seed_baseline(ddb, admin_user_id, my_ip)

    run_id = rand_suffix(6)
    test_user = f"nyu-cloudsec-detectiontest-{run_id}"
    group_name = f"nyu-cloudsec-detectiontest-grp-{run_id}"

    rc = 1
    trigger_results = []
    try:
        create_test_user(iam, test_user)
        trigger_results = trigger_events(iam, test_user, group_name)
        for action, ok, err in trigger_results:
            logger.info("trigger %s: %s %s", action, "OK" if ok else "FAIL", err or "")

        if not args.skip_burst:
            burst_api_calls(iam, args.burst)

        responder_triggered = False
        if not args.skip_responder:
            responder_triggered = setup_responder_test(
                session, iam, ddb, test_user, account_id
            )

        logger.info("waiting %ds for CloudTrail -> CloudWatch / Lambda propagation", args.wait)
        time.sleep(args.wait)

        states = alarm_states(cw)
        rows = recent_activity_rows(ddb, started_epoch - 60, admin_user_id)
        invs = lambda_invocations(cw, started - timedelta(minutes=1))
        responder_ok = False
        responder_statuses = {}
        quarantine_arn = None
        quarantine_ok = False
        quarantine_attached = []
        if responder_triggered:
            responder_ok, responder_statuses = verify_responder_revoke(iam, test_user)
            quarantine_arn = get_quarantine_policy_arn(lam)
            if quarantine_arn:
                quarantine_ok, quarantine_attached = verify_responder_quarantine(
                    iam, test_user, quarantine_arn
                )

        print("\n========== DETECTION TEST RESULTS ==========")
        print(f"run_id:                {run_id}")
        print(f"admin user_id (seen):  {admin_user_id}")
        print(f"test user:             {test_user}")
        print(f"public IP:             {my_ip}")
        print()
        print("Triggers:")
        for action, ok, err in trigger_results:
            print(f"  {'[OK]' if ok else '[FAIL]'} {action}" + (f"   ({err})" if err else ""))
        print()
        print("Alarm states:")
        for name in ALARMS:
            suffix = "  (manual test only)" if name == "RootConsoleLogin" else ""
            print(f"  {name}: {states.get(name, 'UNKNOWN')}{suffix}")
        print()
        print(f"Lambda invocations since {started.isoformat()}: {invs}")
        print(f"IAMActivityTable rows (admin, this run): {len(rows)}")
        by_action = {}
        for r in rows:
            by_action[r.get("event_name", "?")] = by_action.get(r.get("event_name", "?"), 0) + 1
        for k, v in sorted(by_action.items()):
            print(f"  {k}: {v}")
        if not args.skip_responder:
            print()
            if not responder_triggered:
                print("Responder revoke test:     TRIGGER FAILED (see log)")
                print("Responder quarantine test: SKIPPED (trigger failed)")
            else:
                revoke_label = "OK" if responder_ok else "FAIL"
                print(f"Responder revoke test:     {revoke_label}  (keys: {responder_statuses})")
                if not quarantine_arn:
                    print("Responder quarantine test: SKIPPED (QUARANTINE_POLICY_ARN not set on lambda)")
                else:
                    q_label = "OK" if quarantine_ok else "FAIL"
                    print(f"Responder quarantine test: {q_label}  "
                          f"(expected {quarantine_arn}, attached: {quarantine_attached})")
        print("============================================")
        print("Note: EventBridge rule does NOT route AddUserToGroup -> Lambda.")
        print("      It fires the PrivilegeEscalation metric only.")
        print()

        ok_pipelines = (
            states.get("PrivilegeEscalationDetected") == "ALARM"
            and (args.skip_burst or states.get("HighAPICallVolume") == "ALARM")
            and invs > 0
            and len(rows) > 0
            and (args.skip_responder or responder_ok)
            and (args.skip_responder or not quarantine_arn or quarantine_ok)
        )
        if ok_pipelines:
            logger.info("detection pipelines firing as expected")
            rc = 0
        else:
            logger.warning("some detections did not fire yet; CloudTrail delivery can take "
                           "several minutes. Re-run with --skip-seed --skip-burst --no-cleanup "
                           "and a longer --wait to re-verify.")
            rc = 1
    finally:
        if not args.no_cleanup:
            delete_test_user(iam, test_user)
            try:
                iam.delete_group(GroupName=group_name)
            except ClientError as e:
                if e.response["Error"]["Code"] != "NoSuchEntity":
                    logger.warning("failed to delete group: %s", e)
            if not args.skip_seed:
                remove_baseline(ddb, admin_user_id)
            if not args.skip_responder:
                remove_baseline(ddb, test_user)

    sys.exit(rc)


if __name__ == "__main__":
    main()
