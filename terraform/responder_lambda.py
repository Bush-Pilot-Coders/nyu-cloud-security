# Dijone Mehmeti - Responder Lambda
# Implements automated IAM credential compromise response:
# - Detects suspicious activity
# - Disables active access keys
# - Attaches quarantine policy
# - Sends SNS alert

import json
import os
import boto3

iam = boto3.client("iam")
sns = boto3.client("sns")

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")
QUARANTINE_POLICY_ARN = os.environ.get("QUARANTINE_POLICY_ARN")

def lambda_handler(event, context):
    print("EVENT:", json.dumps(event))

    user = event.get("userName")
    ip = event.get("sourceIPAddress")
    action = event.get("eventName")

    if not user:
        return {"statusCode": 400, "body": "No user"}

    suspicious = (ip != "198.51.100.1" and action == "CreateAccessKey")

    if not suspicious:
        return {"statusCode": 200, "body": "No action needed"}

    keys = iam.list_access_keys(UserName=user)
    disabled = []

    for key in keys["AccessKeyMetadata"]:
        if key["Status"] == "Active":
            iam.update_access_key(
                UserName=user,
                AccessKeyId=key["AccessKeyId"],
                Status="Inactive"
            )
            disabled.append(key["AccessKeyId"])

    iam.attach_user_policy(
        UserName=user,
        PolicyArn=QUARANTINE_POLICY_ARN
    )

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject="Security Alert",
        Message=f"User {user} quarantined. Keys disabled: {disabled}"
    )

    return {
        "statusCode": 200,
        "body": json.dumps({
            "user": user,
            "disabled_keys": disabled
        })
    }
