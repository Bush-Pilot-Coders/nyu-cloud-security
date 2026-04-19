import json
from datetime import datetime
import urllib.request
import time
import boto3
import traceback

dynamodb = boto3.resource("dynamodb")
iam_activity_table = dynamodb.Table("IAMActivityTable")
sns = boto3.client("sns")
SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:367878387488:IAMRootConsoleLoginAlert"
baseline_table = dynamodb.Table("IAMIPBaselineTable")

SENSITIVE_ACTIONS = {
    "CreateAccessKey",
    "DeleteAccessKey",
    "AttachUserPolicy",
    "PutUserPolicy",
    "CreateLoginProfile"
}

def lambda_handler(event, context):
    for record in event["Records"]:
        # print(record)
        try:
            #Parse SQS body
            body = json.loads(record["body"])
         
            #Extract CloudTrail detail
            detail = body.get("detail", {})
            
            # Step 3: Only process ConsoleLogin
            # if detail.get("eventName") != "ConsoleLogin":
            #     continue
            
            # Extract core fields
            parsed_event = parse_console_login(detail)
           
            # Add geo info
            if parsed_event['ip_address'] is not None:
                geo = get_geo(parsed_event['ip_address'])
                parsed_event.update(geo)
                
                #record event
                iam_activity_table.put_item(Item = parsed_event)
                
                handle_ip_evnet(parsed_event)
            else:
                parsed_event.update({
                    "country": "UNKNOWN",
                    "region": "UNKNOWN",
                    "city": "UNKNOWN"
                })
                
                #record event
                iam_activity_table.put_item(Item = parsed_event)
                
                
            
            
            
            #Root Login Detection
            if parsed_event['user_id'] == "ROOT" and parsed_event['event_name'] == "ConsoleLogin":
                handle_root_login(parsed_event)
                
             
            # 👉 Next layer:
            # - Geo-IP lookup
            # - DynamoDB write
            # - anomaly detection
            
        except Exception as e:
            print("ERROR:", str(e))
            print(traceback.format_exc())   
            raise
            
def handle_ip_evnet(event):
    user_id, ip, time = event["user_id"], event["ip_address"], event["timestamp"]
    action = event['event_name']
    #get base line
    baseline = get_baseline(user_id)
    
    # create base line if not exist
    if not baseline:
        create_baseline(user_id, ip, time)
        return
    
    newbaseline = update_baseline(user_id, ip, time, baseline)
    
    trusted_ips = newbaseline['trusted_ips']

    is_untrusted_ip = ip not in trusted_ips
    
    if is_untrusted_ip:
        if action in SENSITIVE_ACTIONS:
            # revoke_user_key()
            send_alert(action, event)
    else:
        update_baseline(user_id, ip, "UNKNOWN")

def send_alert(action, event):
    message = f"""
        🚨 UNAUTHORIZED ACTION DETECTED 🚨

        Action: {action}
        User ID: {event["user_id"]}
        Time: {event["timestamp"]}
        IP: {event["ip_address"]}
        Country: {event["country"]}
        Region: {event['region']}
        City: {event['city']}

    """
    
    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject="🚨 Unauthorized action Alert",
        Message=message
    )

    print("alert sent")
    
            
def get_baseline(user_id):
    resp = baseline_table.get_item(Key={"user_id": user_id})
    return resp.get("Item")

def create_baseline(user_id, ip, time):
    baseline_table.put_item(
        Item={
            "user_id": user_id,
            "trusted_ips": [ip],
            "known_ips": [
                {"ip": ip, "timestamps": [time]}
            ],
            "last_seen": time
        }
    )
    return

def update_baseline(user_id, ip, timestamp, baseline):

    trusted = baseline.get("trusted_ips", [])
    known = baseline.get("known_ips", [])

    # ------------------------
    # 1. UPDATE KNOWN IPS
    # ------------------------
    found = False

    for entry in known:
        if entry["ip"] == ip:
            entry["timestamps"].append(timestamp)
            found = True
            break

    if not found:
        known.append({
            "ip": ip,
            "timestamps": [timestamp]
        })

    # ------------------------
    # 2. LIMIT KNOWN IPS
    # ------------------------
    # 5 known ip max, remove the oldest ip
    if len(known) > 5:
        # remove IP with oldest timestamp
        known.sort(key=lambda x: max(x["timestamps"]))
        known.pop(0)

    # ------------------------
    # 3. PROMOTION CHECK
    # ------------------------
    # if ip appear 3 times or more in known with each appearence in a different day, promote to trusted
    for entry in known:
        timestamps = entry["timestamps"]

        days = set(t // 86400 for t in timestamps)

        if len(days) >= 3:
            ip_candidate = entry["ip"]

            if ip_candidate not in trusted:
                trusted.append(ip_candidate)

    # ------------------------
    # 4. CLEANUP TRUSTED IPS
    # ------------------------
    # remove trusted ip that are not in known ip
    known_ip_set = {entry["ip"] for entry in known}

    trusted = [ip for ip in trusted if ip in known_ip_set]
    
    # ------------------------
    # 5. LIMIT TRUSTED IPS
    # ------------------------
    # 3 trusted ip max
    if len(trusted) > 3:
        trusted = trusted[-3:]  # keep newest

    ret =  {
        "user_id": user_id,
        "trusted_ips": trusted,
        "known_ips": known,
        "last_seen": timestamp
    }
    
    
    baseline_table.put_item(
    Item=ret,
    ConditionExpression="attribute_exists(user_id)"
    )
    
    return ret

def handle_root_login(detail):
 
        
    message = f"""
        🚨 ROOT ACCOUNT LOGIN DETECTED 🚨

        Status: {detail["login_status"]}
        Time: {detail["timestamp"]}
        IP: {detail["ip_address"]}
        Country: {detail["country"]}
        Region: {detail['region']}
        City: {detail['city']}

        """

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject="🚨 AWS Root Login Alert",
        Message=message
    )

    print("Root login alert sent")

def get_geo(ip):
    try:
        url = f"https://ipapi.co/{ip}/json/"
        with urllib.request.urlopen(url, timeout=5) as res:
            data = json.loads(res.read())
            return {
                "country": data.get("country"),
                "region": data.get("region"),
                "city": data.get("city")
            }
    except Exception as e:
        print("Geo error:", e)
        return {
                    "country": "UNKNOWN",
                    "region": "UNKNOWN",
                    "city": "UNKNOWN"
                }

def parse_console_login(detail):
    """Normalize ConsoleLogin event into safe structured format"""

    try:
        user_identity = detail.get("userIdentity") or {}

        # user normalization
        user_id = extract_user(user_identity)

        # safe timestamp parsing
        event_time = detail.get("eventTime")
        timestamp = parse_time(event_time) if event_time else None

        # safe IP handling
        ip_address = detail.get("sourceIPAddress")
        if not ip_address or ip_address.strip() == "":
            ip_address = ''

        # response safety
        response = detail.get("responseElements") or {}
        login_status = response.get("ConsoleLogin")

        return {
            "event_name": detail.get("eventName", "UNKNOWN"),
            "user_id": user_id,
            "ip_address": ip_address,
            "timestamp": timestamp,
            "login_status": login_status,
            "user_type": user_identity.get("type", "UNKNOWN"),
            "user_agent": detail.get("userAgent", "UNKNOWN")
        }

    except Exception as e:
        print("Failed to parse ConsoleLogin event:", str(e))
        return None
    


def extract_user(user_identity):
    """Handles IAMUser, Root, AssumedRole cleanly"""
    
    identity_type = user_identity.get("type")
    
    if identity_type == "IAMUser":
        return user_identity.get("userName")
    
    elif identity_type == "Root":
        return "ROOT"
    
    elif identity_type == "AssumedRole":
        # Example: arn:aws:sts::123:assumed-role/role-name/session
        arn = user_identity.get("arn", "")
        return arn.split("/")[-1] if "/" in arn else arn
    
    return "UNKNOWN"


def parse_time(time_str):
    if not time_str:
        return None
    return int(datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%SZ").timestamp())

# with open('testdata.json', 'r') as f:
#     # fdata = f.read()

#     lambda_handler(json.load(f), None)
    