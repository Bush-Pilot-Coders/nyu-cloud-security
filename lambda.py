import json
from datetime import datetime
import urllib.request
import time
import boto3

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table("IAMActivityTable")
sns = boto3.client("sns")
SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:367878387488:IAMRootConsoleLoginAlert"


def lambda_handler(event, context):
    for record in event["Records"]:
        # print(record)
        try:
            #Parse SQS body
            body = json.loads(record["body"])
         
            #Extract CloudTrail detail
            detail = body.get("detail", {})
            
            
            # Extract core fields
            parsed_event = parse_console_login(detail)
           
            # Add geo info
            if parsed_event['ip_address'] is not None:
                geo = get_geo(parsed_event['ip_address'])
                parsed_event.update(geo)
            else:
                parsed_event.update({
                    "country": "UNKNOWN",
                    "region": "UNKNOWN",
                    "city": "UNKNOWN"
                })

            table.put_item(Item = parsed_event)
            
            #Root Login Detection
            if parsed_event['user_id'] == "ROOT" and parsed_event['event_name'] == "ConsoleLogin":
                handle_root_login(parsed_event)
                
            

            
        except Exception as e:
            print("Error processing record:", str(e))

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
    