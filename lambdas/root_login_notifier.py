import json
import os

import boto3


def get_sns():
    return boto3.client("sns")


def lambda_handler(event, context):
    detail = event.get("detail", {})
    console_login = detail.get("responseElements", {}).get("ConsoleLogin", "Unknown")
    source_ip = detail.get("sourceIPAddress", "unknown")
    mfa_used = detail.get("additionalEventData", {}).get("MFAUsed", "Unknown")
    event_time = detail.get("eventTime", event.get("time", "unknown"))

    subject = f"AWS root console sign-in {console_login}"
    message = {
        "summary": "Root user console sign-in event detected",
        "console_login": console_login,
        "event_time": event_time,
        "source_ip": source_ip,
        "mfa_used": mfa_used,
        "account": event.get("account"),
        "region": event.get("region"),
        "event": event,
    }

    get_sns().publish(
        TopicArn=os.environ["ALERT_TOPIC_ARN"],
        Subject=subject[:100],
        Message=json.dumps(message, indent=2, default=str),
    )

    return {
        "notified": True,
        "console_login": console_login,
        "source_ip": source_ip,
    }
