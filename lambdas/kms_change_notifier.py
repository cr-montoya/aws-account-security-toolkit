import json
import os

import boto3


def get_sns():
    return boto3.client("sns")


def lambda_handler(event, context):
    detail = event.get("detail", {})
    event_name = detail.get("eventName", "Unknown")
    request_parameters = detail.get("requestParameters", {})
    user_identity = detail.get("userIdentity", {})
    actor = user_identity.get("arn") or user_identity.get("principalId") or "unknown"
    key_id = request_parameters.get("keyId") or request_parameters.get("keyIdOrAlias") or "unknown"
    source_ip = detail.get("sourceIPAddress", "unknown")
    event_time = detail.get("eventTime", event.get("time", "unknown"))

    message = {
        "summary": "KMS key configuration change detected",
        "event_name": event_name,
        "event_time": event_time,
        "actor": actor,
        "key_id": key_id,
        "source_ip": source_ip,
        "account": event.get("account"),
        "region": event.get("region"),
        "event": event,
    }

    get_sns().publish(
        TopicArn=os.environ["ALERT_TOPIC_ARN"],
        Subject=f"AWS KMS change: {event_name}"[:100],
        Message=json.dumps(message, indent=2, default=str),
    )

    return {
        "notified": True,
        "event_name": event_name,
        "key_id": key_id,
        "actor": actor,
    }
