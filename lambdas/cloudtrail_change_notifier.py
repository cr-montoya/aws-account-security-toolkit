import json
import os

import boto3
import security_hub


def get_sns():
    return boto3.client("sns")


def lambda_handler(event, context):
    detail = event.get("detail", {})
    event_name = detail.get("eventName", "Unknown")
    user_identity = detail.get("userIdentity", {})
    actor = user_identity.get("arn") or user_identity.get("principalId") or "unknown"
    source_ip = detail.get("sourceIPAddress", "unknown")
    event_time = detail.get("eventTime", event.get("time", "unknown"))

    message = {
        "summary": "CloudTrail configuration change detected",
        "event_name": event_name,
        "event_time": event_time,
        "actor": actor,
        "source_ip": source_ip,
        "account": event.get("account"),
        "region": event.get("region"),
        "event": event,
    }

    get_sns().publish(
        TopicArn=os.environ["ALERT_TOPIC_ARN"],
        Subject=f"AWS CloudTrail change: {event_name}"[:100],
        Message=json.dumps(message, indent=2, default=str),
    )
    security_hub.import_findings([{
        "control": "cloudtrail_configuration_change",
        "severity": "HIGH",
        "resource": event.get("account", "unknown-account"),
        "resource_type": "AwsAccount",
        "title": f"CloudTrail configuration changed: {event_name}",
        "detail": f"{actor} called {event_name} from {source_ip}.",
        "remediation": "Review the CloudTrail change, confirm it was authorized, and restore logging if needed.",
        "guidance_url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html",
    }], account_id=event.get("account"), region=event.get("region"))

    return {
        "notified": True,
        "event_name": event_name,
        "actor": actor,
        "source_ip": source_ip,
    }
