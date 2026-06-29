import json
import os

import boto3
import security_hub


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
    security_hub.import_findings([{
        "control": "kms_key_configuration_change",
        "severity": "CRITICAL" if event_name == "ScheduleKeyDeletion" else "HIGH",
        "resource": key_id,
        "resource_type": "AwsKmsKey",
        "title": f"KMS key configuration changed: {event_name}",
        "detail": f"{actor} called {event_name} for KMS key {key_id} from {source_ip}.",
        "remediation": "Review the KMS key change immediately and cancel deletion or restore policy controls if unauthorized.",
        "guidance_url": "https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html",
    }], account_id=event.get("account"), region=event.get("region"))

    return {
        "notified": True,
        "event_name": event_name,
        "key_id": key_id,
        "actor": actor,
    }
