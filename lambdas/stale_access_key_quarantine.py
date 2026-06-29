import json
import os
from datetime import datetime, timezone

import boto3


def get_iam():
    return boto3.client("iam")


def get_sns():
    return boto3.client("sns")

DENY_ALL_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "SecurityToolkitDenyAllDueToStaleAccessKey",
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
        }
    ],
}


def lambda_handler(event, context):
    dry_run = os.environ.get("DRY_RUN", "true").lower() == "true"
    stale_key_days = int(os.environ.get("STALE_KEY_DAYS", "90"))
    policy_name = os.environ.get("QUARANTINE_POLICY_NAME", "SecurityToolkitDenyAllDueToStaleAccessKey")
    now = datetime.now(timezone.utc)
    quarantined = []
    iam = get_iam()

    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page.get("Users", []):
            user_name = user["UserName"]
            stale_keys = _stale_active_keys(iam, user_name, now, stale_key_days)
            if not stale_keys:
                continue

            action = {
                "user_name": user_name,
                "stale_access_keys": stale_keys,
                "dry_run": dry_run,
            }
            quarantined.append(action)

            if not dry_run:
                iam.put_user_policy(
                    UserName=user_name,
                    PolicyName=policy_name,
                    PolicyDocument=json.dumps(DENY_ALL_POLICY),
                )
                iam.tag_user(
                    UserName=user_name,
                    Tags=[
                        {"Key": "SecurityToolkit", "Value": "Quarantined"},
                        {"Key": "SecurityToolkitReason", "Value": "StaleAccessKey"},
                    ],
                )

    if quarantined:
        _notify(quarantined)

    return {
        "dry_run": dry_run,
        "stale_key_days": stale_key_days,
        "quarantined_users": quarantined,
    }


def _stale_active_keys(iam, user_name, now, stale_key_days):
    stale_keys = []
    response = iam.list_access_keys(UserName=user_name)

    for key in response.get("AccessKeyMetadata", []):
        if key.get("Status") != "Active":
            continue

        access_key_id = key["AccessKeyId"]
        last_used_response = iam.get_access_key_last_used(AccessKeyId=access_key_id)
        last_used = last_used_response.get("AccessKeyLastUsed", {}).get("LastUsedDate")
        created = key["CreateDate"]
        reference_date = last_used or created
        age_days = (now - reference_date).days

        if age_days >= stale_key_days:
            stale_keys.append({
                "access_key_id": access_key_id,
                "age_days": age_days,
                "last_used": last_used.isoformat() if last_used else None,
                "created": created.isoformat(),
            })

    return stale_keys


def _notify(quarantined):
    get_sns().publish(
        TopicArn=os.environ["ALERT_TOPIC_ARN"],
        Subject="AWS stale access key quarantine report",
        Message=json.dumps({
            "summary": "Stale active IAM access keys detected",
            "quarantined_users": quarantined,
        }, indent=2, default=str),
    )
