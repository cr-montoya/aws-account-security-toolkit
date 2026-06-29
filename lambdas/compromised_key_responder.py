import json
import os
import re

import boto3
import security_hub


def get_iam():
    return boto3.client("iam")


def get_sns():
    return boto3.client("sns")
ACCESS_KEY_RE = re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b")


def lambda_handler(event, context):
    dry_run = os.environ.get("DRY_RUN", "true").lower() == "true"
    access_key_ids = sorted(_extract_access_key_ids(event))
    disabled = []
    unresolved = []
    iam = get_iam()

    for access_key_id in access_key_ids:
        user_name = _find_user_for_access_key(iam, access_key_id)
        if not user_name:
            unresolved.append(access_key_id)
            continue

        action = {
            "access_key_id": access_key_id,
            "user_name": user_name,
            "dry_run": dry_run,
        }
        disabled.append(action)

        if not dry_run:
            iam.update_access_key(
                UserName=user_name,
                AccessKeyId=access_key_id,
                Status="Inactive",
            )

    if disabled or unresolved:
        _notify(disabled, unresolved, event)
        security_hub.import_findings(
            _security_hub_findings(disabled, unresolved),
            account_id=event.get("account"),
            region=event.get("region"),
        )

    return {
        "dry_run": dry_run,
        "disabled": disabled,
        "unresolved_access_key_ids": unresolved,
    }


def _extract_access_key_ids(event):
    keys = set()
    serialized = json.dumps(event, default=str)
    for match in ACCESS_KEY_RE.finditer(serialized):
        keys.add(match.group(0))

    for entity in event.get("detail", {}).get("affectedEntities", []):
        value = entity.get("entityValue", "")
        for match in ACCESS_KEY_RE.finditer(value):
            keys.add(match.group(0))

    return keys


def _find_user_for_access_key(iam, access_key_id):
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page.get("Users", []):
            user_name = user["UserName"]
            keys = iam.list_access_keys(UserName=user_name).get("AccessKeyMetadata", [])
            if any(key["AccessKeyId"] == access_key_id for key in keys):
                return user_name
    return None


def _notify(disabled, unresolved, event):
    get_sns().publish(
        TopicArn=os.environ["ALERT_TOPIC_ARN"],
        Subject="AWS compromised access key responder",
        Message=json.dumps({
            "summary": "AWS Health reported potentially compromised access keys",
            "disabled": disabled,
            "unresolved_access_key_ids": unresolved,
            "event": event,
        }, indent=2, default=str),
    )


def _security_hub_findings(disabled, unresolved):
    findings = []
    for action in disabled:
        findings.append({
            "control": "compromised_access_key_disabled",
            "severity": "CRITICAL",
            "resource": action["access_key_id"],
            "resource_type": "AwsIamAccessKey",
            "title": "AWS Health reported a compromised IAM access key",
            "detail": f"AWS Health reported access key {action['access_key_id']} for IAM user {action['user_name']}.",
            "remediation": "Rotate credentials, investigate usage, and confirm the key is inactive.",
            "guidance_url": "https://docs.aws.amazon.com/health/latest/ug/cloudwatch-events-health.html",
        })
    for access_key_id in unresolved:
        findings.append({
            "control": "compromised_access_key_unresolved",
            "severity": "HIGH",
            "resource": access_key_id,
            "resource_type": "AwsIamAccessKey",
            "title": "AWS Health reported an access key that could not be mapped",
            "detail": f"Access key {access_key_id} was reported by AWS Health but no IAM user was found.",
            "remediation": "Investigate the key manually and confirm it is inactive or deleted.",
            "guidance_url": "https://docs.aws.amazon.com/health/latest/ug/cloudwatch-events-health.html",
        })
    return findings
