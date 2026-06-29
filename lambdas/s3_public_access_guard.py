import json
import os

import boto3

PUBLIC_ACCESS_BLOCK = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def get_s3():
    return boto3.client("s3")


def get_s3control():
    return boto3.client("s3control")


def get_sts():
    return boto3.client("sts")


def get_sns():
    return boto3.client("sns")


def lambda_handler(event, context):
    dry_run = os.environ.get("DRY_RUN", "true").lower() == "true"
    account_id = get_sts().get_caller_identity()["Account"]
    s3 = get_s3()
    s3control = get_s3control()
    findings = []
    remediation_actions = []

    if _account_public_access_block_is_missing_or_weak(s3control, account_id):
        findings.append({
            "control": "s3_account_public_access_block",
            "severity": "HIGH",
            "resource": account_id,
            "detail": "Account-level S3 Block Public Access is missing or incomplete.",
        })
        if not dry_run:
            s3control.put_public_access_block(
                AccountId=account_id,
                PublicAccessBlockConfiguration=PUBLIC_ACCESS_BLOCK,
            )
            remediation_actions.append({
                "resource": account_id,
                "action": "put_account_public_access_block",
            })

    for bucket in s3.list_buckets().get("Buckets", []):
        bucket_name = bucket["Name"]
        if _bucket_public_access_block_is_missing_or_weak(s3, bucket_name):
            findings.append({
                "control": "s3_bucket_public_access_block",
                "severity": "HIGH",
                "resource": bucket_name,
                "detail": "Bucket-level S3 Block Public Access is missing or incomplete.",
            })
            if not dry_run:
                s3.put_public_access_block(
                    Bucket=bucket_name,
                    PublicAccessBlockConfiguration=PUBLIC_ACCESS_BLOCK,
                )
                remediation_actions.append({
                    "resource": bucket_name,
                    "action": "put_bucket_public_access_block",
                })

        if _bucket_policy_is_public(s3, bucket_name):
            findings.append({
                "control": "s3_bucket_policy_not_public",
                "severity": "CRITICAL",
                "resource": bucket_name,
                "detail": "Bucket policy status reports the bucket as public.",
            })

    if findings:
        _notify(dry_run, findings, remediation_actions)

    return {
        "dry_run": dry_run,
        "finding_count": len(findings),
        "findings": findings,
        "remediation_actions": remediation_actions,
    }


def _account_public_access_block_is_missing_or_weak(s3control, account_id):
    try:
        response = s3control.get_public_access_block(AccountId=account_id)
    except Exception as error:
        if _error_code(error) in ["NoSuchPublicAccessBlockConfiguration", "NoSuchPublicAccessBlockConfigurationError"]:
            return True
        raise

    return not _public_access_block_is_strict(response.get("PublicAccessBlockConfiguration", {}))


def _bucket_public_access_block_is_missing_or_weak(s3, bucket_name):
    try:
        response = s3.get_public_access_block(Bucket=bucket_name)
    except Exception as error:
        if _error_code(error) in ["NoSuchPublicAccessBlockConfiguration", "NoSuchPublicAccessBlockConfigurationError"]:
            return True
        raise

    return not _public_access_block_is_strict(response.get("PublicAccessBlockConfiguration", {}))


def _bucket_policy_is_public(s3, bucket_name):
    try:
        response = s3.get_bucket_policy_status(Bucket=bucket_name)
    except Exception as error:
        if _error_code(error) in ["NoSuchBucketPolicy", "NoSuchBucketPolicyStatus", "AccessDenied"]:
            return False
        raise

    return response.get("PolicyStatus", {}).get("IsPublic", False)


def _public_access_block_is_strict(config):
    return all(config.get(key) is True for key in PUBLIC_ACCESS_BLOCK)


def _error_code(error):
    return getattr(error, "response", {}).get("Error", {}).get("Code")


def _notify(dry_run, findings, remediation_actions):
    get_sns().publish(
        TopicArn=os.environ["ALERT_TOPIC_ARN"],
        Subject="AWS S3 public access findings",
        Message=json.dumps({
            "summary": "S3 public access guard detected risky bucket or account configuration",
            "dry_run": dry_run,
            "finding_count": len(findings),
            "findings": findings,
            "remediation_actions": remediation_actions,
        }, indent=2, default=str),
    )
