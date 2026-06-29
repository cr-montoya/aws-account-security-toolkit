import csv
import io
import json
import os
from urllib.parse import unquote

import boto3
import security_hub

ADMINISTRATOR_ACCESS_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


def get_iam():
    return boto3.client("iam")


def get_sns():
    return boto3.client("sns")


def lambda_handler(event, context):
    iam = get_iam()
    findings = []

    findings.extend(_credential_report_findings(iam))
    findings.extend(_admin_access_findings(iam))

    if findings:
        _notify(findings)
        security_hub.import_findings(findings)

    return {
        "finding_count": len(findings),
        "findings": findings,
    }


def _credential_report_findings(iam):
    findings = []
    rows = _credential_report_rows(iam)

    for row in rows:
        user = row.get("user", "")
        mfa_active = _truthy(row.get("mfa_active"))
        password_enabled = _truthy(row.get("password_enabled"))
        access_key_1_active = _truthy(row.get("access_key_1_active"))
        access_key_2_active = _truthy(row.get("access_key_2_active"))

        if user == "<root_account>":
            if not mfa_active:
                findings.append({
                    "control": "root_mfa_enabled",
                    "severity": "CRITICAL",
                    "resource": "root_account",
                    "resource_type": "AwsAccount",
                    "title": "Root account MFA is not enabled",
                    "detail": "Root account MFA is not enabled.",
                    "remediation": "Enable MFA on the AWS account root user.",
                    "guidance_url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/root-user-best-practices.html",
                })
            if access_key_1_active or access_key_2_active:
                findings.append({
                    "control": "root_access_keys_absent",
                    "severity": "CRITICAL",
                    "resource": "root_account",
                    "resource_type": "AwsIamAccessKey",
                    "title": "Root account has active access keys",
                    "detail": "Root account has one or more active access keys.",
                    "remediation": "Delete root user access keys and use IAM roles or temporary credentials instead.",
                    "guidance_url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/root-user-best-practices.html",
                })
            continue

        if password_enabled and not mfa_active:
            findings.append({
                "control": "iam_user_mfa_enabled",
                "severity": "HIGH",
                "resource": user,
                "resource_type": "AwsIamUser",
                "title": "IAM user console access is missing MFA",
                "detail": "IAM user has console password enabled without MFA.",
                "remediation": "Enable MFA for the IAM user or remove console password access.",
                "guidance_url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
            })

    return findings


def _credential_report_rows(iam):
    iam.generate_credential_report()
    response = iam.get_credential_report()
    content = response["Content"]
    if isinstance(content, bytes):
        content = content.decode("utf-8")

    return list(csv.DictReader(io.StringIO(content)))


def _admin_access_findings(iam):
    findings = []
    paginator = iam.get_paginator("list_users")

    for page in paginator.paginate():
        for user in page.get("Users", []):
            user_name = user["UserName"]
            if _user_has_administrator_access(iam, user_name):
                findings.append({
                    "control": "iam_user_administrator_access",
                    "severity": "HIGH",
                    "resource": user_name,
                    "resource_type": "AwsIamUser",
                    "title": "IAM user has administrator access",
                    "detail": "IAM user has direct, group, or inline administrator access.",
                    "remediation": "Replace direct administrator access with scoped roles and least-privilege policies.",
                    "guidance_url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
                })

    return findings


def _user_has_administrator_access(iam, user_name):
    if _attached_policies_include_admin(iam.list_attached_user_policies(UserName=user_name)):
        return True

    for policy_name in iam.list_user_policies(UserName=user_name).get("PolicyNames", []):
        policy = iam.get_user_policy(UserName=user_name, PolicyName=policy_name)["PolicyDocument"]
        if _policy_allows_admin(policy):
            return True

    for group in iam.list_groups_for_user(UserName=user_name).get("Groups", []):
        group_name = group["GroupName"]
        if _attached_policies_include_admin(iam.list_attached_group_policies(GroupName=group_name)):
            return True

        for policy_name in iam.list_group_policies(GroupName=group_name).get("PolicyNames", []):
            policy = iam.get_group_policy(GroupName=group_name, PolicyName=policy_name)["PolicyDocument"]
            if _policy_allows_admin(policy):
                return True

    return False


def _attached_policies_include_admin(response):
    return any(policy.get("PolicyArn") == ADMINISTRATOR_ACCESS_ARN for policy in response.get("AttachedPolicies", []))


def _policy_allows_admin(policy):
    if isinstance(policy, str):
        policy = json.loads(unquote(policy))

    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    return any(_statement_allows_admin(statement) for statement in statements)


def _statement_allows_admin(statement):
    if statement.get("Effect") != "Allow":
        return False
    actions = _as_list(statement.get("Action"))
    resources = _as_list(statement.get("Resource"))
    return "*" in actions and "*" in resources


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _truthy(value):
    return str(value).lower() == "true"


def _notify(findings):
    get_sns().publish(
        TopicArn=os.environ["ALERT_TOPIC_ARN"],
        Subject="AWS IAM posture findings",
        Message=json.dumps({
            "summary": "IAM posture scanner detected risky account configuration",
            "finding_count": len(findings),
            "findings": findings,
        }, indent=2, default=str),
    )
