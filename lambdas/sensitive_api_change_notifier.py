import json
import os

import boto3
import security_hub

ADMIN_PORTS = {22, 3389}
PUBLIC_CIDRS = {"0.0.0.0/0", "::/0"}


def get_sns():
    return boto3.client("sns")


def lambda_handler(event, context):
    finding = _finding_from_event(event)
    if not finding:
        return {"notified": False, "reason": "ignored_event"}

    get_sns().publish(
        TopicArn=os.environ["ALERT_TOPIC_ARN"],
        Subject=f"AWS security-sensitive API change: {finding['event_name']}"[:100],
        Message=json.dumps({
            "summary": finding["title"],
            "severity": finding["severity"],
            "event_name": finding["event_name"],
            "actor": finding["actor"],
            "source_ip": finding["source_ip"],
            "resource": finding["resource"],
            "remediation": finding["remediation"],
            "event": event,
        }, indent=2, default=str),
    )
    security_hub.import_findings([finding], account_id=event.get("account"), region=event.get("region"))

    return {
        "notified": True,
        "control": finding["control"],
        "event_name": finding["event_name"],
        "resource": finding["resource"],
    }


def _finding_from_event(event):
    detail = event.get("detail", {})
    event_source = detail.get("eventSource", "unknown")
    event_name = detail.get("eventName", "Unknown")
    actor = _actor(detail)
    source_ip = detail.get("sourceIPAddress", "unknown")
    request_parameters = detail.get("requestParameters", {})

    if event_source == "iam.amazonaws.com":
        return _iam_finding(event_name, actor, source_ip, request_parameters)
    if event_source in ["s3.amazonaws.com", "s3control.amazonaws.com"]:
        return _s3_finding(event_name, actor, source_ip, request_parameters)
    if event_source == "ec2.amazonaws.com":
        return _ec2_finding(event_name, actor, source_ip, request_parameters)
    if event_source in ["guardduty.amazonaws.com", "securityhub.amazonaws.com", "config.amazonaws.com"]:
        return _security_service_finding(event_source, event_name, actor, source_ip, request_parameters)
    if event_source == "organizations.amazonaws.com":
        return _organizations_finding(event_name, actor, source_ip, request_parameters)
    return None


def _iam_finding(event_name, actor, source_ip, request_parameters):
    policy_arn = request_parameters.get("policyArn", "")
    severity = "HIGH" if policy_arn.endswith("/AdministratorAccess") else "MEDIUM"
    resource, resource_type = _iam_resource(request_parameters)
    return _finding(
        control="iam_sensitive_change",
        event_name=event_name,
        severity=severity,
        resource=resource,
        resource_type=resource_type,
        title=f"IAM security-sensitive change detected: {event_name}",
        detail=f"{actor} called {event_name} for {resource} from {source_ip}.",
        remediation="Review the IAM change and remove broad or unauthorized permissions.",
        guidance_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
        actor=actor,
        source_ip=source_ip,
    )


def _iam_resource(request_parameters):
    if request_parameters.get("userName"):
        return request_parameters["userName"], "AwsIamUser"
    if request_parameters.get("groupName"):
        return request_parameters["groupName"], "AwsIamGroup"
    if request_parameters.get("roleName"):
        return request_parameters["roleName"], "AwsIamRole"
    if request_parameters.get("policyArn"):
        return request_parameters["policyArn"], "AwsIamPolicy"
    return "iam", "AwsAccount"


def _s3_finding(event_name, actor, source_ip, request_parameters):
    bucket = request_parameters.get("bucketName") or request_parameters.get("name") or "s3-account"
    severity = "HIGH" if "PublicAccessBlock" in event_name or "Policy" in event_name else "MEDIUM"
    return _finding(
        control="s3_sensitive_change",
        event_name=event_name,
        severity=severity,
        resource=bucket,
        resource_type="AwsS3Bucket" if bucket != "s3-account" else "AwsAccount",
        title=f"S3 access control change detected: {event_name}",
        detail=f"{actor} called {event_name} for {bucket} from {source_ip}.",
        remediation="Review the S3 access change and confirm public access remains blocked unless explicitly approved.",
        guidance_url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
        actor=actor,
        source_ip=source_ip,
    )


def _ec2_finding(event_name, actor, source_ip, request_parameters):
    if event_name in ["AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules"] and not _opens_admin_port_to_public(
        request_parameters
    ):
        return None

    group_id = request_parameters.get("groupId") or request_parameters.get("groupName") or "security-group"
    severity = "CRITICAL" if event_name in ["AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules"] else "MEDIUM"
    return _finding(
        control="security_group_admin_port_public",
        event_name=event_name,
        severity=severity,
        resource=group_id,
        resource_type="AwsEc2SecurityGroup",
        title=f"Security group ingress change detected: {event_name}",
        detail=f"{actor} called {event_name} for {group_id} from {source_ip}.",
        remediation="Remove public SSH/RDP ingress and restrict administrative access to trusted networks or SSM Session Manager.",
        guidance_url="https://docs.aws.amazon.com/securityhub/latest/userguide/fsbp-standard.html",
        actor=actor,
        source_ip=source_ip,
    )


def _security_service_finding(event_source, event_name, actor, source_ip, request_parameters):
    service = event_source.split(".")[0]
    resource = request_parameters.get("detectorId") or request_parameters.get("configurationRecorderName") or service
    return _finding(
        control="security_service_disabled_or_changed",
        event_name=event_name,
        severity="HIGH",
        resource=resource,
        resource_type="AwsAccount",
        title=f"AWS security service changed: {event_name}",
        detail=f"{actor} called {event_name} for {service} from {source_ip}.",
        remediation="Confirm the change was authorized and re-enable the security service or standard if needed.",
        guidance_url="https://docs.aws.amazon.com/securityhub/latest/userguide/fsbp-standard.html",
        actor=actor,
        source_ip=source_ip,
    )


def _organizations_finding(event_name, actor, source_ip, request_parameters):
    policy_id = request_parameters.get("policyId") or request_parameters.get("targetId") or "organizations-policy"
    return _finding(
        control="organizations_policy_change",
        event_name=event_name,
        severity="HIGH",
        resource=policy_id,
        resource_type="AwsAccount",
        title=f"AWS Organizations policy changed: {event_name}",
        detail=f"{actor} called {event_name} for {policy_id} from {source_ip}.",
        remediation="Review the Organizations policy change and confirm security guardrails still apply.",
        guidance_url="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html",
        actor=actor,
        source_ip=source_ip,
    )


def _finding(
    *,
    control,
    event_name,
    severity,
    resource,
    resource_type,
    title,
    detail,
    remediation,
    guidance_url,
    actor,
    source_ip,
):
    return {
        "control": control,
        "event_name": event_name,
        "severity": severity,
        "resource": resource,
        "resource_type": resource_type,
        "title": title,
        "detail": detail,
        "remediation": remediation,
        "guidance_url": guidance_url,
        "actor": actor,
        "source_ip": source_ip,
    }


def _opens_admin_port_to_public(request_parameters):
    permissions = request_parameters.get("ipPermissions", {})
    if isinstance(permissions, dict) and "items" in permissions:
        permissions = permissions["items"]
    if isinstance(permissions, dict):
        permissions = [permissions]

    for permission in permissions or []:
        from_port = permission.get("fromPort")
        to_port = permission.get("toPort", from_port)
        if not _port_range_includes_admin(from_port, to_port):
            continue
        if _permission_has_public_cidr(permission):
            return True

    return False


def _port_range_includes_admin(from_port, to_port):
    try:
        from_port = int(from_port)
        to_port = int(to_port)
    except (TypeError, ValueError):
        return False
    return any(from_port <= port <= to_port for port in ADMIN_PORTS)


def _permission_has_public_cidr(permission):
    ranges = []
    for key in ["ipRanges", "ipv6Ranges"]:
        value = permission.get(key, {})
        if isinstance(value, dict) and "items" in value:
            ranges.extend(value["items"])
        elif isinstance(value, list):
            ranges.extend(value)

    for item in ranges:
        cidr = item.get("cidrIp") or item.get("cidrIpv6")
        if cidr in PUBLIC_CIDRS:
            return True
    return False


def _actor(detail):
    identity = detail.get("userIdentity", {})
    return identity.get("arn") or identity.get("principalId") or "unknown"
