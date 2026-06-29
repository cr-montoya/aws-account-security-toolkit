import hashlib
import json
import os
from datetime import UTC, datetime

import boto3

SEVERITY_LABELS = {"INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


def get_securityhub():
    return boto3.client("securityhub")


def findings_enabled():
    return os.environ.get("SECURITY_HUB_FINDINGS_ENABLED", "false").lower() == "true"


def import_findings(findings, *, account_id=None, region=None):
    if not findings_enabled() or not findings:
        return {"skipped": True, "imported": 0}

    account_id = account_id or os.environ.get("TOOLKIT_AWS_ACCOUNT_ID")
    region = region or os.environ.get("AWS_REGION", "us-east-1")
    if not account_id:
        return {"skipped": True, "reason": "missing_account_id", "imported": 0}

    asff_findings = [_to_asff(finding, account_id=account_id, region=region) for finding in findings]
    return get_securityhub().batch_import_findings(Findings=asff_findings)


def _to_asff(finding, *, account_id, region):
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    control = finding["control"]
    resource = str(finding["resource"])
    severity = finding.get("severity", "MEDIUM").upper()
    if severity not in SEVERITY_LABELS:
        severity = "MEDIUM"

    title = finding.get("title") or control.replace("_", " ").title()
    description = finding.get("detail") or title
    resource_type = finding.get("resource_type", "AwsAccount")
    finding_id = _finding_id(control, resource, account_id, region)
    product_arn = f"arn:aws:securityhub:{region}:{account_id}:product/{account_id}/default"

    asff = {
        "SchemaVersion": "2018-10-08",
        "Id": finding_id,
        "ProductArn": product_arn,
        "GeneratorId": f"aws-account-security-toolkit/{control}",
        "AwsAccountId": account_id,
        "Types": finding.get("types", ["Software and Configuration Checks/AWS Security Best Practices"]),
        "CreatedAt": now,
        "UpdatedAt": now,
        "Severity": {"Label": severity},
        "Title": title[:256],
        "Description": description[:1024],
        "Resources": [{
            "Type": resource_type,
            "Id": resource,
            "Partition": "aws",
            "Region": region,
        }],
        "Workflow": {"Status": "NEW"},
        "RecordState": "ACTIVE",
        "ProductFields": {
            "ProviderName": "AWS Account Security Toolkit",
            "ControlId": control,
        },
    }

    if finding.get("remediation"):
        asff["Remediation"] = {
            "Recommendation": {
                "Text": finding["remediation"],
                "Url": finding.get("guidance_url", "https://docs.aws.amazon.com/security/"),
            }
        }

    return asff


def _finding_id(control, resource, account_id, region):
    identity = json.dumps({
        "account_id": account_id,
        "control": control,
        "region": region,
        "resource": resource,
    }, sort_keys=True)
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    return f"aws-account-security-toolkit/{control}/{digest}"
