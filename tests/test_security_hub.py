import security_hub


class FakeSecurityHub:
    def __init__(self):
        self.imported = []

    def batch_import_findings(self, **kwargs):
        self.imported.extend(kwargs["Findings"])
        return {"FailedCount": 0, "SuccessCount": len(kwargs["Findings"])}


def test_import_findings_skips_when_disabled(monkeypatch):
    monkeypatch.delenv("SECURITY_HUB_FINDINGS_ENABLED", raising=False)

    response = security_hub.import_findings([{
        "control": "example_control",
        "resource": "example-resource",
        "severity": "HIGH",
        "detail": "Example finding",
    }])

    assert response == {"skipped": True, "imported": 0}


def test_import_findings_builds_asff(monkeypatch):
    client = FakeSecurityHub()
    monkeypatch.setenv("SECURITY_HUB_FINDINGS_ENABLED", "true")
    monkeypatch.setenv("TOOLKIT_AWS_ACCOUNT_ID", "123456789012")
    monkeypatch.setenv("AWS_REGION", "us-east-2")
    monkeypatch.setattr(security_hub, "get_securityhub", lambda: client)

    response = security_hub.import_findings([{
        "control": "example_control",
        "resource": "example-resource",
        "resource_type": "AwsAccount",
        "severity": "HIGH",
        "title": "Example title",
        "detail": "Example finding",
        "remediation": "Fix the issue.",
        "guidance_url": "https://docs.aws.amazon.com/security/",
    }])

    assert response["FailedCount"] == 0
    assert len(client.imported) == 1
    finding = client.imported[0]
    assert finding["AwsAccountId"] == "123456789012"
    assert finding["ProductArn"] == "arn:aws:securityhub:us-east-2:123456789012:product/123456789012/default"
    assert finding["Severity"]["Label"] == "HIGH"
    assert finding["Resources"][0]["Type"] == "AwsAccount"
