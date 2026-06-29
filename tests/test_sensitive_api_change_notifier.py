import json

import sensitive_api_change_notifier


class FakeSns:
    def __init__(self):
        self.published = []

    def publish(self, **kwargs):
        self.published.append(kwargs)


def test_sensitive_api_change_notifier_reports_public_ssh_ingress(monkeypatch):
    sns = FakeSns()
    imported_findings = []
    monkeypatch.setenv("ALERT_TOPIC_ARN", "arn:aws:sns:us-east-2:123456789012:alerts")
    monkeypatch.setattr(sensitive_api_change_notifier, "get_sns", lambda: sns)
    monkeypatch.setattr(
        sensitive_api_change_notifier.security_hub,
        "import_findings",
        lambda findings, **kwargs: imported_findings.extend(findings),
    )

    response = sensitive_api_change_notifier.lambda_handler({
        "account": "123456789012",
        "region": "us-east-2",
        "detail": {
            "eventSource": "ec2.amazonaws.com",
            "eventName": "AuthorizeSecurityGroupIngress",
            "sourceIPAddress": "203.0.113.10",
            "requestParameters": {
                "groupId": "sg-1234567890abcdef0",
                "ipPermissions": {
                    "items": [{
                        "fromPort": 22,
                        "toPort": 22,
                        "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
                    }]
                },
            },
            "userIdentity": {
                "arn": "arn:aws:iam::123456789012:user/alice",
            },
        },
    }, None)

    assert response["notified"] is True
    assert response["control"] == "security_group_admin_port_public"
    assert len(sns.published) == 1
    assert imported_findings[0]["severity"] == "CRITICAL"

    message = json.loads(sns.published[0]["Message"])
    assert message["severity"] == "CRITICAL"
    assert message["resource"] == "sg-1234567890abcdef0"


def test_sensitive_api_change_notifier_ignores_non_admin_security_group_ingress(monkeypatch):
    monkeypatch.setattr(sensitive_api_change_notifier, "get_sns", lambda: FakeSns())

    response = sensitive_api_change_notifier.lambda_handler({
        "detail": {
            "eventSource": "ec2.amazonaws.com",
            "eventName": "AuthorizeSecurityGroupIngress",
            "requestParameters": {
                "groupId": "sg-1234567890abcdef0",
                "ipPermissions": {
                    "items": [{
                        "fromPort": 443,
                        "toPort": 443,
                        "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
                    }]
                },
            },
        },
    }, None)

    assert response == {"notified": False, "reason": "ignored_event"}
