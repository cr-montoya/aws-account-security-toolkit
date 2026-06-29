import json

import root_login_notifier


class FakeSns:
    def __init__(self):
        self.published = []

    def publish(self, **kwargs):
        self.published.append(kwargs)


def test_root_login_notifier_publishes_root_event(monkeypatch):
    sns = FakeSns()
    monkeypatch.setenv("ALERT_TOPIC_ARN", "arn:aws:sns:us-east-2:123456789012:alerts")
    monkeypatch.setattr(root_login_notifier, "get_sns", lambda: sns)

    response = root_login_notifier.lambda_handler({
        "account": "123456789012",
        "region": "us-east-1",
        "detail": {
            "eventTime": "2026-06-29T00:00:00Z",
            "sourceIPAddress": "203.0.113.10",
            "responseElements": {"ConsoleLogin": "Success"},
            "additionalEventData": {"MFAUsed": "Yes"},
        },
    }, None)

    assert response["notified"] is True
    assert response["console_login"] == "Success"
    assert len(sns.published) == 1

    message = json.loads(sns.published[0]["Message"])
    assert message["summary"] == "Root user console sign-in event detected"
    assert message["source_ip"] == "203.0.113.10"
    assert message["mfa_used"] == "Yes"
