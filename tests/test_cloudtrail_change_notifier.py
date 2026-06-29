import json

import cloudtrail_change_notifier


class FakeSns:
    def __init__(self):
        self.published = []

    def publish(self, **kwargs):
        self.published.append(kwargs)


def test_cloudtrail_change_notifier_publishes_configuration_change(monkeypatch):
    sns = FakeSns()
    monkeypatch.setenv("ALERT_TOPIC_ARN", "arn:aws:sns:us-east-2:123456789012:alerts")
    monkeypatch.setattr(cloudtrail_change_notifier, "get_sns", lambda: sns)

    response = cloudtrail_change_notifier.lambda_handler({
        "account": "123456789012",
        "region": "us-east-1",
        "detail": {
            "eventTime": "2026-06-29T00:00:00Z",
            "eventName": "StopLogging",
            "sourceIPAddress": "203.0.113.10",
            "userIdentity": {
                "arn": "arn:aws:iam::123456789012:user/alice",
            },
        },
    }, None)

    assert response["notified"] is True
    assert response["event_name"] == "StopLogging"
    assert len(sns.published) == 1

    message = json.loads(sns.published[0]["Message"])
    assert message["summary"] == "CloudTrail configuration change detected"
    assert message["actor"] == "arn:aws:iam::123456789012:user/alice"
    assert message["source_ip"] == "203.0.113.10"
