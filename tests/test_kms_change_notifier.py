import json

import kms_change_notifier


class FakeSns:
    def __init__(self):
        self.published = []

    def publish(self, **kwargs):
        self.published.append(kwargs)


def test_kms_change_notifier_publishes_key_change(monkeypatch):
    sns = FakeSns()
    monkeypatch.setenv("ALERT_TOPIC_ARN", "arn:aws:sns:us-east-2:123456789012:alerts")
    monkeypatch.setattr(kms_change_notifier, "get_sns", lambda: sns)

    response = kms_change_notifier.lambda_handler({
        "account": "123456789012",
        "region": "us-east-1",
        "detail": {
            "eventTime": "2026-06-29T00:00:00Z",
            "eventName": "ScheduleKeyDeletion",
            "sourceIPAddress": "203.0.113.10",
            "requestParameters": {"keyId": "1234abcd-12ab-34cd-56ef-1234567890ab"},
            "userIdentity": {
                "arn": "arn:aws:iam::123456789012:user/alice",
            },
        },
    }, None)

    assert response["notified"] is True
    assert response["event_name"] == "ScheduleKeyDeletion"
    assert len(sns.published) == 1

    message = json.loads(sns.published[0]["Message"])
    assert message["summary"] == "KMS key configuration change detected"
    assert message["key_id"] == "1234abcd-12ab-34cd-56ef-1234567890ab"
    assert message["actor"] == "arn:aws:iam::123456789012:user/alice"
