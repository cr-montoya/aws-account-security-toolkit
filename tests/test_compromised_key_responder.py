import json

import compromised_key_responder


class FakePaginator:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self):
        return self.pages


class FakeIam:
    def __init__(self):
        self.update_access_key_calls = []

    def get_paginator(self, name):
        assert name == "list_users"
        return FakePaginator([
            {"Users": [{"UserName": "alice"}, {"UserName": "bob"}]}
        ])

    def list_access_keys(self, UserName):
        keys = {
            "alice": [{"AccessKeyId": "AKIA1111111111111111"}],
            "bob": [{"AccessKeyId": "AKIA2222222222222222"}],
        }
        return {"AccessKeyMetadata": keys[UserName]}

    def update_access_key(self, **kwargs):
        self.update_access_key_calls.append(kwargs)


class FakeSns:
    def __init__(self):
        self.published = []

    def publish(self, **kwargs):
        self.published.append(kwargs)


def test_extract_access_key_ids_from_health_event():
    keys = compromised_key_responder._extract_access_key_ids({
        "detail": {
            "affectedEntities": [
                {"entityValue": "AKIA1111111111111111"},
                {"entityValue": "no-key-here"},
            ],
            "eventDescription": [{
                "latestDescription": "Potentially exposed key AKIA2222222222222222"
            }],
        }
    })

    assert keys == {"AKIA1111111111111111", "AKIA2222222222222222"}


def test_compromised_key_responder_dry_run_reports_without_disabling(monkeypatch):
    iam = FakeIam()
    sns = FakeSns()
    monkeypatch.setenv("ALERT_TOPIC_ARN", "arn:aws:sns:us-east-2:123456789012:alerts")
    monkeypatch.setenv("DRY_RUN", "true")
    monkeypatch.setattr(compromised_key_responder, "get_iam", lambda: iam)
    monkeypatch.setattr(compromised_key_responder, "get_sns", lambda: sns)

    response = compromised_key_responder.lambda_handler({
        "detail": {"affectedEntities": [{"entityValue": "AKIA1111111111111111"}]}
    }, None)

    assert response["dry_run"] is True
    assert response["disabled"][0]["user_name"] == "alice"
    assert iam.update_access_key_calls == []
    assert len(sns.published) == 1


def test_compromised_key_responder_disables_key_when_enabled(monkeypatch):
    iam = FakeIam()
    sns = FakeSns()
    monkeypatch.setenv("ALERT_TOPIC_ARN", "arn:aws:sns:us-east-2:123456789012:alerts")
    monkeypatch.setenv("DRY_RUN", "false")
    monkeypatch.setattr(compromised_key_responder, "get_iam", lambda: iam)
    monkeypatch.setattr(compromised_key_responder, "get_sns", lambda: sns)

    response = compromised_key_responder.lambda_handler({
        "detail": {"affectedEntities": [{"entityValue": "AKIA2222222222222222"}]}
    }, None)

    assert response["dry_run"] is False
    assert response["disabled"][0]["user_name"] == "bob"
    assert iam.update_access_key_calls == [{
        "UserName": "bob",
        "AccessKeyId": "AKIA2222222222222222",
        "Status": "Inactive",
    }]

    message = json.loads(sns.published[0]["Message"])
    assert message["disabled"][0]["access_key_id"] == "AKIA2222222222222222"
