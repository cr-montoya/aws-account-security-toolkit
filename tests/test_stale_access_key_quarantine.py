import json
from datetime import datetime, timezone

import stale_access_key_quarantine


class FakePaginator:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self):
        return self.pages


class FakeIam:
    def __init__(self):
        self.put_user_policy_calls = []
        self.tag_user_calls = []

    def get_paginator(self, name):
        assert name == "list_users"
        return FakePaginator([
            {"Users": [{"UserName": "alice"}, {"UserName": "bob"}]}
        ])

    def list_access_keys(self, UserName):
        if UserName == "alice":
            return {
                "AccessKeyMetadata": [{
                    "AccessKeyId": "AKIA1111111111111111",
                    "Status": "Active",
                    "CreateDate": datetime(2024, 1, 1, tzinfo=timezone.utc),
                }]
            }
        return {
            "AccessKeyMetadata": [{
                "AccessKeyId": "AKIA2222222222222222",
                "Status": "Inactive",
                "CreateDate": datetime(2024, 1, 1, tzinfo=timezone.utc),
            }]
        }

    def get_access_key_last_used(self, AccessKeyId):
        return {"AccessKeyLastUsed": {}}

    def put_user_policy(self, **kwargs):
        self.put_user_policy_calls.append(kwargs)

    def tag_user(self, **kwargs):
        self.tag_user_calls.append(kwargs)


class FakeSns:
    def __init__(self):
        self.published = []

    def publish(self, **kwargs):
        self.published.append(kwargs)


def test_stale_access_key_quarantine_dry_run_only_reports(monkeypatch):
    iam = FakeIam()
    sns = FakeSns()
    monkeypatch.setenv("ALERT_TOPIC_ARN", "arn:aws:sns:us-east-2:123456789012:alerts")
    monkeypatch.setenv("DRY_RUN", "true")
    monkeypatch.setenv("STALE_KEY_DAYS", "90")
    monkeypatch.setattr(stale_access_key_quarantine, "get_iam", lambda: iam)
    monkeypatch.setattr(stale_access_key_quarantine, "get_sns", lambda: sns)

    response = stale_access_key_quarantine.lambda_handler({}, None)

    assert response["dry_run"] is True
    assert [user["user_name"] for user in response["quarantined_users"]] == ["alice"]
    assert iam.put_user_policy_calls == []
    assert iam.tag_user_calls == []
    assert len(sns.published) == 1


def test_stale_access_key_quarantine_applies_deny_policy_when_enabled(monkeypatch):
    iam = FakeIam()
    sns = FakeSns()
    monkeypatch.setenv("ALERT_TOPIC_ARN", "arn:aws:sns:us-east-2:123456789012:alerts")
    monkeypatch.setenv("DRY_RUN", "false")
    monkeypatch.setenv("STALE_KEY_DAYS", "90")
    monkeypatch.setattr(stale_access_key_quarantine, "get_iam", lambda: iam)
    monkeypatch.setattr(stale_access_key_quarantine, "get_sns", lambda: sns)

    response = stale_access_key_quarantine.lambda_handler({}, None)

    assert response["dry_run"] is False
    assert len(iam.put_user_policy_calls) == 1
    assert iam.put_user_policy_calls[0]["UserName"] == "alice"
    policy = json.loads(iam.put_user_policy_calls[0]["PolicyDocument"])
    assert policy["Statement"][0]["Effect"] == "Deny"
    assert len(iam.tag_user_calls) == 1
