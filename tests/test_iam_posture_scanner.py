import json

import iam_posture_scanner


class FakePaginator:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self):
        return self.pages


class FakeIam:
    def generate_credential_report(self):
        return {"State": "COMPLETE"}

    def get_credential_report(self):
        return {
            "Content": (
                b"user,arn,user_creation_time,password_enabled,mfa_active,access_key_1_active,access_key_2_active\n"
                b"<root_account>,arn:aws:iam::123456789012:root,2026-01-01T00:00:00+00:00,not_supported,false,true,false\n"
                b"alice,arn:aws:iam::123456789012:user/alice,2026-01-01T00:00:00+00:00,true,false,false,false\n"
                b"bob,arn:aws:iam::123456789012:user/bob,2026-01-01T00:00:00+00:00,false,true,false,false\n"
            )
        }

    def get_paginator(self, name):
        assert name == "list_users"
        return FakePaginator([
            {"Users": [{"UserName": "alice"}, {"UserName": "bob"}]}
        ])

    def list_attached_user_policies(self, UserName):
        if UserName == "alice":
            return {
                "AttachedPolicies": [{
                    "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                }]
            }
        return {"AttachedPolicies": []}

    def list_user_policies(self, UserName):
        return {"PolicyNames": []}

    def list_groups_for_user(self, UserName):
        return {"Groups": []}


class FakeSns:
    def __init__(self):
        self.published = []

    def publish(self, **kwargs):
        self.published.append(kwargs)


def test_iam_posture_scanner_reports_root_user_mfa_and_admin_findings(monkeypatch):
    iam = FakeIam()
    sns = FakeSns()
    monkeypatch.setenv("ALERT_TOPIC_ARN", "arn:aws:sns:us-east-2:123456789012:alerts")
    monkeypatch.setattr(iam_posture_scanner, "get_iam", lambda: iam)
    monkeypatch.setattr(iam_posture_scanner, "get_sns", lambda: sns)

    response = iam_posture_scanner.lambda_handler({}, None)

    controls = {finding["control"] for finding in response["findings"]}
    assert response["finding_count"] == 4
    assert controls == {
        "root_mfa_enabled",
        "root_access_keys_absent",
        "iam_user_mfa_enabled",
        "iam_user_administrator_access",
    }
    assert len(sns.published) == 1

    message = json.loads(sns.published[0]["Message"])
    assert message["summary"] == "IAM posture scanner detected risky account configuration"
    assert message["finding_count"] == 4


def test_inline_policy_admin_detection_handles_url_encoded_policy():
    policy = (
        "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%7B%22Effect%22%3A%22Allow%22%2C"
        "%22Action%22%3A%22%2A%22%2C%22Resource%22%3A%22%2A%22%7D%7D"
    )

    assert iam_posture_scanner._policy_allows_admin(policy) is True
