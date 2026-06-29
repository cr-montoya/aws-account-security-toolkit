import json

import s3_public_access_guard


class FakeAwsError(Exception):
    def __init__(self, code):
        self.response = {"Error": {"Code": code}}


class FakeSts:
    def get_caller_identity(self):
        return {"Account": "123456789012"}


class FakeS3Control:
    def __init__(self):
        self.put_public_access_block_calls = []

    def get_public_access_block(self, AccountId):
        raise FakeAwsError("NoSuchPublicAccessBlockConfiguration")

    def put_public_access_block(self, **kwargs):
        self.put_public_access_block_calls.append(kwargs)


class FakeS3:
    def __init__(self):
        self.put_public_access_block_calls = []

    def list_buckets(self):
        return {"Buckets": [{"Name": "public-bucket"}, {"Name": "private-bucket"}]}

    def get_public_access_block(self, Bucket):
        if Bucket == "public-bucket":
            return {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": True,
                }
            }
        return {
            "PublicAccessBlockConfiguration": s3_public_access_guard.PUBLIC_ACCESS_BLOCK,
        }

    def put_public_access_block(self, **kwargs):
        self.put_public_access_block_calls.append(kwargs)

    def get_bucket_policy_status(self, Bucket):
        return {"PolicyStatus": {"IsPublic": Bucket == "public-bucket"}}


class FakeSns:
    def __init__(self):
        self.published = []

    def publish(self, **kwargs):
        self.published.append(kwargs)


def test_s3_public_access_guard_dry_run_reports_without_remediation(monkeypatch):
    s3 = FakeS3()
    s3control = FakeS3Control()
    sns = FakeSns()
    monkeypatch.setenv("ALERT_TOPIC_ARN", "arn:aws:sns:us-east-2:123456789012:alerts")
    monkeypatch.setenv("DRY_RUN", "true")
    monkeypatch.setattr(s3_public_access_guard, "get_s3", lambda: s3)
    monkeypatch.setattr(s3_public_access_guard, "get_s3control", lambda: s3control)
    monkeypatch.setattr(s3_public_access_guard, "get_sts", lambda: FakeSts())
    monkeypatch.setattr(s3_public_access_guard, "get_sns", lambda: sns)

    response = s3_public_access_guard.lambda_handler({}, None)

    assert response["dry_run"] is True
    assert response["finding_count"] == 3
    assert response["remediation_actions"] == []
    assert s3control.put_public_access_block_calls == []
    assert s3.put_public_access_block_calls == []
    assert len(sns.published) == 1

    message = json.loads(sns.published[0]["Message"])
    assert message["summary"] == "S3 public access guard detected risky bucket or account configuration"


def test_s3_public_access_guard_remediates_public_access_block_when_enabled(monkeypatch):
    s3 = FakeS3()
    s3control = FakeS3Control()
    sns = FakeSns()
    monkeypatch.setenv("ALERT_TOPIC_ARN", "arn:aws:sns:us-east-2:123456789012:alerts")
    monkeypatch.setenv("DRY_RUN", "false")
    monkeypatch.setattr(s3_public_access_guard, "get_s3", lambda: s3)
    monkeypatch.setattr(s3_public_access_guard, "get_s3control", lambda: s3control)
    monkeypatch.setattr(s3_public_access_guard, "get_sts", lambda: FakeSts())
    monkeypatch.setattr(s3_public_access_guard, "get_sns", lambda: sns)

    response = s3_public_access_guard.lambda_handler({}, None)

    assert response["dry_run"] is False
    assert s3control.put_public_access_block_calls == [{
        "AccountId": "123456789012",
        "PublicAccessBlockConfiguration": s3_public_access_guard.PUBLIC_ACCESS_BLOCK,
    }]
    assert s3.put_public_access_block_calls == [{
        "Bucket": "public-bucket",
        "PublicAccessBlockConfiguration": s3_public_access_guard.PUBLIC_ACCESS_BLOCK,
    }]
    assert [action["action"] for action in response["remediation_actions"]] == [
        "put_account_public_access_block",
        "put_bucket_public_access_block",
    ]
