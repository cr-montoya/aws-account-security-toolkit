# Changelog

## v0.2.0

- Added optional Security Hub custom findings using AWS Security Finding Format.
- Added optional single-account security baseline resources for GuardDuty, Security Hub, AWS Config, IAM Access Analyzer, and S3 account-level Block Public Access.
- Added sensitive API change detection for IAM, S3, EC2 security groups, GuardDuty, Security Hub, AWS Config, and AWS Organizations policy changes.
- Added structured Security Hub remediation metadata to IAM, S3, KMS, CloudTrail, stale key, and compromised key findings.
- Added control catalog, architecture documentation, issue templates, pull request template, and release notes.

## v0.1.0

- Initial toolkit release with AWS CDK deployment, uv workflow, CI, pre-commit, and AWS-guided documentation.
- Added root login notification, CloudTrail change notification, KMS change notification, IAM posture scanner, S3 public access guard, stale access key quarantine, compromised key responder, and optional approved Regions SCP.
