# AWS Account Security Toolkit

[![CI](https://github.com/cr-montoya/aws-account-security-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/cr-montoya/aws-account-security-toolkit/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/tag/cr-montoya/aws-account-security-toolkit?label=release)](https://github.com/cr-montoya/aws-account-security-toolkit/tags)
[![Python](https://img.shields.io/badge/python-3.12-blue)](https://www.python.org/)
[![AWS Security](https://img.shields.io/badge/AWS-Security-orange)](https://docs.aws.amazon.com/security/)
[![AWS CDK](https://img.shields.io/badge/AWS%20CDK-v2-orange)](https://docs.aws.amazon.com/cdk/v2/guide/home.html)
[![uv](https://img.shields.io/badge/package%20manager-uv-5c3ee8)](https://docs.astral.sh/uv/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Deployable AWS security automation toolkit for account guardrails, IAM access key remediation, root login alerts, compromised credential response, and region restrictions.

Security automation toolkit for AWS accounts. This project is designed as a collection of deployable guardrails and responders that help detect risky account activity, reduce credential exposure, and enforce account-level operating standards.

The toolkit starts intentionally small and practical:

- Notify root user console sign-in attempts and successes.
- Notify when CloudTrail trails are stopped, deleted, or modified.
- Notify when KMS keys are disabled, scheduled for deletion, or have key policies changed.
- Detect root account access keys, missing root MFA, IAM users without MFA, and IAM users with administrator access.
- Detect weak S3 account/bucket Block Public Access settings and public bucket policies.
- Detect IAM access keys that have not been used in 90 days and attach a deny-all quarantine policy to the IAM user.
- Disable access keys reported by AWS Health as exposed or compromised.
- Provide an Organizations SCP pattern to deny usage outside approved AWS Regions.

The default posture is safe for labs: destructive/remediation actions run in `DRY_RUN=true` unless explicitly disabled.

## Architecture

```text
AWS account events
  |
  +--> EventBridge: AWS Console Sign In via CloudTrail
  |       `--> RootLoginNotifier Lambda --> SNS topic
  |
  +--> EventBridge: AWS API Call via CloudTrail
  |       `--> CloudTrailChangeNotifier Lambda --> SNS topic
  |
  +--> EventBridge: AWS API Call via CloudTrail
  |       `--> KmsChangeNotifier Lambda --> SNS topic
  |
  +--> EventBridge: AWS Health event
  |       `--> CompromisedKeyResponder Lambda --> IAM UpdateAccessKey Inactive
  |
  +--> EventBridge schedule
  |       +--> IamPostureScanner Lambda --> SNS topic
  |       +--> S3PublicAccessGuard Lambda --> SNS topic / optional Block Public Access remediation
  |       `--> StaleAccessKeyQuarantine Lambda --> IAM user inline deny-all policy

AWS Organizations
  `--> Optional SCP for approved Regions only
```

## Controls

| Control | Mode | Default |
|---|---|---|
| Root sign-in notification | EventBridge + Lambda + SNS | Active |
| CloudTrail change notification | EventBridge + Lambda + SNS | Active |
| KMS key change notification | EventBridge + Lambda + SNS | Active |
| IAM posture scanner | Scheduled Lambda + SNS | Active |
| S3 public access guard | Scheduled Lambda + SNS / optional remediation | Dry run |
| 90-day unused access key quarantine | Scheduled Lambda | Dry run |
| AWS Health compromised key disablement | EventBridge + Lambda | Dry run |
| Approved Regions only | SCP artifact / optional CDK Organizations policy | Disabled unless target IDs are provided |

## AWS Guidance Mapping

Each control is intentionally mapped to AWS security guidance, service documentation, or managed control patterns.

| Toolkit control | AWS guidance behind it |
|---|---|
| Root sign-in notification | AWS recommends securing root credentials, enabling MFA, avoiding root access keys, and monitoring root usage in [Root user best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/root-user-best-practices.html). |
| IAM posture scanner | AWS recommends MFA, least privilege, temporary credentials, IAM Access Analyzer, and regular review/removal of unused users, permissions, policies, and credentials in [Security best practices in IAM](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html). |
| Stale access key quarantine | AWS recommends relying on temporary credentials where possible and updating/removing long-term access keys using last-used information in [Security best practices in IAM](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html). |
| CloudTrail change notification | AWS recommends creating multi-Region trails, integrating CloudTrail with monitoring, and protecting trail configuration in [Security best practices in AWS CloudTrail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html). |
| KMS key change notification | AWS warns that KMS key deletion is destructive after the waiting period and recommends monitoring scheduled deletion in [Delete an AWS KMS key](https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html). |
| S3 public access guard | AWS recommends using S3 Block Public Access settings as centralized guardrails in [Blocking public access to your Amazon S3 storage](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html). |
| Compromised key responder | AWS Health events can be routed through EventBridge for operational and security response, as documented in [Monitoring events in AWS Health with Amazon EventBridge](https://docs.aws.amazon.com/health/latest/ug/cloudwatch-events-health.html). |
| Approved Regions SCP | AWS Organizations SCPs provide central permission guardrails in [Service control policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html), and AWS policy examples use `aws:RequestedRegion` to deny actions outside selected Regions in [Deny access based on requested Region](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_aws_deny-requested-region.html). |
| Future Security Hub findings | AWS Security Hub provides the [AWS Foundational Security Best Practices standard](https://docs.aws.amazon.com/securityhub/latest/userguide/fsbp-standard.html), which this toolkit can complement with custom findings. |

## Project Structure

```text
SecurityToolkit/
|-- app.py
|-- cdk.json
|-- pyproject.toml
|-- uv.lock
|-- README.md
|-- stacks/
|   `-- security_toolkit_stack.py
|-- lambdas/
|   |-- root_login_notifier.py
|   |-- cloudtrail_change_notifier.py
|   |-- kms_change_notifier.py
|   |-- iam_posture_scanner.py
|   |-- s3_public_access_guard.py
|   |-- stale_access_key_quarantine.py
|   `-- compromised_key_responder.py
|-- tests/
|   |-- test_root_login_notifier.py
|   |-- test_cloudtrail_change_notifier.py
|   |-- test_kms_change_notifier.py
|   |-- test_iam_posture_scanner.py
|   |-- test_s3_public_access_guard.py
|   |-- test_stale_access_key_quarantine.py
|   |-- test_compromised_key_responder.py
|   `-- test_stack.py
`-- policies/
    `-- deny-unapproved-regions-scp.json
```

## Configuration

Configuration is read from CDK context in `cdk.json`.

| Context key | Purpose |
|---|---|
| `security_toolkit.stage` | Naming suffix, usually `dev`, `audit`, or `prod` |
| `security_toolkit.notification_email` | Optional email subscribed to the SNS topic |
| `security_toolkit.dry_run` | Keeps remediation actions from changing IAM state |
| `security_toolkit.stale_key_days` | Age threshold for access key quarantine |
| `security_toolkit.schedule_expression` | EventBridge schedule for stale-key checks |
| `security_toolkit.controls` | Per-control enable/disable flags |
| `security_toolkit.allowed_regions` | Regions allowed by the SCP |
| `security_toolkit.organization_target_ids` | Optional OU/account/root IDs to attach the SCP |

Control flags default to enabled when omitted:

```json
"controls": {
  "root_login_notifier": true,
  "cloudtrail_change_notifier": true,
  "kms_change_notifier": true,
  "iam_posture_scanner": true,
  "s3_public_access_guard": true,
  "stale_access_key_quarantine": true,
  "compromised_key_responder": true
}
```

## Deploy

```bash
cd SecurityToolkit
uv sync --all-groups

npx -y aws-cdk@latest synth
npx -y aws-cdk@latest deploy
```

If `notification_email` is set, confirm the SNS subscription email after deployment.

## Enabling Remediation

The default `dry_run` value is `true`. In this mode, Lambdas log what they would do and publish notifications, but they do not quarantine users or disable keys.

`dry_run` also keeps the S3 public access guard from applying account-level or bucket-level Block Public Access settings automatically.

After validating logs and behavior in a sandbox account, set:

```json
"dry_run": false
```

Then redeploy.

## Testing

```bash
uv sync --all-groups
uv run pytest
npx -y aws-cdk@latest synth
```

The unit tests validate Lambda responder behavior with fake AWS clients and verify that the CDK stack creates the expected core resources.

## Development

This project uses `uv` for Python dependency management. Common commands:

```bash
make sync
make lint
make test
make synth
make validate
```

`uv` manages Python dependencies and runs the CDK app through `cdk.json`. The CDK CLI is invoked with `npx -y aws-cdk@latest` so local and CI runs do not depend on a stale globally installed `cdk` binary.

To install local git hooks:

```bash
uv run pre-commit install
```

`pyproject.toml` and `uv.lock` are the source of truth for local development and CI dependencies.

## Approved Regions SCP

The stack can create an AWS Organizations SCP if `organization_target_ids` is not empty. Deploy this only from an Organizations management account or delegated admin account with the right permissions.

The SCP denies actions outside `allowed_regions`, while exempting common global services such as IAM, STS, CloudFront, Route 53, Organizations, Support, and Health.

Review [policies/deny-unapproved-regions-scp.json](policies/deny-unapproved-regions-scp.json) before applying it to production OUs.

## Roadmap Ideas

High-impact next controls:

- Auto-enable GuardDuty across regions.
- Auto-enable Security Hub standards.
- Detect security groups exposing SSH/RDP to `0.0.0.0/0`.
- Rotate or quarantine access keys older than a maximum age.
- Notify on IAM policy changes that add `AdministratorAccess` or wildcard permissions.
- Notify on creation of new access keys for IAM users.

Platform/team features:

- Multi-account deployment from an AWS Organizations security account.
- Security Hub custom findings for every responder action.
- Slack, Teams, or PagerDuty notification targets.
- Quarantine allowlist for break-glass users and automation roles.
- Dashboard with remediation counts and dry-run findings.

Additional detections:

- Alert when GuardDuty, Security Hub, AWS Config, or CloudTrail is disabled.
- Detect console users with inactive passwords.
- Detect changes to account alternate contacts.
- Detect changes to AWS Organizations SCPs.

## Cleanup

```bash
cdk destroy
```

If an SCP was attached to an organization target, verify that it was detached/deleted as expected.
