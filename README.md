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
- Publish optional custom findings to AWS Security Hub using ASFF.
- Optionally bootstrap single-account security services such as GuardDuty, Security Hub, AWS Config, IAM Access Analyzer, and S3 account-level Block Public Access.
- Alert on security-sensitive IAM, S3, EC2 security group, GuardDuty, Security Hub, AWS Config, and Organizations API changes.
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
  |
  `--> EventBridge: security-sensitive API changes
          `--> SensitiveApiChangeNotifier Lambda --> SNS topic / optional Security Hub finding

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
| Sensitive API change notification | EventBridge + Lambda + SNS | Active |
| Security Hub custom findings | ASFF import for detected findings | Disabled until enabled |
| Security services baseline | GuardDuty, Security Hub, AWS Config, IAM Access Analyzer, S3 account BPA | Disabled until enabled |
| 90-day unused access key quarantine | Scheduled Lambda | Dry run |
| AWS Health compromised key disablement | EventBridge + Lambda | Dry run |
| Approved Regions only | SCP artifact / optional CDK Organizations policy | Disabled unless target IDs are provided |

## Personal Account Quickstart

For a personal AWS account, start with the default safety posture:

- Keep `dry_run=true`.
- Keep `security_hub_findings_enabled=false`.
- Keep every `security_baseline` flag set to `false`.
- Set `notification_email` so SNS can email you alerts.
- Deploy only after reviewing `cdk synth`.

This gives you a practical monitoring layer without enabling paid security services or applying remediation automatically.

Recommended personal-account flow:

```bash
uv sync --all-groups
npx -y aws-cdk@latest synth
npx -y aws-cdk@latest deploy
```

After deploy, confirm the SNS subscription email. Then watch alerts for a few days before enabling remediation or baseline services.

Good first controls for a personal account:

- Root sign-in notification.
- CloudTrail and KMS change notification.
- IAM posture scanner.
- S3 public access guard in dry-run mode.
- Sensitive API change notification.
- Stale access key quarantine in dry-run mode.

## Advanced Options and Impact

Some options change account-level security services, create recurring service usage, or apply remediation. Enable them deliberately.

| Option | What it does | Possible impact |
|---|---|---|
| `dry_run=false` | Allows remediation actions such as IAM quarantine and S3 Block Public Access updates. | Can deny IAM user actions or change S3 public access settings. Test in a sandbox first. |
| `security_hub_findings_enabled=true` | Imports toolkit findings into Security Hub using ASFF. | Requires Security Hub to be enabled. Security Hub may incur service charges. |
| `security_baseline.enable_guardduty=true` | Creates a GuardDuty detector. | GuardDuty may incur charges based on analyzed events and data sources. |
| `security_baseline.enable_security_hub=true` | Enables Security Hub. | Security Hub may incur charges for checks, findings, and enabled standards. |
| `security_baseline.enable_security_hub_fsbp=true` | Subscribes to AWS Foundational Security Best Practices when Security Hub is enabled. | Can produce many findings in existing accounts. Useful, but noisy at first. |
| `security_baseline.enable_config=true` | Creates AWS Config recorder, delivery bucket, and delivery channel. | AWS Config may incur charges for configuration items and rule evaluations. Creates an S3 bucket. |
| `security_baseline.enable_access_analyzer=true` | Creates an account-level IAM Access Analyzer. | Usually low-friction, but it can produce findings for external access that need triage. |
| `security_baseline.enable_s3_account_public_access_block=true` | Applies account-level S3 Block Public Access. | Can break intentional public S3 website or public bucket use cases. |
| `organization_target_ids` | Creates and attaches the approved Regions SCP to listed OU/account/root targets. | Requires Organizations permissions and can block workloads in unapproved Regions. |

For a stronger personal account setup, a reasonable next step is:

```json
"security_baseline": {
  "enable_guardduty": true,
  "enable_security_hub": true,
  "enable_security_hub_fsbp": true,
  "enable_config": false,
  "enable_access_analyzer": true,
  "enable_s3_account_public_access_block": true
}
```

Then, after Security Hub is enabled and stable:

```json
"security_hub_findings_enabled": true
```

Treat `enable_config=true` as a more deliberate step because it creates a recorder and delivery bucket and can add recurring cost.

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
| Sensitive API change notification | AWS Security Hub FSBP and CIS-style controls emphasize monitoring security group, IAM, S3, Config, GuardDuty, and Security Hub changes in [AWS Foundational Security Best Practices](https://docs.aws.amazon.com/securityhub/latest/userguide/fsbp-standard.html). |
| Security Hub findings | AWS Security Hub supports custom findings in ASFF, complementing the [AWS Foundational Security Best Practices standard](https://docs.aws.amazon.com/securityhub/latest/userguide/fsbp-standard.html). |

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
|   |-- sensitive_api_change_notifier.py
|   |-- security_hub.py
|   |-- stale_access_key_quarantine.py
|   `-- compromised_key_responder.py
|-- tests/
|   |-- test_root_login_notifier.py
|   |-- test_cloudtrail_change_notifier.py
|   |-- test_kms_change_notifier.py
|   |-- test_iam_posture_scanner.py
|   |-- test_s3_public_access_guard.py
|   |-- test_sensitive_api_change_notifier.py
|   |-- test_security_hub.py
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
| `security_toolkit.security_hub_findings_enabled` | Imports toolkit findings into Security Hub when Security Hub is enabled |
| `security_toolkit.stale_key_days` | Age threshold for access key quarantine |
| `security_toolkit.schedule_expression` | EventBridge schedule for stale-key checks |
| `security_toolkit.controls` | Per-control enable/disable flags |
| `security_toolkit.security_baseline` | Optional single-account baseline service enablement |
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
  "sensitive_api_change_notifier": true,
  "stale_access_key_quarantine": true,
  "compromised_key_responder": true
}
```

Security baseline flags default to disabled to avoid surprise cost or service state changes:

```json
"security_baseline": {
  "enable_guardduty": false,
  "enable_security_hub": false,
  "enable_security_hub_fsbp": true,
  "enable_config": false,
  "enable_access_analyzer": false,
  "enable_s3_account_public_access_block": false
}
```

Set `security_hub_findings_enabled` to `true` only after Security Hub is enabled in the target account.

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

Additional documentation:

- [Architecture](docs/architecture.md)
- [Control catalog](docs/control-catalog.md)
- [Changelog](CHANGELOG.md)

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

## What This Does Today

- Deploys account-level security notifications and responders with AWS CDK.
- Keeps remediation disabled by default through `dry_run=true`.
- Detects root sign-ins, CloudTrail changes, KMS key changes, compromised access keys, stale access keys, IAM posture issues, S3 public exposure, and security-sensitive API changes.
- Optionally imports custom ASFF findings into Security Hub.
- Optionally enables single-account baseline services such as GuardDuty, Security Hub, AWS Config, IAM Access Analyzer, and S3 account-level Block Public Access.
- Documents the AWS guidance behind each control.

## Next Enhancements

- Add Slack, Teams, and PagerDuty notification targets.
- Add allowlists for break-glass users, trusted automation roles, and approved public buckets.
- Add Security Hub Insights or saved filters for toolkit findings.
- Detect inactive console passwords.
- Detect and report maximum IAM access key age, separately from last-used age.
- Detect changes to account alternate contacts.
- Add CloudWatch dashboard widgets for findings, dry-run actions, and remediations.
- Add example deployment profiles such as `personal`, `audit`, and `strict`.

## Later

- Multi-account deployment from a security account.
- AWS Organizations delegated administrator setup.
- Centralized aggregation across accounts and Regions.
- Full dashboard or web UI.

## Cleanup

```bash
cdk destroy
```

If an SCP was attached to an organization target, verify that it was detached/deleted as expected.
