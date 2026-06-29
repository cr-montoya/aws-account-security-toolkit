# AWS Account Security Toolkit

Deployable AWS security automation toolkit for account guardrails, IAM access key remediation, root login alerts, compromised credential response, and region restrictions.

Security automation toolkit for AWS accounts. This project is designed as a collection of deployable guardrails and responders that help detect risky account activity, reduce credential exposure, and enforce account-level operating standards.

The toolkit starts intentionally small and practical:

- Notify root user console sign-in attempts and successes.
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
  +--> EventBridge: AWS Health event
  |       `--> CompromisedKeyResponder Lambda --> IAM UpdateAccessKey Inactive
  |
  `--> EventBridge schedule
          `--> StaleAccessKeyQuarantine Lambda --> IAM user inline deny-all policy

AWS Organizations
  `--> Optional SCP for approved Regions only
```

## Controls

| Control | Mode | Default |
|---|---|---|
| Root sign-in notification | EventBridge + Lambda + SNS | Active |
| 90-day unused access key quarantine | Scheduled Lambda | Dry run |
| AWS Health compromised key disablement | EventBridge + Lambda | Dry run |
| Approved Regions only | SCP artifact / optional CDK Organizations policy | Disabled unless target IDs are provided |

## Project Structure

```text
SecurityToolkit/
|-- app.py
|-- cdk.json
|-- requirements.txt
|-- requirements-dev.txt
|-- README.md
|-- stacks/
|   `-- security_toolkit_stack.py
|-- lambdas/
|   |-- root_login_notifier.py
|   |-- stale_access_key_quarantine.py
|   `-- compromised_key_responder.py
|-- tests/
|   |-- test_root_login_notifier.py
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
| `security_toolkit.allowed_regions` | Regions allowed by the SCP |
| `security_toolkit.organization_target_ids` | Optional OU/account/root IDs to attach the SCP |

## Deploy

```bash
cd SecurityToolkit
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cdk synth
cdk deploy
```

If `notification_email` is set, confirm the SNS subscription email after deployment.

## Enabling Remediation

The default `dry_run` value is `true`. In this mode, Lambdas log what they would do and publish notifications, but they do not quarantine users or disable keys.

After validating logs and behavior in a sandbox account, set:

```json
"dry_run": false
```

Then redeploy.

## Testing

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt

python -m pytest tests -q
cdk synth
```

The unit tests validate Lambda responder behavior with fake AWS clients and verify that the CDK stack creates the expected core resources.

## Approved Regions SCP

The stack can create an AWS Organizations SCP if `organization_target_ids` is not empty. Deploy this only from an Organizations management account or delegated admin account with the right permissions.

The SCP denies actions outside `allowed_regions`, while exempting common global services such as IAM, STS, CloudFront, Route 53, Organizations, Support, and Health.

Review [policies/deny-unapproved-regions-scp.json](policies/deny-unapproved-regions-scp.json) before applying it to production OUs.

## Roadmap Ideas

High-impact next controls:

- Alert when CloudTrail is stopped, deleted, or modified.
- Auto-enable GuardDuty across regions.
- Auto-enable Security Hub standards.
- Detect and quarantine public S3 buckets.
- Detect security groups exposing SSH/RDP to `0.0.0.0/0`.
- Detect IAM users without MFA.
- Rotate or quarantine access keys older than a maximum age.
- Notify on IAM policy changes that add `AdministratorAccess` or wildcard permissions.
- Notify on creation of new access keys for IAM users.
- Detect root account access key creation.

Platform/team features:

- Multi-account deployment from an AWS Organizations security account.
- Per-control enable/disable flags in CDK context.
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
