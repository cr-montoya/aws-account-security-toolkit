# Architecture

The toolkit deploys account-level security responders and guardrails with AWS CDK.

```text
CloudTrail/EventBridge events
  |-- root sign-in
  |-- CloudTrail/KMS/IAM/S3/EC2/Organizations/security service changes
  |-- AWS Health compromised key events
  `--> Lambda responders
          |-- SNS notifications
          `-- optional Security Hub custom findings

EventBridge schedules
  |-- IAM posture scanner
  |-- S3 public access guard
  `-- stale access key quarantine

Optional baseline
  |-- GuardDuty detector
  |-- Security Hub + FSBP
  |-- AWS Config recorder
  |-- IAM Access Analyzer
  `-- S3 account Block Public Access
```

The default posture is intentionally safe for labs:

- `dry_run=true` prevents IAM quarantine and S3 Block Public Access remediation.
- `security_hub_findings_enabled=false` avoids writes to Security Hub unless explicitly enabled.
- `security_baseline` resources are disabled by default to avoid unexpected cost or account-level service state changes.

Enable baseline services first, validate findings, then enable remediation in a sandbox before production use.
