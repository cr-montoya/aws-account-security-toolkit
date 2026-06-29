# v0.2.0 Release Notes

This release turns the toolkit into a more complete single-account security bootstrap and detection project.

Highlights:

- Security Hub custom findings using ASFF.
- Optional security baseline resources for GuardDuty, Security Hub, AWS Config, IAM Access Analyzer, and S3 account-level Block Public Access.
- Sensitive API change detection for IAM, S3, EC2 security groups, GuardDuty, Security Hub, AWS Config, and AWS Organizations policy changes.
- Improved AWS guidance traceability through README links and a dedicated control catalog.
- GitHub issue templates and pull request template for easier collaboration.

Validation:

```bash
make validate
uv run pre-commit run --all-files
```
