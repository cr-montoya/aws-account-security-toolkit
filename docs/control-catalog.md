# Control Catalog

| Control | Signal | Action | AWS guidance |
|---|---|---|---|
| Root sign-in notification | Root console sign-in events | SNS + optional Security Hub | [Root user best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/root-user-best-practices.html) |
| IAM posture scanner | Credential report and IAM policy inspection | SNS + optional Security Hub | [IAM best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html) |
| Stale access key quarantine | Scheduled IAM access key last-used scan | SNS, optional IAM deny policy, optional Security Hub | [IAM best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html) |
| Compromised key responder | AWS Health compromised key events | SNS, optional key disablement, optional Security Hub | [AWS Health with EventBridge](https://docs.aws.amazon.com/health/latest/ug/cloudwatch-events-health.html) |
| CloudTrail change notification | CloudTrail control plane API calls | SNS + optional Security Hub | [CloudTrail security best practices](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html) |
| KMS key change notification | KMS disable, policy, and deletion API calls | SNS + optional Security Hub | [Deleting KMS keys](https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html) |
| S3 public access guard | Scheduled S3 Block Public Access and policy status scan | SNS, optional Block Public Access remediation, optional Security Hub | [S3 Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html) |
| Sensitive API change notification | IAM, S3, EC2 security group, Config, GuardDuty, Security Hub, and Organizations API calls | SNS + optional Security Hub | [Security Hub FSBP](https://docs.aws.amazon.com/securityhub/latest/userguide/fsbp-standard.html) |
| Approved Regions SCP | AWS Organizations SCP artifact | Optional SCP attachment | [Deny access based on requested Region](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_aws_deny-requested-region.html) |
| Security baseline | CDK context flags | Optional service enablement | [AWS Security Documentation](https://docs.aws.amazon.com/security/) |
