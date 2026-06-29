# Security

This repository is a learning and portfolio environment. It is not a drop-in production baseline.

## Reporting

If you find a security issue, open a private report if the hosting platform supports it, or contact the repository owner directly. Do not publish exploit details in a public issue.

## Lab Safety

- Do not commit AWS credentials, API keys, account IDs, secrets, or generated `.env` files.
- Review IAM policy changes carefully before deployment.
- Deploy into a non-production AWS account when practicing.
- Clean up resources after validation to avoid unnecessary exposure and cost.
- Restrict CORS origins and API access before adapting the examples for production.
- Review encryption, backup, logging, WAF, TLS, and secret rotation requirements for real workloads.

## Supported Versions

This repo tracks the current study implementation only. Security fixes are applied to the active branch as the project evolves.
