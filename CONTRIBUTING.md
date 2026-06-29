# Contributing

This is a study and portfolio repository, so contributions should keep the projects easy to understand and safe to run in a personal AWS account.

## Guidelines

- Keep app domains simple; the infrastructure and delivery patterns are the focus.
- Prefer small, reviewable changes.
- Keep IAM permissions scoped to the resource patterns used by the apps.
- Add or update tests when changing infrastructure behavior or Lambda/application logic.
- Update the relevant project README when commands, architecture, or cleanup behavior changes.
- Avoid committing secrets, account IDs, generated build output, or local environment files.

## Validation

For SAM changes:

```bash
cd SAM
python -m pytest tests/unit -q
sam validate --lint
sam build
```

For CDK changes:

```bash
cd CDK
.venv/bin/python -m pytest tests/unit/ -v --tb=short -p no:cacheprovider
cdk synth
```

## Documentation

Use the root README for shared repository context: exam coverage, shared prerequisites, cost notes, safety notes, and how the projects compare.

Use project READMEs for app-specific details: architecture, commands, pipeline behavior, validation, and cleanup.
