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

Use `uv` for local validation:

```bash
uv sync --all-groups
uv run ruff check .
uv run pytest
npx -y aws-cdk@latest synth
```

Or run the combined target:

```bash
make validate
```

Before opening a pull request, run the same checks through pre-commit if hooks are installed:

```bash
uv run pre-commit run --all-files
```

## Documentation

Update `README.md` when commands, architecture, configuration, validation, or cleanup behavior changes.
