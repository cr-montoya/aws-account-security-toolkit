.PHONY: sync test lint synth pre-commit validate

sync:
	uv sync --all-groups

test:
	uv run pytest

lint:
	uv run ruff check .

pre-commit:
	uv run pre-commit run --all-files

synth:
	npx -y aws-cdk@latest synth

validate: lint test synth
