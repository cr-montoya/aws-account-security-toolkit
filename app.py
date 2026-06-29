#!/usr/bin/env python3
import os

import aws_cdk as cdk

from stacks.security_toolkit_stack import SecurityToolkitStack


app = cdk.App()

config = app.node.try_get_context("security_toolkit") or {}
stage = config.get("stage", "dev")

env = cdk.Environment(
    account=os.environ.get("CDK_DEFAULT_ACCOUNT"),
    region=os.environ.get("CDK_DEFAULT_REGION", "us-east-2"),
)

SecurityToolkitStack(
    app,
    f"SecurityToolkit-{stage}",
    config=config,
    description="AWS account security automation toolkit",
    env=env,
)

app.synth()
