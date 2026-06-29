import aws_cdk as cdk
from aws_cdk import assertions

from stacks.security_toolkit_stack import SecurityToolkitStack


def test_stack_creates_core_security_controls():
    app = cdk.App()
    stack = SecurityToolkitStack(
        app,
        "TestSecurityToolkit",
        config={
            "stage": "test",
            "dry_run": True,
            "stale_key_days": 90,
            "schedule_expression": "rate(1 day)",
            "allowed_regions": ["us-east-1", "us-east-2"],
            "organization_target_ids": [],
        },
    )

    template = assertions.Template.from_stack(stack)

    template.resource_count_is("AWS::Lambda::Function", 3)
    template.resource_count_is("AWS::Events::Rule", 3)
    template.resource_count_is("AWS::SNS::Topic", 1)
    template.has_resource_properties("AWS::Events::Rule", {
        "EventPattern": {
            "source": ["aws.signin"],
            "detail-type": ["AWS Console Sign In via CloudTrail"],
        }
    })
    template.has_resource_properties("AWS::Events::Rule", {
        "ScheduleExpression": "rate(1 day)",
    })
