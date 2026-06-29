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

    template.resource_count_is("AWS::Lambda::Function", 4)
    template.resource_count_is("AWS::Events::Rule", 4)
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
    template.has_resource_properties("AWS::Events::Rule", {
        "EventPattern": {
            "source": ["aws.cloudtrail"],
            "detail-type": ["AWS API Call via CloudTrail"],
            "detail": {
                "eventSource": ["cloudtrail.amazonaws.com"],
                "eventName": [
                    "DeleteTrail",
                    "PutEventSelectors",
                    "StopLogging",
                    "UpdateTrail",
                ],
            },
        }
    })


def test_stack_can_disable_individual_controls():
    app = cdk.App()
    stack = SecurityToolkitStack(
        app,
        "TestSecurityToolkitControlFlags",
        config={
            "stage": "test",
            "dry_run": True,
            "stale_key_days": 90,
            "schedule_expression": "rate(1 day)",
            "allowed_regions": ["us-east-1", "us-east-2"],
            "organization_target_ids": [],
            "controls": {
                "root_login_notifier": False,
                "cloudtrail_change_notifier": True,
                "stale_access_key_quarantine": False,
                "compromised_key_responder": False,
            },
        },
    )

    template = assertions.Template.from_stack(stack)

    template.resource_count_is("AWS::Lambda::Function", 1)
    template.resource_count_is("AWS::Events::Rule", 1)


def test_stack_accepts_string_control_flags():
    app = cdk.App()
    stack = SecurityToolkitStack(
        app,
        "TestSecurityToolkitStringControlFlags",
        config={
            "stage": "test",
            "dry_run": True,
            "stale_key_days": 90,
            "schedule_expression": "rate(1 day)",
            "allowed_regions": ["us-east-1", "us-east-2"],
            "organization_target_ids": [],
            "controls": {
                "root_login_notifier": "false",
                "cloudtrail_change_notifier": "true",
                "stale_access_key_quarantine": "false",
                "compromised_key_responder": "false",
            },
        },
    )

    template = assertions.Template.from_stack(stack)

    template.resource_count_is("AWS::Lambda::Function", 1)
    template.resource_count_is("AWS::Events::Rule", 1)
