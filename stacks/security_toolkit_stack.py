import json
from pathlib import Path

import aws_cdk as cdk
from aws_cdk import Duration
from aws_cdk import aws_events as events
from aws_cdk import aws_events_targets as targets
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from aws_cdk import aws_organizations as organizations
from aws_cdk import aws_sns as sns
from aws_cdk import aws_sns_subscriptions as subscriptions
from constructs import Construct


class SecurityToolkitStack(cdk.Stack):
    def __init__(self, scope: Construct, construct_id: str, *, config: dict, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        stage = config.get("stage", "dev")
        dry_run = str(config.get("dry_run", True)).lower()
        stale_key_days = str(config.get("stale_key_days", 90))
        notification_email = config.get("notification_email", "")
        schedule_expression = config.get("schedule_expression", "rate(1 day)")
        allowed_regions = config.get("allowed_regions", ["us-east-1", "us-east-2"])
        organization_target_ids = config.get("organization_target_ids", [])
        controls = config.get("controls", {})

        topic = sns.Topic(
            self,
            "SecurityAlertsTopic",
            topic_name=f"security-toolkit-alerts-{stage}",
            display_name="AWS Account Security Toolkit Alerts",
        )

        if notification_email:
            topic.add_subscription(subscriptions.EmailSubscription(notification_email))

        common_env = {
            "ALERT_TOPIC_ARN": topic.topic_arn,
            "DRY_RUN": dry_run,
        }

        if self._control_enabled(controls, "root_login_notifier"):
            root_login_function = self._python_function(
                "RootLoginNotifier",
                "root_login_notifier.py",
                environment=common_env,
            )
            topic.grant_publish(root_login_function)

            events.Rule(
                self,
                "RootConsoleLoginRule",
                rule_name=f"security-toolkit-root-console-login-{stage}",
                event_pattern=events.EventPattern(
                    source=["aws.signin"],
                    detail_type=["AWS Console Sign In via CloudTrail"],
                    detail={
                        "userIdentity": {
                            "type": ["Root"],
                        }
                    },
                ),
                targets=[targets.LambdaFunction(root_login_function)],
            )

        if self._control_enabled(controls, "cloudtrail_change_notifier"):
            cloudtrail_change_function = self._python_function(
                "CloudTrailChangeNotifier",
                "cloudtrail_change_notifier.py",
                environment=common_env,
            )
            topic.grant_publish(cloudtrail_change_function)

            events.Rule(
                self,
                "CloudTrailChangeRule",
                rule_name=f"security-toolkit-cloudtrail-change-{stage}",
                event_pattern=events.EventPattern(
                    source=["aws.cloudtrail"],
                    detail_type=["AWS API Call via CloudTrail"],
                    detail={
                        "eventSource": ["cloudtrail.amazonaws.com"],
                        "eventName": [
                            "DeleteTrail",
                            "PutEventSelectors",
                            "StopLogging",
                            "UpdateTrail",
                        ],
                    },
                ),
                targets=[targets.LambdaFunction(cloudtrail_change_function)],
            )

        if self._control_enabled(controls, "kms_change_notifier"):
            kms_change_function = self._python_function(
                "KmsChangeNotifier",
                "kms_change_notifier.py",
                environment=common_env,
            )
            topic.grant_publish(kms_change_function)

            events.Rule(
                self,
                "KmsChangeRule",
                rule_name=f"security-toolkit-kms-change-{stage}",
                event_pattern=events.EventPattern(
                    source=["aws.kms"],
                    detail_type=["AWS API Call via CloudTrail"],
                    detail={
                        "eventSource": ["kms.amazonaws.com"],
                        "eventName": [
                            "DisableKey",
                            "PutKeyPolicy",
                            "ScheduleKeyDeletion",
                        ],
                    },
                ),
                targets=[targets.LambdaFunction(kms_change_function)],
            )

        if self._control_enabled(controls, "iam_posture_scanner"):
            iam_posture_function = self._python_function(
                "IamPostureScanner",
                "iam_posture_scanner.py",
                timeout=Duration.minutes(5),
                environment=common_env,
            )
            topic.grant_publish(iam_posture_function)
            iam_posture_function.add_to_role_policy(
                iam.PolicyStatement(
                    actions=[
                        "iam:GenerateCredentialReport",
                        "iam:GetCredentialReport",
                        "iam:GetGroupPolicy",
                        "iam:GetUserPolicy",
                        "iam:ListAttachedGroupPolicies",
                        "iam:ListAttachedUserPolicies",
                        "iam:ListGroupPolicies",
                        "iam:ListGroupsForUser",
                        "iam:ListUserPolicies",
                        "iam:ListUsers",
                    ],
                    resources=["*"],
                )
            )

            events.Rule(
                self,
                "IamPostureScanSchedule",
                rule_name=f"security-toolkit-iam-posture-scan-{stage}",
                schedule=events.Schedule.expression(schedule_expression),
                targets=[targets.LambdaFunction(iam_posture_function)],
            )

        if self._control_enabled(controls, "s3_public_access_guard"):
            s3_guard_function = self._python_function(
                "S3PublicAccessGuard",
                "s3_public_access_guard.py",
                timeout=Duration.minutes(5),
                environment=common_env,
            )
            topic.grant_publish(s3_guard_function)
            s3_guard_function.add_to_role_policy(
                iam.PolicyStatement(
                    actions=[
                        "s3:GetAccountPublicAccessBlock",
                        "s3:GetBucketPolicyStatus",
                        "s3:GetBucketPublicAccessBlock",
                        "s3:ListAllMyBuckets",
                        "s3:PutAccountPublicAccessBlock",
                        "s3:PutBucketPublicAccessBlock",
                        "sts:GetCallerIdentity",
                    ],
                    resources=["*"],
                )
            )

            events.Rule(
                self,
                "S3PublicAccessScanSchedule",
                rule_name=f"security-toolkit-s3-public-access-scan-{stage}",
                schedule=events.Schedule.expression(schedule_expression),
                targets=[targets.LambdaFunction(s3_guard_function)],
            )

        if self._control_enabled(controls, "stale_access_key_quarantine"):
            stale_key_function = self._python_function(
                "StaleAccessKeyQuarantine",
                "stale_access_key_quarantine.py",
                timeout=Duration.minutes(5),
                environment={
                    **common_env,
                    "STALE_KEY_DAYS": stale_key_days,
                    "QUARANTINE_POLICY_NAME": "SecurityToolkitDenyAllDueToStaleAccessKey",
                },
            )
            topic.grant_publish(stale_key_function)
            stale_key_function.add_to_role_policy(
                iam.PolicyStatement(
                    actions=[
                        "iam:GetAccessKeyLastUsed",
                        "iam:ListAccessKeys",
                        "iam:ListUsers",
                        "iam:PutUserPolicy",
                        "iam:TagUser",
                    ],
                    resources=["*"],
                )
            )

            events.Rule(
                self,
                "StaleAccessKeySchedule",
                rule_name=f"security-toolkit-stale-access-key-scan-{stage}",
                schedule=events.Schedule.expression(schedule_expression),
                targets=[targets.LambdaFunction(stale_key_function)],
            )

        if self._control_enabled(controls, "compromised_key_responder"):
            compromised_key_function = self._python_function(
                "CompromisedKeyResponder",
                "compromised_key_responder.py",
                timeout=Duration.minutes(2),
                environment=common_env,
            )
            topic.grant_publish(compromised_key_function)
            compromised_key_function.add_to_role_policy(
                iam.PolicyStatement(
                    actions=[
                        "iam:GetAccessKeyLastUsed",
                        "iam:ListAccessKeys",
                        "iam:ListUsers",
                        "iam:UpdateAccessKey",
                    ],
                    resources=["*"],
                )
            )

            events.Rule(
                self,
                "AwsHealthCompromisedKeyRule",
                rule_name=f"security-toolkit-compromised-key-health-{stage}",
                event_pattern=events.EventPattern(
                    source=["aws.health"],
                    detail_type=["AWS Health Event"],
                    detail={
                        "service": ["IAM"],
                        "eventTypeCategory": ["issue", "accountNotification"],
                    },
                ),
                targets=[targets.LambdaFunction(compromised_key_function)],
            )

        if organization_target_ids:
            policy_content = self._region_deny_scp(allowed_regions)
            organizations.CfnPolicy(
                self,
                "DenyUnapprovedRegionsScp",
                name=f"security-toolkit-deny-unapproved-regions-{stage}",
                description="Deny AWS actions outside approved regions, with global service exceptions.",
                type="SERVICE_CONTROL_POLICY",
                content=json.dumps(policy_content),
                target_ids=organization_target_ids,
            )

        cdk.CfnOutput(self, "SecurityAlertsTopicArn", value=topic.topic_arn)

    def _python_function(
        self,
        construct_id: str,
        handler_file: str,
        *,
        environment: dict,
        timeout: Duration | None = None,
    ) -> lambda_.Function:
        timeout = timeout or Duration.seconds(60)
        log_group = logs.LogGroup(
            self,
            f"{construct_id}LogGroup",
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )

        return lambda_.Function(
            self,
            construct_id,
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler=f"{handler_file.removesuffix('.py')}.lambda_handler",
            code=lambda_.Code.from_asset("lambdas"),
            architecture=lambda_.Architecture.X86_64,
            timeout=timeout,
            memory_size=256,
            environment=environment,
            log_group=log_group,
            tracing=lambda_.Tracing.ACTIVE,
        )

    def _control_enabled(self, controls: dict, control_name: str) -> bool:
        value = controls.get(control_name, True)
        if isinstance(value, str):
            return value.lower() in ["1", "true", "yes", "on"]
        return bool(value)

    def _region_deny_scp(self, allowed_regions: list[str]) -> dict:
        policy_path = Path(__file__).resolve().parents[1] / "policies" / "deny-unapproved-regions-scp.json"
        policy = json.loads(policy_path.read_text())
        policy["Statement"][0]["Condition"]["StringNotEquals"]["aws:RequestedRegion"] = allowed_regions
        return policy
