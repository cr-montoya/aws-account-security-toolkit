import json
from pathlib import Path

import aws_cdk as cdk
from aws_cdk import Duration
from aws_cdk import aws_accessanalyzer as accessanalyzer
from aws_cdk import aws_config as config
from aws_cdk import aws_events as events
from aws_cdk import aws_events_targets as targets
from aws_cdk import aws_guardduty as guardduty
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from aws_cdk import aws_organizations as organizations
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_securityhub as securityhub
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
        security_baseline = config.get("security_baseline", {})
        security_hub_findings_enabled = str(config.get("security_hub_findings_enabled", False)).lower()

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
            "SECURITY_HUB_FINDINGS_ENABLED": security_hub_findings_enabled,
            "TOOLKIT_AWS_ACCOUNT_ID": cdk.Aws.ACCOUNT_ID,
        }

        self._add_security_baseline(stage, security_baseline)

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

        if self._control_enabled(controls, "sensitive_api_change_notifier"):
            sensitive_api_function = self._python_function(
                "SensitiveApiChangeNotifier",
                "sensitive_api_change_notifier.py",
                environment=common_env,
            )
            topic.grant_publish(sensitive_api_function)

            events.Rule(
                self,
                "IamSensitiveChangeRule",
                rule_name=f"security-toolkit-iam-sensitive-change-{stage}",
                event_pattern=events.EventPattern(
                    source=["aws.iam"],
                    detail_type=["AWS API Call via CloudTrail"],
                    detail={
                        "eventSource": ["iam.amazonaws.com"],
                        "eventName": [
                            "AttachGroupPolicy",
                            "AttachUserPolicy",
                            "CreateAccessKey",
                            "CreatePolicyVersion",
                            "PutGroupPolicy",
                            "PutUserPolicy",
                            "SetDefaultPolicyVersion",
                            "UpdateAssumeRolePolicy",
                        ],
                    },
                ),
                targets=[targets.LambdaFunction(sensitive_api_function)],
            )

            events.Rule(
                self,
                "S3SensitiveChangeRule",
                rule_name=f"security-toolkit-s3-sensitive-change-{stage}",
                event_pattern=events.EventPattern(
                    source=["aws.s3", "aws.s3control"],
                    detail_type=["AWS API Call via CloudTrail"],
                    detail={
                        "eventSource": ["s3.amazonaws.com", "s3control.amazonaws.com"],
                        "eventName": [
                            "DeleteAccountPublicAccessBlock",
                            "DeleteBucketPolicy",
                            "DeleteBucketPublicAccessBlock",
                            "PutAccountPublicAccessBlock",
                            "PutBucketAcl",
                            "PutBucketPolicy",
                            "PutBucketPublicAccessBlock",
                        ],
                    },
                ),
                targets=[targets.LambdaFunction(sensitive_api_function)],
            )

            events.Rule(
                self,
                "NetworkExposureChangeRule",
                rule_name=f"security-toolkit-network-exposure-change-{stage}",
                event_pattern=events.EventPattern(
                    source=["aws.ec2"],
                    detail_type=["AWS API Call via CloudTrail"],
                    detail={
                        "eventSource": ["ec2.amazonaws.com"],
                        "eventName": [
                            "AuthorizeSecurityGroupIngress",
                            "ModifySecurityGroupRules",
                            "RevokeSecurityGroupIngress",
                            "UpdateSecurityGroupRuleDescriptionsIngress",
                        ],
                    },
                ),
                targets=[targets.LambdaFunction(sensitive_api_function)],
            )

            events.Rule(
                self,
                "SecurityServiceChangeRule",
                rule_name=f"security-toolkit-security-service-change-{stage}",
                event_pattern=events.EventPattern(
                    detail_type=["AWS API Call via CloudTrail"],
                    detail={
                        "eventSource": [
                            "config.amazonaws.com",
                            "guardduty.amazonaws.com",
                            "securityhub.amazonaws.com",
                        ],
                        "eventName": [
                            "BatchDisableStandards",
                            "DeleteConfigurationRecorder",
                            "DeleteDeliveryChannel",
                            "DeleteDetector",
                            "DisableSecurityHub",
                            "StopConfigurationRecorder",
                            "UpdateDetector",
                        ],
                    },
                ),
                targets=[targets.LambdaFunction(sensitive_api_function)],
            )

            events.Rule(
                self,
                "OrganizationsPolicyChangeRule",
                rule_name=f"security-toolkit-organizations-policy-change-{stage}",
                event_pattern=events.EventPattern(
                    source=["aws.organizations"],
                    detail_type=["AWS API Call via CloudTrail"],
                    detail={
                        "eventSource": ["organizations.amazonaws.com"],
                        "eventName": [
                            "AttachPolicy",
                            "CreatePolicy",
                            "DeletePolicy",
                            "DetachPolicy",
                            "DisablePolicyType",
                            "UpdatePolicy",
                        ],
                    },
                ),
                targets=[targets.LambdaFunction(sensitive_api_function)],
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

        function = lambda_.Function(
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

        if environment.get("SECURITY_HUB_FINDINGS_ENABLED") == "true":
            function.add_to_role_policy(
                iam.PolicyStatement(
                    actions=["securityhub:BatchImportFindings"],
                    resources=["*"],
                )
            )

        return function

    def _add_security_baseline(self, stage: str, baseline: dict) -> None:
        if self._control_enabled(baseline, "enable_guardduty", default=False):
            guardduty.CfnDetector(
                self,
                "GuardDutyDetector",
                enable=True,
                finding_publishing_frequency="FIFTEEN_MINUTES",
            )

        if self._control_enabled(baseline, "enable_security_hub", default=False):
            hub = securityhub.CfnHub(
                self,
                "SecurityHub",
                enable_default_standards=False,
            )
            if self._control_enabled(baseline, "enable_security_hub_fsbp", default=True):
                fsbp = securityhub.CfnStandard(
                    self,
                    "SecurityHubFoundationalSecurityBestPractices",
                    standards_arn=(
                        f"arn:{cdk.Aws.PARTITION}:securityhub:{cdk.Aws.REGION}"
                        "::standards/aws-foundational-security-best-practices/v/1.0.0"
                    ),
                )
                fsbp.add_dependency(hub)

        if self._control_enabled(baseline, "enable_access_analyzer", default=False):
            accessanalyzer.CfnAnalyzer(
                self,
                "AccountAccessAnalyzer",
                analyzer_name=f"security-toolkit-account-analyzer-{stage}",
                type="ACCOUNT",
            )

        if self._control_enabled(baseline, "enable_s3_account_public_access_block", default=False):
            cdk.CfnResource(
                self,
                "S3AccountPublicAccessBlock",
                type="AWS::S3::AccountPublicAccessBlock",
                properties={
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": True,
                        "BlockPublicPolicy": True,
                        "IgnorePublicAcls": True,
                        "RestrictPublicBuckets": True,
                    }
                },
            )

        if self._control_enabled(baseline, "enable_config", default=False):
            self._add_config_baseline(stage)

    def _add_config_baseline(self, stage: str) -> None:
        config_bucket = s3.Bucket(
            self,
            "ConfigDeliveryBucket",
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
            versioned=True,
        )
        config_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                actions=["s3:GetBucketAcl", "s3:ListBucket"],
                principals=[iam.ServicePrincipal("config.amazonaws.com")],
                resources=[config_bucket.bucket_arn],
            )
        )
        config_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                actions=["s3:PutObject"],
                principals=[iam.ServicePrincipal("config.amazonaws.com")],
                resources=[f"{config_bucket.bucket_arn}/AWSLogs/{cdk.Aws.ACCOUNT_ID}/Config/*"],
                conditions={"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
            )
        )

        recorder_role = iam.Role(
            self,
            "ConfigRecorderRole",
            assumed_by=iam.ServicePrincipal("config.amazonaws.com"),
            managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWS_ConfigRole")],
        )

        recorder = config.CfnConfigurationRecorder(
            self,
            "ConfigRecorder",
            role_arn=recorder_role.role_arn,
            recording_group=config.CfnConfigurationRecorder.RecordingGroupProperty(
                all_supported=True,
                include_global_resource_types=True,
            ),
        )
        delivery_channel = config.CfnDeliveryChannel(
            self,
            "ConfigDeliveryChannel",
            name=f"security-toolkit-config-{stage}",
            s3_bucket_name=config_bucket.bucket_name,
        )
        delivery_channel.add_dependency(recorder)

    def _control_enabled(self, controls: dict, control_name: str, *, default: bool = True) -> bool:
        value = controls.get(control_name, default)
        if isinstance(value, str):
            return value.lower() in ["1", "true", "yes", "on"]
        return bool(value)

    def _region_deny_scp(self, allowed_regions: list[str]) -> dict:
        policy_path = Path(__file__).resolve().parents[1] / "policies" / "deny-unapproved-regions-scp.json"
        policy = json.loads(policy_path.read_text())
        policy["Statement"][0]["Condition"]["StringNotEquals"]["aws:RequestedRegion"] = allowed_regions
        return policy
