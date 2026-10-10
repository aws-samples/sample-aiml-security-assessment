import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_PATHS = [
    REPO_ROOT / "aiml-security-assessment" / "template.yaml",
    REPO_ROOT / "aiml-security-assessment" / "template-multi-account.yaml",
]

# These actions back the SageMaker checks that the assessment Lambda actually runs
# for transform jobs, tuning jobs, compilation jobs, AutoML, and lineage tracking.
REQUIRED_SAGEMAKER_ACTIONS = [
    "sagemaker:ListTransformJobs",
    "sagemaker:DescribeTransformJob",
    "sagemaker:ListHyperParameterTuningJobs",
    "sagemaker:DescribeHyperParameterTuningJob",
    "sagemaker:ListCompilationJobs",
    "sagemaker:DescribeCompilationJob",
    "sagemaker:ListAutoMLJobs",
    "sagemaker:DescribeAutoMLJob",
    "sagemaker:ListExperiments",
    "sagemaker:ListTrials",
    "sagemaker:ListAssociations",
]


def test_sagemaker_lambda_templates_include_required_actions():
    for template_path in TEMPLATE_PATHS:
        template_text = template_path.read_text(encoding="utf-8")
        missing_actions = [
            action
            for action in REQUIRED_SAGEMAKER_ACTIONS
            if action not in template_text
        ]
        assert not missing_actions, (
            f"{template_path.name} is missing SageMaker Lambda permissions: "
            f"{', '.join(missing_actions)}"
        )


# Actions the full-grade SageMaker legs added, each with the resource ARN its
# statement must name. A resource-typed action granted on '*' fails here.
SCOPED_SAGEMAKER_GRANTS = {
    "sagemaker:DescribeEndpointConfig": ":endpoint-config/*'",
    "organizations:ListTargetsForPolicy": ":policy/o-*/service_control_policy/p-*'",
    "organizations:ListParents": ":account/o-*/${AWS::AccountId}'",
    "securityhub:DescribeOrganizationConfiguration": ":hub/default'",
    "securityhub:ListEnabledProductsForImport": ":hub/default'",
    "logs:DescribeMetricFilters": ":log-group:*'",
    "events:ListTargetsByRule": ":rule/*'",
    "iot:ListPrincipalThings": ":cert/*'",
    "iot:DescribeScheduledAudit": ":scheduledaudit/*'",
    "s3:GetEncryptionConfiguration": ":s3:::*'",
    "s3:GetBucketPolicy": ":s3:::*'",
    "kms:DescribeKey": ":key/*'",
    "sagemaker:DescribeUserProfile": ":user-profile/*/*'",
    "sagemaker:DescribeInferenceComponent": ":inference-component/*'",
    "cloudtrail:GetTrailStatus": ":cloudtrail:*:*:trail/*'",
    "cloudtrail:GetEventSelectors": ":cloudtrail:*:*:trail/*'",
    "config:DescribeConfigurationRecorderStatus": ":configuration-recorder/*/*'",
    "config:DescribeConformancePackCompliance": ":conformance-pack/*/*'",
    "ecr:DescribeRepositories": ":ecr:*:*:repository/*'",
    "ecr:DescribeImageSigningStatus": ":ecr:*:${AWS::AccountId}:repository/*'",
    "elasticfilesystem:DescribeFileSystems": (
        ":elasticfilesystem:*:${AWS::AccountId}:file-system/*'"
    ),
}


def _sagemaker_function_statements(template_text):
    start = re.search(
        r"^  SagemakerSecurityAssessmentFunction:\n", template_text, re.MULTILINE
    )
    rest = template_text[start.end() :]
    match = re.search(r"\n  [A-Za-z0-9]+:\n", rest)
    block = rest[: match.start()] if match else rest
    return block.split("- Sid:")[1:]


def _sagemaker_managed_statements(template_text):
    start = re.search(
        r"^  SageMakerAssessmentReadsPolicy:\n", template_text, re.MULTILINE
    )
    rest = template_text[start.end() :]
    match = re.search(r"\n  [A-Za-z0-9]+:\n", rest)
    return rest[: match.start()].split("- Sid:")[1:]


def test_new_sagemaker_grants_are_resource_scoped_on_the_sagemaker_function():
    # The function's inline statements and its managed policy together, so an
    # action held once in each fails as held twice.
    for template_path in TEMPLATE_PATHS:
        text = template_path.read_text(encoding="utf-8")
        statements = _sagemaker_function_statements(
            text
        ) + _sagemaker_managed_statements(text)
        for action, resource in SCOPED_SAGEMAKER_GRANTS.items():
            holding = [s for s in statements if re.search(rf"- {action}\b", s)]
            assert len(holding) == 1, f"{template_path.name}: {action} not granted once"
            assert resource in holding[0], f"{template_path.name}: {action} scope"
            assert "Resource: '*'" not in holding[0], f"{template_path.name}: {action}"


# Approved reads with no IAM resource type, each with the statement that holds
# it on '*'.
APPROVED_WILDCARD_SAGEMAKER_GRANTS = {
    "ec2:DescribeVpcEndpoints": "EC2NetworkPostureInventory",
    "ec2:DescribeFlowLogs": "EC2NetworkPostureInventory",
    "ec2:DescribeSecurityGroups": "EC2NetworkPostureInventory",
    "config:DescribeConformancePacks": "ConformancePackInventory",
    "iot:DescribeAccountAuditConfiguration": "IoTDeviceDefenderAuditRead",
    "iot:ListAuditFindings": "IoTDeviceDefenderAuditRead",
    "inspector2:BatchGetAccountStatus": "InspectorAccountStatusRead",
    "lambda:ListFunctions": "LambdaFunctionInventory",
    "cloudtrail:DescribeTrails": "ApprovedInventoryWithoutResourceType",
    "config:ListConfigurationRecorders": "ApprovedInventoryWithoutResourceType",
    "ecs:DescribeTaskDefinition": "ApprovedInventoryWithoutResourceType",
    "ecs:ListClusters": "ApprovedInventoryWithoutResourceType",
    "ecs:ListServices": "ApprovedInventoryWithoutResourceType",
    "events:ListRules": "ApprovedInventoryWithoutResourceType",
    "inspector2:ListCoverage": "ApprovedInventoryWithoutResourceType",
    "iot:ListScheduledAudits": "ApprovedInventoryWithoutResourceType",
    "ram:ListResources": "ApprovedInventoryWithoutResourceType",
    "securityhub:GetConfigurationPolicyAssociation": "ApprovedInventoryWithoutResourceType",
    "ecr:GetSigningConfiguration": "ApprovedInventoryWithoutResourceType",
    "fsx:DescribeFileSystems": "ApprovedInventoryWithoutResourceType",
    "sagemaker:ListInferenceComponents": "ApprovedInventoryWithoutResourceType",
    "sagemaker:ListUserProfiles": "ApprovedInventoryWithoutResourceType",
    # API_DescribeAlarms and API_DescribeAlarmHistory return composite alarms
    # only when the permission is scoped to '*'.
    "cloudwatch:DescribeAlarms": "CompositeAlarmRead",
    "cloudwatch:DescribeAlarmHistory": "CompositeAlarmRead",
}

# Reads the SageMaker legs call that are not approved. Each leg reports "not
# read" on AccessDenied, so none may be granted.
UNAPPROVED_SAGEMAKER_READS = [
    "guardduty:ListMembers",
    "organizations:ListAccounts",
    "s3:GetObjectAttributes",
]


def test_approved_wildcard_grants_sit_in_their_named_statement():
    for template_path in TEMPLATE_PATHS:
        statements = _sagemaker_function_statements(
            template_path.read_text(encoding="utf-8")
        )
        for action, sid in APPROVED_WILDCARD_SAGEMAKER_GRANTS.items():
            holding = [s for s in statements if re.search(rf"- {action}\b", s)]
            assert len(holding) == 1, f"{template_path.name}: {action} not granted once"
            assert holding[0].split()[0] == sid, f"{template_path.name}: {action} sid"
            assert "Resource: '*'" in holding[0], f"{template_path.name}: {action}"


def test_unapproved_reads_are_not_granted_to_the_sagemaker_function():
    for template_path in TEMPLATE_PATHS:
        statements = _sagemaker_function_statements(
            template_path.read_text(encoding="utf-8")
        )
        for action in UNAPPROVED_SAGEMAKER_READS:
            assert not [s for s in statements if re.search(rf"- {action}\b", s)], (
                f"{template_path.name}: {action} is granted without approval"
            )


def test_model_artifact_object_read_is_get_object_on_objects_only():
    # SM-43 calls only HeadObject, which s3:GetObject authorizes. The grant
    # names the object resource type and sits apart from the report bucket's
    # permissions-cache read, so neither widens the other.
    for template_path in TEMPLATE_PATHS:
        statements = _sagemaker_function_statements(
            template_path.read_text(encoding="utf-8")
        )
        holding = [s for s in statements if re.search(r"- s3:GetObject\b", s)]
        assert sorted(s.split()[0] for s in holding) == [
            "ModelArtifactObjectRead",
            "PermissionCacheRead",
        ], template_path.name
        artifact = next(s for s in holding if s.split()[0] == "ModelArtifactObjectRead")
        assert re.findall(r"- ([a-z0-9-]+:[A-Za-z*]+)", artifact) == ["s3:GetObject"]
        assert "Resource: !Sub 'arn:${AWS::Partition}:s3:::*/*'" in artifact
        # The grant sits inside the opt-in condition, so it is absent by default.
        assert "- !Ref AWS::NoValue" in artifact
        text = template_path.read_text(encoding="utf-8")
        assert (
            "- !If\n              - SageMakerArtifactObjectReadsEnabled\n"
            "              - Sid: ModelArtifactObjectRead\n"
        ) in text
        cache = next(s for s in holding if s.split()[0] == "PermissionCacheRead")
        assert "permissions_cache_*.json" in cache


def test_model_image_repository_read_reaches_other_accounts_for_describe_only():
    # SM-43 reads the tag mutability of repositories in any registry an
    # endpoint image names, AWS Deep Learning Containers included. Signing
    # status is read only for this account's registry, so it stays scoped.
    for template_path in TEMPLATE_PATHS:
        text = template_path.read_text(encoding="utf-8")
        by_sid = {
            s.split()[0]: s
            for s in _sagemaker_function_statements(text)
            + _sagemaker_managed_statements(text)
        }
        assert not any(
            s.split()[0] == "ModelImageRepositoryAnyAccountRead"
            for s in _sagemaker_function_statements(text)
        )
        any_account = by_sid["ModelImageRepositoryAnyAccountRead"]
        assert re.findall(r"- ([a-z0-9-]+:[A-Za-z*]+)", any_account) == [
            "ecr:DescribeRepositories"
        ], template_path.name
        assert (
            "Resource: !Sub 'arn:${AWS::Partition}:ecr:*:*:repository/*'" in any_account
        )
        own = by_sid["ModelImageRepositoryRead"]
        assert re.findall(r"- ([a-z0-9-]+:[A-Za-z*]+)", own) == [
            "ecr:DescribeImageSigningStatus"
        ], template_path.name
        assert (
            "Resource: !Sub 'arn:${AWS::Partition}:ecr:*:${AWS::AccountId}:repository/*'"
            in own
        )


def test_model_artifact_prefix_list_is_list_bucket_on_buckets_only():
    # SM-43 calls ListObjectsV2, which s3:ListBucket authorizes on the bucket
    # resource type. The grant sits in the managed policy and nowhere inline.
    for template_path in TEMPLATE_PATHS:
        text = template_path.read_text(encoding="utf-8")
        assert not any(
            re.search(r"- s3:ListBucket\b", s)
            for s in _sagemaker_function_statements(text)
        ), template_path.name
        holding = [
            s
            for s in _sagemaker_managed_statements(text)
            if re.search(r"- s3:ListBucket\b", s)
        ]
        assert [s.split()[0] for s in holding] == ["ModelArtifactPrefixList"]
        assert re.findall(r"- ([a-z0-9-]+:[A-Za-z*]+)", holding[0]) == ["s3:ListBucket"]
        assert "Resource: !Sub 'arn:${AWS::Partition}:s3:::*'\n" in holding[0]
