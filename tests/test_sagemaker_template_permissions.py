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
    "sagemaker:DescribeExperiment",
    "sagemaker:ListTrials",
    "sagemaker:DescribeTrial",
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
