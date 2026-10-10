"""Guard the Botocore Agent Registry model required by both implementation phases."""

from pathlib import Path

import boto3
import botocore
import botocore.loaders
import botocore.session


REPO_ROOT = Path(__file__).resolve().parents[1]
REQUIRED_SDK_VERSION = "1.43.108"
BOTOCORE_DATA_PATH = Path(botocore.__file__).resolve().parent / "data"


def _bundled_botocore_session():
    """Create a session that can resolve models only from pinned Botocore data."""
    data_loader = botocore.loaders.Loader(
        extra_search_paths=[str(BOTOCORE_DATA_PATH)],
        include_default_search_paths=False,
    )
    botocore_session = botocore.session.Session()
    botocore_session.register_component("data_loader", data_loader)
    return botocore_session


def _agent_registry_control_client():
    return _bundled_botocore_session().create_client(
        "agent-registry-control",
        region_name="us-east-1",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
    )


def _agent_registry_data_client():
    return _bundled_botocore_session().create_client(
        "agent-registry",
        region_name="us-east-1",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
    )


def test_agent_registry_sdk_version_is_pinned_to_required_model():
    assert boto3.__version__ == REQUIRED_SDK_VERSION
    assert botocore.__version__ == REQUIRED_SDK_VERSION


def test_sdk_contract_resolves_only_bundled_botocore_models():
    session = _bundled_botocore_session()
    data_loader = session.get_component("data_loader")

    assert BOTOCORE_DATA_PATH.is_dir()
    assert [Path(path).resolve() for path in data_loader.search_paths] == [
        BOTOCORE_DATA_PATH
    ]


def test_all_runtime_requirements_use_the_tested_sdk_contract():
    requirements_files = sorted(
        (REPO_ROOT / "aiml-security-assessment" / "functions" / "security").glob(
            "*/requirements.txt"
        )
    )
    requirements_files.append(REPO_ROOT / "tests" / "requirements.txt")

    expected_pins = {
        f"boto3=={REQUIRED_SDK_VERSION}",
        f"botocore=={REQUIRED_SDK_VERSION}",
    }
    for requirements_file in requirements_files:
        lines = {
            line.strip()
            for line in requirements_file.read_text(encoding="utf-8").splitlines()
        }
        missing = sorted(expected_pins - lines)
        assert not missing, (
            f"{requirements_file.relative_to(REPO_ROOT)} is missing exact AWS SDK "
            f"pin(s): {missing}"
        )


def test_agent_registry_control_operations_and_paginator_are_available():
    client = _agent_registry_control_client()
    operation_names = set(client.meta.service_model.operation_names)

    assert {
        "ListRegistries",
        "GetRegistry",
        "ListRegistryRecords",
    } <= operation_names
    assert client.can_paginate("list_registries")
    assert client.can_paginate("list_registry_records")


def test_get_registry_exposes_phase_one_security_configuration():
    client = _agent_registry_control_client()
    service_model = client.meta.service_model
    output_shape = service_model.operation_model("GetRegistry").output_shape

    assert {"approvalConfiguration", "discoveryConfiguration"} <= set(
        output_shape.members
    )

    discovery_shape = output_shape.members["discoveryConfiguration"]
    authorizer_shape = discovery_shape.members["authorizerConfiguration"]
    jwt_shape = authorizer_shape.members["customJWTAuthorizer"]

    assert {
        "discoveryUrl",
        "allowedAudience",
        "allowedClients",
        "allowedScopes",
        "customClaims",
    } <= set(jwt_shape.members)


def test_get_registry_exposes_phase_two_security_configuration():
    client = _agent_registry_control_client()
    service_model = client.meta.service_model
    output_shape = service_model.operation_model("GetRegistry").output_shape

    assert {"encryptionConfiguration", "autoDetection"} <= set(output_shape.members)

    encryption_shape = output_shape.members["encryptionConfiguration"]
    assert {"kmsKeyArn"} <= set(encryption_shape.members)

    auto_detection_shape = output_shape.members["autoDetection"]
    assert {"configuration", "status", "statusReason"} <= set(
        auto_detection_shape.members
    )
    configuration_shape = auto_detection_shape.members["configuration"]
    assert {"enabled", "scope"} <= set(configuration_shape.members)
    assert {"ORGANIZATION"} <= set(configuration_shape.members["scope"].enum)
    assert {"ACTIVE", "INACTIVE"} <= set(auto_detection_shape.members["status"].enum)


def test_registry_record_model_exposes_phase_two_governance_metadata():
    client = _agent_registry_control_client()
    service_model = client.meta.service_model
    list_output_shape = service_model.operation_model(
        "ListRegistryRecords"
    ).output_shape
    summary_shape = list_output_shape.members["registryRecords"].member
    assert {
        "status",
        "createdBy",
        "createdByAutoDetection",
        "provenanceSummaryList",
    } <= set(summary_shape.members)
    assert {"GATEWAY"} <= set(summary_shape.members["recordType"].enum)

    provenance_shape = summary_shape.members["provenanceSummaryList"].member
    assert {"relation", "sourceId", "sourceType"} <= set(provenance_shape.members)


def test_agent_registry_discovery_plane_operations_and_paginator_are_available():
    client = _agent_registry_data_client()
    operation_names = set(client.meta.service_model.operation_names)

    assert {
        "ListDiscoverableRegistryRecords",
        "SearchDiscoverableRegistryRecords",
        "BatchGetDiscoverableRegistryRecord",
    } <= operation_names
    assert client.can_paginate("list_discoverable_registry_records")
