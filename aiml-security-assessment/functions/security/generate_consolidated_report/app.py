import boto3
import csv
import os
import logging
import re
from datetime import datetime, timezone
from typing import Dict, List, Any
from io import StringIO
from botocore.config import Config
from botocore.exceptions import ClientError

from aisf_mappings import aisf_scope, derive_aisf_findings
from aisf_results import build_aisf_register
from assessment_artifacts import (
    REGION_PATTERN,
    SOURCE_IDS,
    artifact_identity,
    artifact_issue,
    bucket_observation_region_matches,
    coverage_issues,
    equivalent_observation_key,
    parse_csv_artifact,
    scoped_issues,
)
from report_template import (
    COMPLIANCE_STANDARDS,
    core_service_selection,
    generate_html_report as generate_report_from_template,
)

# Sentinel region label used by the per-service assessments to tag findings that
# are derived purely from global (IAM) data and run once per execution rather
# than per region (e.g. BR-01, SM-02, AC-09). It is NOT a real AWS region, so it
# must be excluded when counting scanned regions for the report's multi-region
# UI (region filter, "Risk by Region", region count).
GLOBAL_REGION_LABEL = "Global"

boto3_config = Config(
    retries=dict(
        max_attempts=10,  # Maximum number of retries
        mode="adaptive",  # Exponential backoff with adaptive mode
    )
)

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.WARNING)


def parse_csv_content(csv_content: str) -> List[Dict[str, str]]:
    """
    Parse CSV content into a list of dictionaries

    Args:
        csv_content (str): CSV content as string

    Returns:
        List[Dict[str, str]]: List of dictionaries where each dict represents a row
    """
    results = []
    csv_file = StringIO(csv_content)
    csv_reader = csv.DictReader(csv_file)

    for row in csv_reader:
        results.append(dict(row))

    return results


def _flag_is_true(value: Any) -> bool:
    """Interpret a Step Functions payload flag as a boolean.

    Accepts the string "true" (case-insensitive) or the boolean True. Any
    other value (missing key, "false", None, unrelated string) is False.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return False


def _assessment_receipt_issues(
    original_input: Dict[str, Any],
    *,
    account: str,
    execution_id: str,
    regions: List[str],
    selected_services: Dict[str, bool],
    enable_grc: bool,
    enable_owasp: bool,
    require_receipts: bool,
) -> List[Dict[str, Any]]:
    """Validate compact region receipts without replacing useful CSV evidence."""
    if "AssessmentResults" not in original_input and not require_receipts:
        return []
    receipts = original_input.get("AssessmentResults")
    if not isinstance(receipts, list):
        return [
            artifact_issue(
                "missing-receipts",
                "Restore the region assessment receipts and rerun this execution.",
                account=account,
            )
        ]
    issues = []
    observed = set()
    owners = {*selected_services, "responsible-ai-grc", "owasp"}
    expected = {
        (region, owner)
        for region in regions
        for owner, selected in selected_services.items()
        if selected
    }
    if regions and (enable_grc or enable_owasp):
        expected.add((regions[0], "responsible-ai-grc"))
    if enable_owasp:
        expected.update((region, "owasp") for region in regions)
    for receipt in receipts:
        if not isinstance(receipt, dict):
            issues.append(
                artifact_issue(
                    "invalid-receipt",
                    "Restore a valid region assessment receipt and rerun.",
                    account=account,
                    observation=receipt,
                )
            )
            continue
        region = receipt.get("Region", "")
        if (
            region not in regions
            or receipt.get("ExecutionId") != execution_id
            or receipt.get("Account", account) != account
            or type(receipt.get("RegionIndex")) is not int
            or receipt.get("RegionIndex") != regions.index(region)
        ):
            issues.append(
                artifact_issue(
                    "scope-mismatch",
                    "A region receipt belongs to another scope; restore the expected receipt.",
                    account=account,
                    observation=receipt,
                )
            )
            continue
        service_results = receipt.get("ServiceResults")
        if not isinstance(service_results, list):
            service_results = []
            issues.append(
                artifact_issue(
                    "invalid-receipt",
                    "Restore the service assessment receipts for this region.",
                    account=account,
                    region=region,
                    observation=receipt,
                )
            )
        wrappers = [(wrapper, False) for wrapper in service_results]
        if "OWASPResult" in receipt:
            wrappers.append((receipt["OWASPResult"], True))
        for wrapper, is_owasp in wrappers:
            if (
                not isinstance(wrapper, dict)
                or not isinstance(wrapper.get("service"), str)
                or wrapper["service"] not in owners
            ):
                issues.append(
                    artifact_issue(
                        "invalid-receipt",
                        "Restore a receipt with a known assessment owner.",
                        account=account,
                        region=region,
                        observation=wrapper,
                    )
                )
                continue
            owner = wrapper["service"]
            if (
                is_owasp != (owner == "owasp")
                or wrapper.get("Region", region) != region
                or wrapper.get("Account", account) != account
                or wrapper.get("ExecutionId", execution_id) != execution_id
            ):
                issues.append(
                    artifact_issue(
                        "scope-mismatch",
                        "An assessment receipt belongs to another owner or execution scope.",
                        account=account,
                        region=region,
                        owner=owner,
                        observation=wrapper,
                    )
                )
                continue
            if (region, owner) not in expected:
                continue
            observed.add((region, owner))
            if (
                wrapper.get("statusCode") != 200
                or _flag_is_true(wrapper.get("incomplete"))
                or _flag_is_true(wrapper.get("skipped"))
                or wrapper.get("error")
            ):
                issues.append(
                    artifact_issue(
                        "failed-assessment",
                        f"Restore the failed {owner} assessment in {region} and rerun; "
                        "valid CSV observations remain evidence, but do not prove completion.",
                        account=account,
                        region=region,
                        owner=owner,
                        observation=wrapper,
                        error=wrapper.get("error", ""),
                    )
                )
    for region, owner in sorted(expected - observed):
        issues.append(
            artifact_issue(
                "missing-receipt",
                f"Restore the selected {owner} assessment receipt in {region} and rerun.",
                account=account,
                region=region,
                owner=owner,
            )
        )
    return issues


def validate_assessment_artifacts(
    assessment_results: Dict[str, Any],
    execution_id: str,
    original_input: Dict[str, Any],
    *,
    require_receipts: bool = False,
) -> None:
    """Record incomplete input scopes, then fail the completion gate."""
    resolved_regions = (original_input.get("ResolvedRegions") or {}).get("regions")
    selected_services = core_service_selection(original_input.get("ServiceSelection"))
    enable_grc = _flag_is_true(original_input.get("enableResponsibleAIGRC"))
    enable_owasp = _flag_is_true(original_input.get("enableOWASP"))
    issues = scoped_issues(
        assessment_results.get("artifact_issues", []),
        selected_services,
        enable_grc=enable_grc,
        enable_owasp=enable_owasp,
    )
    account = assessment_results.get("account_id") or "Unknown"
    if (
        not isinstance(resolved_regions, list)
        or not resolved_regions
        or not all(
            isinstance(region, str) and re.fullmatch(REGION_PATTERN, region)
            for region in resolved_regions
        )
    ):
        resolved_regions = []
        issues.append(
            artifact_issue(
                "missing-regions",
                "ResolvedRegions.regions is required to validate assessment coverage",
                account=account,
            )
        )
    assessment_results["expected_regions"] = list(resolved_regions)
    assessment_results["scopes"] = [
        {"account": account, "region": region, "execution_id": execution_id}
        for region in resolved_regions or ["Unspecified"]
    ]
    assessment_results["enable_owasp"] = enable_owasp
    issues.extend(
        _assessment_receipt_issues(
            original_input,
            account=account,
            execution_id=execution_id,
            regions=resolved_regions,
            selected_services=selected_services,
            enable_grc=enable_grc,
            enable_owasp=enable_owasp,
            require_receipts=require_receipts,
        )
    )
    issues.extend(
        coverage_issues(
            assessment_results,
            account=account,
            execution_id=execution_id,
            regions=resolved_regions,
            service_selection=selected_services,
            enable_grc=enable_grc,
            enable_owasp=enable_owasp,
        )
    )
    assessment_results["artifact_issues"] = issues
    if issues:
        raise ValueError(
            f"Incomplete assessment artifacts for execution {execution_id}: "
            + "; ".join(issue["message"] for issue in issues)
        )


def get_assessment_results(
    execution_id: str,
    account_id: str = None,
    *,
    expected_regions: List[str] | None = None,
) -> Dict[str, Any]:
    """
    Download and parse Bedrock, SageMaker, AgentCore, and Responsible AI GRC assessment CSV files for a given execution

    Args:
        s3_bucket (str): Source S3 bucket name
        execution_id (str): Step Functions execution ID

    Returns:
        Dict[str, Any]: Nested object containing all assessment results
    """
    try:
        s3_client = boto3.client("s3", config=boto3_config)

        # List all CSV files with execution ID in filename (bucket root).
        # Use a paginator: a multi-region scan produces one file per service per
        # region, so a single list_objects_v2 call (capped at 1000 keys) could
        # silently truncate and drop regions for large scans.
        s3_bucket = os.environ.get("AIML_ASSESSMENT_BUCKET_NAME")
        paginator = s3_client.get_paginator("list_objects_v2")

        # Category slug → CSV filename fragment (also matched in S3 key). The
        # first four are hard-coded per-service Lambdas; compliance-standard
        # entries (owasp, and future NIST/EU AI Act) come from the shared
        # COMPLIANCE_STANDARDS registry so adding a standard is data-only.
        # The Responsible AI GRC category's CSV filename fragment
        # (responsible_ai_grc_security_report_) differs from its report
        # slug (responsible-ai-grc); category_to_csv_fragment maps between
        # them for the prefix list and the filename-matching loop below.
        #
        # Derived standards are excluded here and only here. A derived standard
        # (AISF) writes no CSV, so listing its prefix would be a request this
        # function's s3:ListBucket grant does not permit: the grant's s3:prefix
        # condition in template.yaml names the producing artifacts only, so the
        # call returns AccessDenied, the except ClientError below re-raises, and
        # report generation fails for every category. The fix belongs on the
        # registry, not on the IAM condition. All other consumers of
        # COMPLIANCE_STANDARDS keep the derived slug: it still needs its report
        # category, its service_stats/service_findings buckets, its prefix
        # routing, and its rendered section.
        category_slugs = [
            "bedrock",
            "sagemaker",
            "agentcore",
            "agent-registry",
            "responsible-ai-grc",
        ] + [std["slug"] for std in COMPLIANCE_STANDARDS if not std.get("derived")]
        category_to_csv_fragment = {
            "agent-registry": "agent_registry",
            "responsible-ai-grc": "responsible_ai_grc",
        }
        prefixes = [
            f"{category_to_csv_fragment.get(slug, slug)}_security_report_{execution_id}"
            for slug in category_slugs
        ]

        all_objects = []
        issues = []
        for slug, prefix in zip(category_slugs, prefixes):
            try:
                for page in paginator.paginate(Bucket=s3_bucket, Prefix=prefix):
                    all_objects.extend(page.get("Contents", []))
            except Exception as error:
                issues.append(
                    artifact_issue(
                        "discovery-failed",
                        "Restore artifact discovery and rerun; earlier pages were retained.",
                        account=account_id or "Unknown",
                        owner=slug,
                        artifact=prefix,
                        error=str(error),
                    )
                )

        if not all_objects:
            logger.warning(f"No assessment files found for execution {execution_id}")

        # Categories the report understands: per-service (bedrock/sagemaker/
        # agentcore/responsible-ai-grc), the reconstructed agentic lens, and
        # every registered compliance standard.
        report_categories = [
            "bedrock",
            "sagemaker",
            "agentcore",
            "agent-registry",
            "agentic",
            "responsible-ai-grc",
        ] + [std["slug"] for std in COMPLIANCE_STANDARDS]
        assessment_results = {
            "execution_id": execution_id,
            "account_id": account_id,
            "timestamp": os.environ.get("AISF_REPORT_TIMESTAMP")
            or datetime.now(timezone.utc).isoformat(),
            "artifact_issues": issues,
        }
        if expected_regions is not None:
            assessment_results["expected_regions"] = list(expected_regions)
        for cat in report_categories:
            assessment_results[cat] = {}

        producer_regions = {slug: set() for slug in category_slugs}
        for obj in all_objects:
            identity = artifact_identity(obj["Key"], execution_id)
            if identity and identity["matches_execution"] and identity["region"]:
                producer_regions[identity["owner"]].add(identity["region"])

        # Process each CSV file. Match category by filename prefix (e.g.
        # `owasp_security_report_...`); no substring collisions exist among
        # the registered slugs so first-match wins is safe.
        seen_objects = set()
        for obj in all_objects:
            s3_key = obj["Key"]

            # Skip if not a CSV file
            if not s3_key.endswith(".csv") or s3_key in seen_objects:
                continue
            seen_objects.add(s3_key)

            file_name = os.path.basename(s3_key)
            identity = artifact_identity(file_name, execution_id)
            if (
                not identity
                or not identity["matches_execution"]
                or (
                    expected_regions is not None
                    and identity["region"]
                    and identity["region"] not in expected_regions
                )
            ):
                issues.append(
                    artifact_issue(
                        "scope-mismatch",
                        "Isolate the CSV with an unknown producer or a different execution or region.",
                        account=account_id or "Unknown",
                        artifact=file_name,
                        owner=(identity or {}).get("owner", ""),
                    )
                )
                continue
            category = identity["owner"]
            assessment_type = file_name[:-4]
            assessment_results[category].setdefault(assessment_type, [])
            try:
                response = s3_client.get_object(Bucket=s3_bucket, Key=s3_key)
                parsed = parse_csv_artifact(
                    response["Body"].read(),
                    artifact=file_name,
                    account=account_id or "",
                    region=identity["region"],
                    selected_regions=(
                        expected_regions
                        if expected_regions is not None
                        else sorted(producer_regions[category])
                    ),
                    owner=category,
                    execution_id=execution_id,
                )
                issues.extend(parsed["issues"])
                assessment_results[category][assessment_type].extend(parsed["rows"])
                logger.info(
                    f"Successfully processed {file_name} for {category} assessment"
                )

            except Exception as e:
                logger.error(f"Error processing file {s3_key}: {str(e)}", exc_info=True)
                issues.append(
                    artifact_issue(
                        "unreadable",
                        "Restore access to the selected assessment CSV and rerun.",
                        account=account_id or "Unknown",
                        region=identity["region"],
                        owner=category,
                        artifact=file_name,
                        error=str(e),
                    )
                )
                continue

        assessment_results["summary"] = {
            "total_files_processed": sum(
                len(assessment_results[cat]) for cat in report_categories
            ),
            "categories_found": [
                cat for cat in report_categories if assessment_results[cat]
            ],
            "rows": assessment_results["bedrock"],
            "assessment_types": {
                cat: list(assessment_results[cat].keys()) for cat in report_categories
            },
        }

        return assessment_results

    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchBucket":
            logger.error(f"Bucket not found: {s3_bucket}")
        else:
            logger.error(
                f"AWS error retrieving assessment results: {str(e)}", exc_info=True
            )
        raise
    except Exception as e:
        logger.error(
            f"Unexpected error retrieving assessment results: {str(e)}", exc_info=True
        )
        raise


def generate_html_report(
    assessment_results: Dict[str, Any],
    show_finserv: bool = True,
    service_selection=None,
    enable_aisf: bool = False,
) -> str:
    """
    Generate HTML report from assessment results.

    This function transforms the assessment_results structure into the format
    expected by the shared report_template module.

    Args:
        assessment_results: Dict containing bedrock, sagemaker, agentcore,
            responsible-ai-grc findings
        show_finserv: When False, hide the standalone Responsible AI GRC
            (FS-*) section. When OWASP is enabled, its GRC dependency still
            supplies source evidence for the canonical AISF register.

    Returns:
        HTML report string
    """
    # Transform assessment_results into flat findings lists. Bedrock/SageMaker/
    # AgentCore/Agentic/Responsible AI GRC are fixed report categories;
    # compliance standards (OWASP + future NIST/EU AI Act) are appended from
    # the shared COMPLIANCE_STANDARDS registry so adding a standard is data-only.
    selected_services = core_service_selection(service_selection)
    compliance_slugs = [std["slug"] for std in COMPLIANCE_STANDARDS]
    all_report_slugs = [
        "bedrock",
        "sagemaker",
        "agentcore",
        "agent-registry",
        "agentic",
        "responsible-ai-grc",
    ] + compliance_slugs
    all_findings = []
    evidence_findings = []
    enable_owasp = assessment_results.get(
        "enable_owasp", bool(assessment_results.get("owasp"))
    )
    artifact_issues = scoped_issues(
        assessment_results.get("artifact_issues", []),
        selected_services,
        enable_grc=show_finserv,
        enable_owasp=enable_owasp,
    )
    account_id = assessment_results.get("account_id") or "Unknown"
    execution_id = assessment_results.get("execution_id", "")
    expected_regions = assessment_results.get("expected_regions")
    service_stats = {
        slug: {"passed": 0, "failed": 0, "na": 0} for slug in all_report_slugs
    }
    service_findings = {slug: [] for slug in all_report_slugs}
    # Check_ID prefix (uppercase, without trailing dash) → report-service slug
    # for the compliance standards; used to route rows by Check_ID prefix.
    compliance_prefix_to_slug = {
        std["prefix"].upper().rstrip("-"): std["slug"] for std in COMPLIANCE_STANDARDS
    }
    regions = set()

    # Global/IAM findings (Region == "Global", e.g. BR-01, SM-02, AC-09) are
    # produced once per run by the primary-region Lambda and should land in a
    # single CSV. Dedup defensively here so the totals and per-region tiles stay
    # correct even if the same finding ever appears in more than one region's
    # file (e.g. RegionIndex missing from the event, or a future per-region
    # write of a global check). The key uniquely identifies a finding within an
    # account; account is included so a future multi-account merge is unaffected.
    seen_findings = set()

    csv_source_slugs = [
        "bedrock",
        "sagemaker",
        "agentcore",
        "agent-registry",
        "responsible-ai-grc",
    ] + compliance_slugs
    for service in csv_source_slugs:
        if not selected_services.get(service, True):
            continue
        if service == "owasp" and not enable_owasp:
            continue
        if service == "responsible-ai-grc" and not (show_finserv or enable_owasp):
            continue
        if service in assessment_results:
            producer_regions = (
                expected_regions
                if expected_regions is not None
                else [
                    identity["region"]
                    for report_type in assessment_results[service]
                    if (
                        identity := artifact_identity(
                            report_type + ".csv", execution_id
                        )
                    )
                    and identity["owner"] == service
                    and identity["matches_execution"]
                    and identity["region"]
                ]
            )
            for report_type, findings in assessment_results[service].items():
                identity = artifact_identity(report_type + ".csv", execution_id)
                if (
                    not identity
                    or identity["owner"] != service
                    or not identity["matches_execution"]
                    or (
                        expected_regions is not None
                        and identity["region"]
                        and identity["region"] not in expected_regions
                    )
                ):
                    artifact_issues.append(
                        artifact_issue(
                            "scope-mismatch",
                            "Isolate the artifact from another producer, execution, or region.",
                            account=account_id,
                            owner=service,
                            artifact=report_type,
                            observations=findings,
                        )
                    )
                    continue
                for original in findings:
                    finding = dict(original)
                    check_id_upper = finding.get("Check_ID", "").upper()
                    owner = SOURCE_IDS.get(check_id_upper)
                    if (
                        owner != service
                        or finding.get("Account_ID", account_id) != account_id
                        or finding.get("account_id", account_id) != account_id
                        or (
                            execution_id
                            and finding.get("Execution_ID", execution_id)
                            != execution_id
                        )
                        or (
                            execution_id
                            and finding.get("execution_id", execution_id)
                            != execution_id
                        )
                        or (
                            identity["region"]
                            and finding.get("Region")
                            not in (identity["region"], "Global")
                            and not bucket_observation_region_matches(
                                finding,
                                owner=service,
                                artifact_region=identity["region"],
                                selected_regions=producer_regions,
                            )
                        )
                        or (
                            expected_regions is not None
                            and finding.get("Region")
                            not in (*expected_regions, "Global")
                        )
                        or finding.get("Status") not in ("Passed", "Failed", "N/A")
                    ):
                        artifact_issues.append(
                            artifact_issue(
                                "scope-mismatch",
                                "Isolate unknown/retired checks and cross-account, region, owner, or execution observations.",
                                account=account_id,
                                owner=service,
                                artifact=report_type,
                                observation=finding,
                            )
                        )
                        continue
                    finding.setdefault("Account_ID", account_id)
                    finding.setdefault("Execution_ID", execution_id)
                    finding.setdefault("_owner", owner)
                    finding.setdefault("_artifact", report_type + ".csv")
                    finding.setdefault("_artifact_region", identity["region"])
                    if check_id_upper.startswith("AG-"):
                        output_service = "agentic"
                    elif check_id_upper.startswith("AR-"):
                        output_service = "agent-registry"
                    elif (
                        "-" in check_id_upper
                        and check_id_upper.split("-", 1)[0] in compliance_prefix_to_slug
                    ):
                        output_service = compliance_prefix_to_slug[
                            check_id_upper.split("-", 1)[0]
                        ]
                    else:
                        output_service = service
                    dedup_key = equivalent_observation_key(finding)
                    if dedup_key in seen_findings:
                        continue
                    seen_findings.add(dedup_key)
                    evidence_findings.append(finding)
                    # OWASP's GRC dependency supplies AISF evidence without
                    # adding a standalone GRC section when GRC is not selected.
                    if not show_finserv and output_service == "responsible-ai-grc":
                        continue
                    finding["_service"] = output_service
                    all_findings.append(finding)
                    service_findings[output_service].append(finding)
                    status = finding.get("Status", "").lower()
                    if status == "passed":
                        service_stats[output_service]["passed"] += 1
                    elif status == "failed":
                        service_stats[output_service]["failed"] += 1
                    elif status == "n/a":
                        service_stats[output_service]["na"] += 1
                    region = finding.get("Region", "")
                    # "Global" tags IAM-only findings; it is not a scanned region
                    # and must not inflate the region count / multi-region UI.
                    if region and region != GLOBAL_REGION_LABEL and "," not in region:
                        regions.add(region)

    # AISF is a derived standard: no assessment Lambda produced AISF-* rows, so
    # they are computed here from the verdicts collected above. The input list
    # is snapshotted by the call, so appending to all_findings below is safe.
    # Derived rows run through the same seen_findings key as CSV rows so a
    # source file that appeared twice cannot double-count an AISF control.
    derived_aisf_findings = derive_aisf_findings(all_findings, selected_services)
    for finding in derived_aisf_findings:
        output_service = finding["_service"]
        dedup_key = equivalent_observation_key(finding)
        if dedup_key in seen_findings:
            continue
        seen_findings.add(dedup_key)
        all_findings.append(finding)
        service_findings[output_service].append(finding)
        status = finding.get("Status", "").lower()
        if status == "passed":
            service_stats[output_service]["passed"] += 1
        elif status == "failed":
            service_stats[output_service]["failed"] += 1
        elif status == "n/a":
            service_stats[output_service]["na"] += 1

    timestamp = os.environ.get("AISF_REPORT_TIMESTAMP") or assessment_results.get(
        "timestamp", datetime.now(timezone.utc).strftime("%B %d, %Y %H:%M:%S UTC")
    )
    assessment_results["artifact_issues"] = artifact_issues
    register = build_aisf_register(
        evidence_findings,
        accounts=[account_id],
        regions=expected_regions if expected_regions is not None else sorted(regions),
        service_selection=selected_services,
        artifact_issues=artifact_issues,
        execution_id=execution_id,
        scopes=assessment_results.get("scopes"),
        enable_grc=show_finserv,
        enable_owasp=enable_owasp,
        enable_aisf=enable_aisf,
    )

    return generate_report_from_template(
        all_findings=all_findings,
        service_findings=service_findings,
        service_stats=service_stats,
        service_selection=selected_services,
        compliance_scope={"aisf": aisf_scope(selected_services)},
        mode="single",
        account_id=account_id,
        timestamp=timestamp,
        regions=(
            expected_regions
            if expected_regions is not None
            else sorted(regions)
            if regions
            else None
        ),
        aisf_register=register,
    )


def get_current_utc_date():
    return datetime.now(timezone.utc).strftime("%Y/%m/%d")


def build_single_account_report_key(timestamp: str) -> str:
    """Build the single-account HTML report object key."""
    return f"security_assessment_single_account_{timestamp}.html"


def write_html_to_s3(
    html_content: str, s3_bucket: str, execution_id: str, account_id: str = None
) -> str:
    """
    Write HTML report to S3

    Args:
        html_content (str): HTML content to write
        s3_bucket (str): Destination S3 bucket name
        execution_id (str): Step Functions execution ID

    Returns:
        str: S3 key for the uploaded report
    """
    s3_client = boto3.client("s3", config=boto3_config)

    # Generate the S3 key for local bucket (no account folder needed)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    s3_key = build_single_account_report_key(timestamp)

    # Upload the HTML file. Any failure must propagate so Step Functions cannot
    # treat a missing report as a successful assessment.
    s3_client.put_object(
        Bucket=s3_bucket,
        Key=s3_key,
        Body=html_content,
        ContentType="text/html",
        Metadata={"execution-id": execution_id},
    )

    logger.info(f"Successfully wrote HTML report to s3://{s3_bucket}/{s3_key}")
    return s3_key


def delete_permissions_cache(s3_bucket: str, execution_id: str) -> None:
    """Best-effort cleanup for the execution-scoped IAM permissions cache."""
    try:
        cache_key = f"permissions_cache_{execution_id}.json"
        s3_client = boto3.client("s3", config=boto3_config)
        s3_client.delete_object(Bucket=s3_bucket, Key=cache_key)
        logger.info(f"Deleted permissions cache: {cache_key}")
    except Exception as cache_err:
        logger.warning(f"Failed to delete permissions cache: {cache_err}")


def lambda_handler(event, context):
    """
    Main Lambda handler
    """
    logger.info("Generating Consolidated HTML Report")
    logger.info(f"Event: {event}")

    execution_id = None
    s3_bucket = None
    try:
        # Get execution ID from event
        execution_id = event["Execution"]["Name"]
        # Get S3 bucket name from environment variable
        s3_bucket = os.environ.get("AIML_ASSESSMENT_BUCKET_NAME")
        if not s3_bucket:
            raise ValueError(
                "AIML_ASSESSMENT_BUCKET_NAME environment variable is required"
            )
        # Get account ID using STS GetCallerIdentity
        sts_client = boto3.client("sts", config=boto3_config)
        account_id = sts_client.get_caller_identity()["Account"]

        # The state machine now forces Responsible AI GRC to run whenever
        # OWASP is enabled (OWASP's FS→OW mappings need the Responsible AI
        # GRC CSV). Show the Responsible AI GRC UI only when the customer
        # selected it explicitly or through the AISF preset. When OWASP is on
        # but Responsible AI GRC
        # is off, FS-* rows are consumed silently by OWASP and hidden from
        # the report.
        original_input = event.get("OriginalInput") or {}
        show_finserv = _flag_is_true(original_input.get("enableResponsibleAIGRC"))
        resolved_regions = original_input.get("ResolvedRegions")
        expected_regions = (
            resolved_regions.get("regions")
            if isinstance(resolved_regions, dict)
            else None
        )

        # Get assessment results
        assessment_results = get_assessment_results(
            execution_id,
            account_id,
            expected_regions=(
                expected_regions if isinstance(expected_regions, list) else []
            ),
        )
        # Even an empty selection produces an explicit scope report. Coverage
        # validation below still rejects missing artifacts for selected areas.
        if not assessment_results:
            assessment_results = {
                "execution_id": execution_id,
                "account_id": account_id,
            }
        incomplete_error = None
        try:
            validate_assessment_artifacts(
                assessment_results,
                execution_id,
                original_input,
                require_receipts=True,
            )
        except ValueError as error:
            incomplete_error = error

        # Generate HTML report
        html_content = generate_html_report(
            assessment_results,
            show_finserv=show_finserv,
            service_selection=original_input.get("ServiceSelection"),
            enable_aisf=_flag_is_true(original_input.get("enableAISF")),
        )

        # Write HTML report to S3
        s3_key = write_html_to_s3(html_content, s3_bucket, execution_id, account_id)

        if not s3_key:
            raise Exception("Failed to write HTML report to S3")
        if incomplete_error or assessment_results.get("artifact_issues"):
            raise incomplete_error or ValueError(
                "Incomplete assessment artifacts: input scope validation failed"
            )

        # Note: Multi-account consolidation is handled by consolidate_html_reports.py
        # in the CodeBuild post-build phase, not here. This Lambda only generates
        # the per-account security_assessment_*.html report.

        return {
            "statusCode": 200,
            "executionId": execution_id,
            "body": {
                "message": "Successfully generated HTML report",
                "report_location": f"s3://{s3_bucket}/{s3_key}",
            },
        }

    except Exception as e:
        logger.error(f"Error in lambda_handler: {str(e)}", exc_info=True)
        raise
    finally:
        # The cache contains full IAM policy documents and is no longer needed
        # once report generation starts. Cleanup must not mask report failures.
        if execution_id and s3_bucket:
            delete_permissions_cache(s3_bucket, execution_id)
