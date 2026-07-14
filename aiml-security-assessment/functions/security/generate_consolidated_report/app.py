import boto3
import csv
import os
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from io import StringIO
from botocore.config import Config
from botocore.exceptions import ClientError

from report_template import generate_html_report as generate_report_from_template

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


# Reserved per-service check IDs used for rows synthesized by the report layer
# (matches the existing XX-00 convention the service Lambdas use for
# service-availability rows).
_MISSING_RESULTS_CHECK_IDS = {
    "bedrock": "BR-00",
    "sagemaker": "SM-00",
    "agentcore": "AC-00",
    "finserv": "FS-00",
}
_SERVICE_DISPLAY_NAMES = {
    "bedrock": "Bedrock",
    "sagemaker": "SageMaker",
    "agentcore": "AgentCore",
    "finserv": "FinServ",
}
# Name prefix shared with the per-check COULD_NOT_ASSESS disposition (see
# docs/SECURITY_CHECKS_FINSERV_SEVERITY_METHODOLOGY.md §3.4). The report
# template surfaces rows with this prefix in the "Unassessed Checks" metric.
COULD_NOT_ASSESS_PREFIX = "COULD NOT ASSESS: "


def _missing_results_row(
    service: str, region: str, execution_id: str
) -> Dict[str, str]:
    """Synthesize one visible finding row for a service whose assessment CSV is
    missing from S3 (for example, the service Lambda timed out or crashed and
    the state machine's Catch routed to its "Assessment Incomplete" state).

    Without this row the consolidated report would silently omit an entire
    service (or a service/region cell) and the customer would have no signal
    that anything was skipped — a silent understatement of risk. The row uses
    the COULD_NOT_ASSESS convention: Status="N/A" and Severity="Low", so it is
    visible in the findings table and the Unassessed Checks metric but is
    excluded from pass-rate denominators.
    """
    display = _SERVICE_DISPLAY_NAMES[service]
    scope = f"in region {region}" if region else "for this execution"
    return {
        "Check_ID": _MISSING_RESULTS_CHECK_IDS[service],
        "Finding": f"{COULD_NOT_ASSESS_PREFIX}{display} assessment results missing",
        "Finding_Details": (
            f"No {display} assessment report was found in S3 {scope} "
            f"(execution {execution_id}). The {display} checks were NOT assessed "
            "for this scope. The most common cause is a Lambda timeout, "
            "out-of-memory error, or crash that the state machine caught and "
            "skipped; the report would otherwise silently omit these checks."
        ),
        "Resolution": (
            "1. Open the Step Functions execution and look for a branch that "
            "ended in an 'Assessment Incomplete' state.\n"
            "2. Review the CloudWatch logs for the corresponding assessment "
            "Lambda function to find the root cause.\n"
            "3. Re-run the assessment; treat these checks as unassessed until "
            "a run completes without this row."
        ),
        "Reference": "https://docs.aws.amazon.com/step-functions/latest/dg/concepts-error-handling.html",
        "Severity": "Low",
        "Status": "N/A",
        "Region": region,
        "Compliance_Frameworks": "",
    }


def _regions_from_keys(keys, service: str, execution_id: str):
    """Parse the region suffix out of a service's report object keys.

    Keys look like ``{service}_security_report_{execution_id}_{region}.csv``
    (multi-region) or ``{service}_security_report_{execution_id}.csv``
    (single-file). Returns ``(regions, has_regionless_file)``.
    """
    prefix = f"{service}_security_report_{execution_id}"
    regions = set()
    has_regionless = False
    for key in keys:
        base = os.path.basename(key)
        if not base.startswith(prefix) or not base.endswith(".csv"):
            continue
        remainder = base[len(prefix) : -len(".csv")]
        if not remainder:
            has_regionless = True
        elif remainder.startswith("_") and len(remainder) > 1:
            regions.add(remainder[1:])
    return regions, has_regionless


def synthesize_missing_result_rows(
    assessment_results: Dict[str, Any],
    object_keys,
    execution_id: str,
    finserv_enabled: bool,
    account_id: str = None,
) -> None:
    """Append COULD_NOT_ASSESS rows for every service (and service/region cell)
    whose CSV is missing, so orchestration-level failures are visible in the
    report instead of silently shrinking it.

    - Bedrock/SageMaker/AgentCore run once per region and write one CSV per
      region; the expected region set is the union of regions any of them
      reported. A service missing a region from that union gets one row per
      missing region; a service with no files at all gets a single row.
    - FinServ runs once per execution (single CSV, multi-region internally)
      and only when the execution was started with enableFinServ=true, so it
      is only flagged when enabled and absent.
    """
    per_region_services = ["bedrock", "sagemaker", "agentcore"]
    regions_by_service = {}
    regionless_by_service = {}
    for service in per_region_services + ["finserv"]:
        regions, has_regionless = _regions_from_keys(object_keys, service, execution_id)
        regions_by_service[service] = regions
        regionless_by_service[service] = has_regionless

    expected_regions = set()
    for service in per_region_services:
        expected_regions.update(regions_by_service[service])

    for service in per_region_services:
        rows = []
        has_any_file = (
            bool(regions_by_service[service]) or regionless_by_service[service]
        )
        if not has_any_file:
            rows.append(_missing_results_row(service, "", execution_id))
        elif regions_by_service[service]:
            # Only compare per-region coverage for services using the
            # per-region file layout; a legacy region-less file covers the run.
            for region in sorted(expected_regions - regions_by_service[service]):
                rows.append(_missing_results_row(service, region, execution_id))
        if rows:
            if account_id:
                for row in rows:
                    row["Account_ID"] = account_id
            assessment_results[service]["missing_results"] = rows
            logger.warning(
                f"Synthesized {len(rows)} missing-results row(s) for {service} "
                f"(execution {execution_id})"
            )

    finserv_has_file = (
        bool(regions_by_service["finserv"]) or regionless_by_service["finserv"]
    )
    if finserv_enabled and not finserv_has_file:
        row = _missing_results_row("finserv", "", execution_id)
        if account_id:
            row["Account_ID"] = account_id
        assessment_results["finserv"]["missing_results"] = [row]
        logger.warning(
            f"Synthesized missing-results row for finserv (execution {execution_id})"
        )


def get_assessment_results(
    execution_id: str, account_id: str = None, finserv_enabled: bool = False
) -> Dict[str, Any]:
    """
    Download and parse Bedrock, SageMaker, AgentCore, and FinServ assessment CSV files for a given execution

    Args:
        s3_bucket (str): Source S3 bucket name
        execution_id (str): Step Functions execution ID
        finserv_enabled (bool): Whether the execution was started with
            enableFinServ=true (used to flag a missing FinServ report)

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

        # One prefix per service; each matches every region's report file.
        prefixes = [
            f"bedrock_security_report_{execution_id}",
            f"sagemaker_security_report_{execution_id}",
            f"agentcore_security_report_{execution_id}",
            f"finserv_security_report_{execution_id}",
        ]

        all_objects = []
        for prefix in prefixes:
            for page in paginator.paginate(Bucket=s3_bucket, Prefix=prefix):
                all_objects.extend(page.get("Contents", []))

        if not all_objects:
            logger.warning(f"No assessment files found for execution {execution_id}")
            return {}

        assessment_results = {
            "execution_id": execution_id,
            "account_id": account_id,
            "timestamp": datetime.now().isoformat(),
            "bedrock": {},
            "sagemaker": {},
            "agentcore": {},
            "agentic": {},
            "finserv": {},
        }

        # Process each CSV file
        for obj in all_objects:
            s3_key = obj["Key"]

            # Skip if not a CSV file
            if not s3_key.endswith(".csv"):
                continue

            try:
                # Get the file content
                response = s3_client.get_object(Bucket=s3_bucket, Key=s3_key)

                # Read CSV content
                csv_content = response["Body"].read().decode("utf-8")

                # Parse CSV content
                parsed_data = parse_csv_content(csv_content)

                # Add account_id to each row if provided
                if account_id:
                    for row in parsed_data:
                        row["Account_ID"] = account_id

                # Determine which category this file belongs to based on the path
                file_name = os.path.basename(s3_key)
                category = None

                if "bedrock" in s3_key.lower():
                    category = "bedrock"
                elif "sagemaker" in s3_key.lower():
                    category = "sagemaker"
                elif "agentcore" in s3_key.lower():
                    category = "agentcore"
                elif "finserv" in s3_key.lower():
                    category = "finserv"
                else:
                    logger.warning(f"Unknown assessment type for file: {s3_key}")
                    continue

                # Store parsed data in appropriate category
                assessment_type = file_name.replace(".csv", "").lower()
                assessment_results[category][assessment_type] = parsed_data

                logger.info(
                    f"Successfully processed {file_name} for {category} assessment"
                )

            except Exception as e:
                logger.error(f"Error processing file {s3_key}: {str(e)}", exc_info=True)
                continue

        # Surface orchestration-level gaps: if a service (or a service/region
        # cell) produced no CSV — e.g. its Lambda timed out and the state
        # machine's Catch skipped it — synthesize a visible COULD_NOT_ASSESS
        # row instead of silently omitting those checks from the report.
        synthesize_missing_result_rows(
            assessment_results,
            [obj["Key"] for obj in all_objects],
            execution_id,
            finserv_enabled,
            account_id,
        )

        # Add summary information
        assessment_results["summary"] = {
            "total_files_processed": len(assessment_results["bedrock"])
            + len(assessment_results["sagemaker"])
            + len(assessment_results["agentcore"])
            + len(assessment_results["agentic"])
            + len(assessment_results["finserv"]),
            "categories_found": [
                cat
                for cat in ["bedrock", "sagemaker", "agentcore", "agentic", "finserv"]
                if assessment_results[cat]
            ],
            "rows": assessment_results["bedrock"],
            "assessment_types": {
                "bedrock": list(assessment_results["bedrock"].keys()),
                "sagemaker": list(assessment_results["sagemaker"].keys()),
                "agentcore": list(assessment_results["agentcore"].keys()),
                "agentic": list(assessment_results["agentic"].keys()),
                "finserv": list(assessment_results["finserv"].keys()),
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


def generate_html_report(assessment_results: Dict[str, Any]) -> str:
    """
    Generate HTML report from assessment results.

    This function transforms the assessment_results structure into the format
    expected by the shared report_template module.

    Args:
        assessment_results: Dict containing bedrock, sagemaker, agentcore, finserv findings

    Returns:
        HTML report string
    """
    # Transform assessment_results into flat findings lists
    all_findings = []
    service_stats = {
        "bedrock": {"passed": 0, "failed": 0, "na": 0},
        "sagemaker": {"passed": 0, "failed": 0, "na": 0},
        "agentcore": {"passed": 0, "failed": 0, "na": 0},
        "agentic": {"passed": 0, "failed": 0, "na": 0},
        "finserv": {"passed": 0, "failed": 0, "na": 0},
    }
    service_findings = {
        "bedrock": [],
        "sagemaker": [],
        "agentcore": [],
        "agentic": [],
        "finserv": [],
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

    for service in ["bedrock", "sagemaker", "agentcore", "finserv"]:
        if service in assessment_results:
            for report_type, findings in assessment_results[service].items():
                for finding in findings:
                    output_service = (
                        "agentic"
                        if finding.get("Check_ID", "").upper().startswith("AG-")
                        else service
                    )
                    dedup_key = (
                        finding.get("Account_ID", ""),
                        output_service,
                        finding.get("Check_ID", ""),
                        finding.get("Region", ""),
                        finding.get("Finding_Details", ""),
                    )
                    if dedup_key in seen_findings:
                        continue
                    seen_findings.add(dedup_key)

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

    account_id = assessment_results.get("account_id", "Unknown")
    timestamp = assessment_results.get(
        "timestamp", datetime.now(timezone.utc).strftime("%B %d, %Y %H:%M:%S UTC")
    )

    try:
        return generate_report_from_template(
            all_findings=all_findings,
            service_findings=service_findings,
            service_stats=service_stats,
            mode="single",
            account_id=account_id,
            timestamp=timestamp,
            regions=sorted(regions) if regions else None,
        )
    except Exception as e:
        logger.error(f"Error generating HTML report: {str(e)}", exc_info=True)
        return f"""<!DOCTYPE html><html><body><h1>Error Generating Report</h1><p>An error occurred: {str(e)}</p></body></html>"""


def get_current_utc_date():
    return datetime.now(timezone.utc).strftime("%Y/%m/%d")


def build_single_account_report_key(timestamp: str) -> str:
    """Build the single-account HTML report object key."""
    return f"security_assessment_single_account_{timestamp}.html"


def write_html_to_s3(
    html_content: str, s3_bucket: str, execution_id: str, account_id: str = None
) -> Optional[str]:
    """
    Write HTML report to S3

    Args:
        html_content (str): HTML content to write
        s3_bucket (str): Destination S3 bucket name
        execution_id (str): Step Functions execution ID

    Returns:
        Optional[str]: S3 key if successful, None if error
    """
    try:
        s3_client = boto3.client("s3", config=boto3_config)

        # Generate the S3 key for local bucket (no account folder needed)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        s3_key = build_single_account_report_key(timestamp)

        # Upload the HTML file
        s3_client.put_object(
            Bucket=s3_bucket,
            Key=s3_key,
            Body=html_content,
            ContentType="text/html",
            Metadata={"execution-id": execution_id},
        )

        logger.info(f"Successfully wrote HTML report to s3://{s3_bucket}/{s3_key}")
        return s3_key

    except Exception as e:
        logger.error(f"Error writing HTML report to S3: {str(e)}", exc_info=True)
        return None


def lambda_handler(event, context):
    """
    Main Lambda handler
    """
    logger.info("Generating Consolidated HTML Report")
    logger.info(f"Event: {event}")

    try:
        # Get execution ID from event
        execution_id = event["Execution"]["Name"]
        # The Step Functions context object ($$.Execution) carries the original
        # execution input; enableFinServ gates whether the FinServ branch ran,
        # so a missing FinServ CSV is only an assessment gap when it was enabled.
        execution_input = event.get("Execution", {}).get("Input", {}) or {}
        if not isinstance(execution_input, dict):
            execution_input = {}
        finserv_enabled = (
            str(execution_input.get("enableFinServ", "")).lower() == "true"
        )
        # Get account ID using STS GetCallerIdentity
        sts_client = boto3.client("sts", config=boto3_config)
        account_id = sts_client.get_caller_identity()["Account"]
        # Get S3 bucket name from environment variable
        s3_bucket = os.environ.get("AIML_ASSESSMENT_BUCKET_NAME")
        if not s3_bucket:
            raise ValueError(
                "AIML_ASSESSMENT_BUCKET_NAME environment variable is required"
            )

        # Get assessment results
        assessment_results = get_assessment_results(
            execution_id, account_id, finserv_enabled
        )
        if not assessment_results:
            raise ValueError(f"No assessment results found: {execution_id}")

        # Generate HTML report
        html_content = generate_html_report(assessment_results)

        # Write HTML report to S3
        s3_key = write_html_to_s3(html_content, s3_bucket, execution_id, account_id)

        if not s3_key:
            raise Exception("Failed to write HTML report to S3")

        # Note: Multi-account consolidation is handled by consolidate_html_reports.py
        # in the CodeBuild post-build phase, not here. This Lambda only generates
        # the per-account security_assessment_*.html report.

        # Delete the IAM permissions cache file — it contains full policy documents
        # and should not persist in S3 after the assessment completes
        try:
            cache_key = f"permissions_cache_{execution_id}.json"
            s3_client = boto3.client("s3", config=boto3_config)
            s3_client.delete_object(Bucket=s3_bucket, Key=cache_key)
            logger.info(f"Deleted permissions cache: {cache_key}")
        except Exception as cache_err:
            logger.warning(f"Failed to delete permissions cache: {cache_err}")

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
        return {
            "statusCode": 500,
            "executionId": execution_id if "execution_id" in locals() else "unknown",
            "body": f"Error generating HTML report: {str(e)}",
        }
