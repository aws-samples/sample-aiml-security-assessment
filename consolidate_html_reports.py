#!/usr/bin/env python3
"""
Multi-account report consolidation script.

This script is executed during CodeBuild post-build phase to consolidate
security findings from CSV reports across multiple AWS accounts into a single
consolidated HTML report.

It uses the shared report_template module from the Lambda function directory
to ensure consistent report generation between single-account and multi-account
reports.
"""

import os
import sys
import glob
import csv
import boto3
from datetime import datetime
from botocore.exceptions import ClientError

# Add the Lambda function directory to path to import shared template
sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(__file__),
        "aiml-security-assessment",
        "functions",
        "security",
        "generate_consolidated_report",
    ),
)

from report_template import generate_html_report

# Sentinel region label used by the per-service assessments to tag IAM-only
# findings that run once per execution rather than per region. It is not a real
# AWS region and must be excluded when counting scanned regions.
GLOBAL_REGION_LABEL = "Global"


def build_multi_account_report_key(timestamp: str) -> str:
    """Build the consolidated multi-account HTML report object key."""
    return f"consolidated-reports/security_assessment_multi_account_{timestamp}.html"


def _account_files_dir():
    """Base directory holding per-account CSV files.

    Defaults to the CodeBuild layout (/tmp/account-files) but is overridable
    via the ACCOUNT_FILES_DIR environment variable so the consolidator can be
    exercised hermetically in tests (and repointed if ever needed).
    """
    # /tmp/account-files is the ephemeral CodeBuild working directory where the
    # buildspec stages per-account CSVs; it is not a security-sensitive path and is
    # overridable via ACCOUNT_FILES_DIR.
    return os.environ.get("ACCOUNT_FILES_DIR", "/tmp/account-files")  # nosec B108


def consolidate_html_reports():
    """
    Consolidate security findings from CSV reports across all accounts into a
    single HTML report using the shared report template.

    Reads CSV files from /tmp/account-files/*/security_report_*.csv and generates
    a consolidated multi-account report using the same template as single-account reports.
    """

    try:
        s3 = boto3.client("s3")
    except Exception as e:
        print(f"Error creating S3 client: {str(e)}")
        raise

    bucket = os.environ.get("BUCKET_REPORT")
    if not bucket:
        print("Error: BUCKET_REPORT environment variable is not set")
        raise ValueError("BUCKET_REPORT environment variable is required")

    all_findings = []
    account_ids = set()
    regions = set()
    service_stats = {
        "bedrock": {"passed": 0, "failed": 0, "na": 0},
        "sagemaker": {"passed": 0, "failed": 0, "na": 0},
        "agentcore": {"passed": 0, "failed": 0, "na": 0},
        "finserv": {"passed": 0, "failed": 0, "na": 0},
    }
    service_findings = {"bedrock": [], "sagemaker": [], "agentcore": [], "finserv": []}

    for account_dir in glob.glob(os.path.join(_account_files_dir(), "*/")):
        account_id = os.path.basename(account_dir.rstrip("/"))
        if account_id == "consolidated-reports":
            continue

        # Find all CSV files for this account
        csv_files = glob.glob(
            os.path.join(account_dir, "**/*_security_report_*.csv"), recursive=True
        )

        if csv_files:
            print(f"Processing CSV files for account {account_id}")
            account_ids.add(account_id)

            for csv_file in csv_files:
                try:
                    with open(csv_file, "r", encoding="utf-8") as f:
                        reader = csv.DictReader(f)
                        for row in reader:
                            # Map CSV columns to finding structure
                            region = row.get("Region", "")
                            # "Global" tags IAM-only findings; not a scanned region.
                            if (
                                region
                                and region != GLOBAL_REGION_LABEL
                                and "," not in region
                            ):
                                regions.add(region)
                            finding = {
                                "account_id": account_id,
                                "check_id": row.get("Check_ID", ""),
                                "finding": row.get("Finding", ""),
                                "details": row.get("Finding_Details", ""),
                                "resolution": row.get("Resolution", ""),
                                "reference": row.get("Reference", ""),
                                "severity": row.get("Severity", "N/A"),
                                "status": row.get("Status", ""),
                                "region": region,
                            }

                            # Determine service from Check_ID prefix
                            check_id = finding["check_id"].upper()
                            status = finding["status"].lower()

                            if check_id.startswith("BR-"):
                                service = "bedrock"
                            elif check_id.startswith("SM-"):
                                service = "sagemaker"
                            elif check_id.startswith("AC-"):
                                service = "agentcore"
                            elif check_id.startswith("FS-"):
                                service = "finserv"
                            else:
                                # Fallback to finding name analysis
                                finding_name = finding["finding"].lower()
                                if (
                                    "bedrock" in finding_name
                                    or "guardrail" in finding_name
                                ):
                                    service = "bedrock"
                                elif (
                                    "sagemaker" in finding_name
                                    or "domain" in finding_name
                                ):
                                    service = "sagemaker"
                                elif "agentcore" in finding_name:
                                    service = "agentcore"
                                else:
                                    service = "bedrock"

                            finding["_service"] = service
                            all_findings.append(finding)
                            service_findings[service].append(finding)

                            if status == "passed":
                                service_stats[service]["passed"] += 1
                            elif status == "failed":
                                service_stats[service]["failed"] += 1
                            elif status == "n/a":
                                service_stats[service]["na"] += 1

                except IOError as e:
                    print(f"Error reading CSV file {csv_file}: {str(e)}")
                    continue
                except Exception as e:
                    print(f"Error parsing CSV file {csv_file}: {str(e)}")
                    continue

    if all_findings:
        timestamp_display = datetime.now().strftime("%B %d, %Y %H:%M:%S UTC")

        # Use shared template to generate report
        consolidated_html = generate_html_report(
            all_findings=all_findings,
            service_findings=service_findings,
            service_stats=service_stats,
            mode="multi",
            account_ids=list(account_ids),
            timestamp=timestamp_display,
            regions=sorted(regions) if regions else None,
        )

        timestamp_file = datetime.now().strftime("%Y%m%d_%H%M%S")
        s3_key = build_multi_account_report_key(timestamp_file)

        try:
            s3.put_object(
                Bucket=bucket,
                Key=s3_key,
                Body=consolidated_html,
                ContentType="text/html",
            )
            print(f"Consolidated report saved to s3://{bucket}/{s3_key}")
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "NoSuchBucket":
                print(f"Error: Bucket '{bucket}' does not exist")
            elif error_code == "AccessDenied":
                print(f"Error: Access denied to bucket '{bucket}'")
            else:
                print(f"Error uploading to S3: {str(e)}")
            raise
        except Exception as e:
            print(f"Unexpected error uploading consolidated report: {str(e)}")
            raise
    else:
        print("No findings found for consolidation")
        for account_dir in glob.glob(os.path.join(_account_files_dir(), "*/")):
            account_id = os.path.basename(account_dir.rstrip("/"))
            all_files = glob.glob(os.path.join(account_dir, "**/*"), recursive=True)
            print(f"Account {account_id} files: {all_files}")


if __name__ == "__main__":
    consolidate_html_reports()
