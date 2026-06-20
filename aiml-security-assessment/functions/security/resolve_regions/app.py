"""
Resolve Target Regions Lambda Function

Resolves the list of AWS regions to scan based on the TARGET_REGIONS
environment variable. Returns a list for the Step Functions Map state
to iterate over.
"""

import os
import logging
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

BEDROCK_SERVICE = "bedrock"
SAGEMAKER_SERVICE = "sagemaker"
AGENTCORE_SERVICE = "bedrock-agentcore-control"

SERVICES = [BEDROCK_SERVICE, SAGEMAKER_SERVICE, AGENTCORE_SERVICE]


def get_available_regions():
    """Get the union of all regions where assessed services are available."""
    session = boto3.Session()
    all_regions = set()
    for service in SERVICES:
        try:
            regions = session.get_available_regions(service)
            all_regions.update(regions)
        except Exception as e:
            logger.warning(f"Could not get regions for {service}: {e}")
    return sorted(all_regions)


def resolve_regions():
    """Resolve target regions from environment variable."""
    target_regions = os.environ.get("TARGET_REGIONS", "").strip()
    current_region = os.environ.get(
        "AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
    )

    if not target_regions:
        return [current_region]

    if target_regions.lower() == "all":
        regions = get_available_regions()
        if not regions:
            logger.warning("No regions discovered, falling back to current region")
            return [current_region]
        return regions

    return [r.strip() for r in target_regions.split(",") if r.strip()]


def lambda_handler(event, context):
    """Main Lambda handler. Returns region list for Map state."""
    logger.info(f"Event: {event}")

    regions = resolve_regions()
    logger.info(f"Resolved {len(regions)} target regions: {regions}")

    return {"regions": regions}
