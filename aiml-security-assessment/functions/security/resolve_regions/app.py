"""
Resolve Target Regions Lambda Function

Resolves the list of AWS regions to scan based on the TARGET_REGIONS
environment variable. Returns a list for the Step Functions Map state
to iterate over.
"""

import os
import logging
import re

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def resolve_regions():
    """Resolve target regions from environment variable."""
    target_regions = os.environ.get("TARGET_REGIONS", "").strip()
    current_region = os.environ.get(
        "AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
    )

    if not target_regions:
        return [current_region]

    if target_regions.lower() == "all":
        raise ValueError(
            "TARGET_REGIONS no longer accepts 'all'; leave it empty to scan the "
            "deployment region or provide an explicit region list"
        )

    return [r.strip() for r in re.split(r"[,\s]+", target_regions) if r.strip()]


def lambda_handler(event, context):
    """Main Lambda handler. Returns region list for Map state."""
    logger.info(f"Event: {event}")

    regions = resolve_regions()
    logger.info(f"Resolved {len(regions)} target regions: {regions}")

    return {"regions": regions}
