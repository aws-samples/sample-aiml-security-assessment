import boto3
import os
import logging
from botocore.config import Config

# Configure boto3 with retries
boto3_config = Config(retries=dict(max_attempts=10, mode="adaptive"))

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    """
    Clean up old assessment reports from the per-account SAM bucket.

    NOTE: This Lambda only cleans the temporary per-account assessment bucket
    (AIMLAssessmentBucket in the SAM template) at the start of each run.
    The central reporting bucket (AssessmentBucket in the deployment template)
    where final results are synced by CodeBuild is NOT affected — historical
    results are preserved there. Each run writes files with unique execution IDs,
    so results accumulate in the central bucket over time.
    """
    logger.info("Starting S3 bucket cleanup")

    try:
        bucket_name = os.environ.get("AIML_ASSESSMENT_BUCKET_NAME")
        if not bucket_name:
            raise ValueError(
                "AIML_ASSESSMENT_BUCKET_NAME environment variable is not set"
            )

        s3_client = boto3.client("s3", config=boto3_config)

        # Use paginator to handle buckets with more than 1000 objects
        paginator = s3_client.get_paginator("list_objects_v2")
        objects_to_delete = []

        for page in paginator.paginate(Bucket=bucket_name):
            for obj in page.get("Contents", []):
                if obj["Key"].endswith((".csv", ".html", ".json")):
                    objects_to_delete.append({"Key": obj["Key"]})

        if objects_to_delete:
            # delete_objects supports max 1000 keys per call
            for i in range(0, len(objects_to_delete), 1000):
                batch = objects_to_delete[i : i + 1000]
                s3_client.delete_objects(Bucket=bucket_name, Delete={"Objects": batch})
            logger.info(
                f"Deleted {len(objects_to_delete)} old files from bucket {bucket_name}"
            )
        else:
            logger.info("No old files to delete")

        return {
            "statusCode": 200,
            "body": {
                "message": "Bucket cleanup completed successfully",
                "bucket": bucket_name,
            },
        }

    except Exception as e:
        logger.error(f"Error during bucket cleanup: {str(e)}", exc_info=True)
        return {
            "statusCode": 500,
            "body": f"Error during bucket cleanup: {str(e)}",
        }
