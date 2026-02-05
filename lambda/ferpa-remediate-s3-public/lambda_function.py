import os
import boto3

s3 = boto3.client("s3")

def lambda_handler(event, context):
    bucket = os.environ.get("TARGET_BUCKET")
    if not bucket:
        return {"ok": False, "error": "Missing TARGET_BUCKET env var"}

    # Turn on Block Public Access
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True
        }
    )

    return {"ok": True, "action": "enabled_block_public_access", "bucket": bucket}
