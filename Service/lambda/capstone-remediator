import json
import os
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone

s3 = boto3.client("s3")
iam = boto3.client("iam")
ec2 = boto3.client("ec2")

SAFE_POLICY_ARN = os.environ.get("SAFE_POLICY_ARN", "")
BAD_POLICY_ARN = os.environ.get("BAD_POLICY_ARN", "")
TEST_USER_NAME = os.environ.get("TEST_USER_NAME", "capstone-test-user")
RESULTS_BUCKET = os.environ.get("RESULTS_BUCKET", "")

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def write_result(record):
    if not RESULTS_BUCKET:
        print(json.dumps(record))
        return
    key = f"results/{record['test_type']}/{record['timestamp'].replace(':', '-')}.json"
    s3.put_object(
        Bucket=RESULTS_BUCKET,
        Key=key,
        Body=json.dumps(record, indent=2).encode("utf-8"),
        ContentType="application/json"
    )

def remediate_s3(bucket_name):
    desired = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True
    }

    needs_update = True
    try:
        current = s3.get_public_access_block(Bucket=bucket_name)["PublicAccessBlockConfiguration"]
        needs_update = any(current.get(k) != v for k, v in desired.items())
    except ClientError as e:
        if e.response["Error"]["Code"] not in ["NoSuchPublicAccessBlockConfiguration", "NoSuchBucket"]:
            raise

    if needs_update:
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration=desired
        )

    try:
        s3.get_bucket_policy(Bucket=bucket_name)
        s3.delete_bucket_policy(Bucket=bucket_name)
    except ClientError as e:
        if e.response["Error"]["Code"] not in ["NoSuchBucketPolicy", "NoSuchBucket"]:
            raise

def remediate_iam():
    attached = iam.list_attached_user_policies(UserName=TEST_USER_NAME).get("AttachedPolicies", [])
    for pol in attached:
        if pol["PolicyArn"] == BAD_POLICY_ARN:
            iam.detach_user_policy(UserName=TEST_USER_NAME, PolicyArn=BAD_POLICY_ARN)

    attached_after = iam.list_attached_user_policies(UserName=TEST_USER_NAME).get("AttachedPolicies", [])
    safe_attached = any(pol["PolicyArn"] == SAFE_POLICY_ARN for pol in attached_after)

    if SAFE_POLICY_ARN and not safe_attached:
        iam.attach_user_policy(UserName=TEST_USER_NAME, PolicyArn=SAFE_POLICY_ARN)

def remediate_sg(group_id, cidr_ip, ip_protocol, from_port, to_port):
    permission = {
        "IpProtocol": ip_protocol,
        "IpRanges": [{"CidrIp": cidr_ip}]
    }
    if from_port is not None:
        permission["FromPort"] = int(from_port)
    if to_port is not None:
        permission["ToPort"] = int(to_port)

    ec2.revoke_security_group_ingress(GroupId=group_id, IpPermissions=[permission])

def lambda_handler(event, context):
    print("Received event:", json.dumps(event))
    ts = now_iso()

    detail = event.get("detail", {})
    principal_arn = detail.get("userIdentity", {}).get("arn", "")

    if "capstone-lambda-remediator-role" in principal_arn:
        record = {
            "timestamp": now_iso(),
            "event_source": detail.get("eventSource", ""),
            "event_name": detail.get("eventName", ""),
            "status": "ignored",
            "test_type": "self-generated",
            "reason": "Lambda-generated event ignored to prevent recursion"
        }
        print("Result:", json.dumps(record))
        try:
            write_result(record)
        except Exception as write_err:
            print("Failed to write result:", str(write_err))
        return {"statusCode": 200, "body": json.dumps(record)}

    event_name = detail.get("eventName", "")
    event_source = detail.get("eventSource", "")

    record = {
        "timestamp": ts,
        "event_source": event_source,
        "event_name": event_name,
        "status": "started",
        "test_type": "unknown",
        "details": detail
    }

    try:
        if event_source == "s3.amazonaws.com" and event_name in ["PutBucketPublicAccessBlock", "PutBucketPolicy", "DeleteBucketPolicy"]:
            bucket_name = detail.get("requestParameters", {}).get("bucketName")
            record["test_type"] = "s3"
            record["target"] = bucket_name
            if bucket_name:
                remediate_s3(bucket_name)
                record["status"] = "success"
            else:
                record["status"] = "failed"
                record["error"] = "No bucketName found"

        elif event_source == "iam.amazonaws.com" and event_name in ["AttachUserPolicy", "PutUserPolicy"]:
            record["test_type"] = "iam"
            remediate_iam()
            record["status"] = "success"

        elif event_source == "ec2.amazonaws.com" and event_name == "AuthorizeSecurityGroupIngress":
            record["test_type"] = "security-group"
            params = detail.get("requestParameters", {})
            group_id = params.get("groupId")
            ip_permissions = params.get("ipPermissions", {}).get("items", [])

            if group_id and ip_permissions:
                first = ip_permissions[0]
                ip_protocol = first.get("ipProtocol", "-1")
                from_port = first.get("fromPort")
                to_port = first.get("toPort")
                ip_ranges = first.get("ipRanges", {}).get("items", [])
                cidr_ip = ip_ranges[0].get("cidrIp") if ip_ranges else None

                if cidr_ip == "0.0.0.0/0":
                    remediate_sg(group_id, cidr_ip, ip_protocol, from_port, to_port)
                    record["target"] = group_id
                    record["status"] = "success"
                else:
                    record["status"] = "ignored"
                    record["reason"] = "CIDR was not 0.0.0.0/0"
            else:
                record["status"] = "failed"
                record["error"] = "Missing security group details"

        else:
            record["status"] = "ignored"
            record["reason"] = "Unhandled event"

    except Exception as e:
        record["status"] = "failed"
        record["error"] = str(e)
        
    finally:
        print("Result:", json.dumps(record))
        try:
            write_result(record)
        except Exception as write_err:
            print("Failed to write result:", str(write_err))

    return {"statusCode": 200, "body": json.dumps(record)}
