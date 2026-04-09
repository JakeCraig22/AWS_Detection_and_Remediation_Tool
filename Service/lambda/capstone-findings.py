import json
import os
import boto3
from datetime import datetime, timezone

s3 = boto3.client("s3")

RESULTS_BUCKET = os.environ.get("RESULTS_BUCKET", "")

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def detect_source(event):
    source = event.get("source", "")
    detail_type = event.get("detail-type", "")

    if source == "aws.guardduty":
        return "guardduty"
    elif source == "aws.macie":
        return "macie"
    elif source == "aws.securityhub":
        return "securityhub"
    else:
        return "unknown"

def get_event_id(event):
    return event.get("id", "no-event-id")

def write_result(prefix, record, event_id):
    if not RESULTS_BUCKET:
        print(json.dumps(record))
        return

    safe_ts = record["timestamp"].replace(":", "-")
    key = f"results/findings/{prefix}/{safe_ts}_{event_id}.json"

    s3.put_object(
        Bucket=RESULTS_BUCKET,
        Key=key,
        Body=json.dumps(record, indent=2).encode("utf-8"),
        ContentType="application/json"
    )

def lambda_handler(event, context):
    print("Received event:", json.dumps(event))

    source_type = detect_source(event)
    event_id = get_event_id(event)

    record = {
        "timestamp": now_iso(),
        "recorded_source": source_type,
        "event_id": event_id,
        "original_source": event.get("source", ""),
        "detail_type": event.get("detail-type", ""),
        "status": "recorded",
        "event": event
    }

    try:
        write_result(source_type, record, event_id)
    except Exception as e:
        record["status"] = "failed"
        record["error"] = str(e)
        print("Failed to write result:", json.dumps(record))
        return {
            "statusCode": 500,
            "body": json.dumps(record)
        }

    print("Stored record:", json.dumps(record))
    return {
        "statusCode": 200,
        "body": json.dumps({
            "status": "success",
            "recorded_source": source_type,
            "event_id": event_id
        })
    }
