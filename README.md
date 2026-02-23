# AWS_Detection_and_Remediation_Tool# Automated Vulnerability Detection and Remediation Tool Using AWS

## Overview
Capstone Project: An automated and event-driven remediation workflow built in AWS, that detects and corrects security misconfigurations in real time using Free Tier.

The system focuses on protecting FERPA-sensitive student records (Mock) and following FERPA guidelines/ 

## Architecture

Services Used:
- AWS Lambda
- Amazon EventBridge
- AWS CloudTrail
- Amazon S3
- Amazon CloudWatch Logs

Event Flow:
1. A public access configuration change occurs on the S3 bucket.
2. CloudTrail logs the API call.
3. EventBridge detects the matching event pattern.
4. Lambda is invoked.
5. Lambda re-enables Block Public Access.
6. CloudWatch logs remediation details.

## Bucket Under Protection

Bucket Name:
ferpa-student-records-demo-398351901202

## Testing Methodology

1. Apply a public bucket policy.
2. Confirm bucket becomes publicly accessible.
3. Trigger CloudTrail event.
4. Observe EventBridge invocation.
5. Confirm Lambda re-enables Block Public Access.
6. Validate logs in CloudWatch.

## Metrics Being Collected

- Detection time
- Remediation time
- Success rate
- Repeatability

## Current Scope

- S3 Public Access Block enforcement (Working)
- CloudTrail multi-region trail enabled
- EventBridge rule configured
- Lambda remediation active

## Author
Jacob Craig  
University of Southern Maine  
ITT 460 Capstone
