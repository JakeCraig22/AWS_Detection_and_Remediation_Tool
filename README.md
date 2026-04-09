.
#Project overview

This is my capstone for the University of Southern Maine's Cyber Security program. The goal was to design an event-driven AWS security automation system, designed to detect and remediate vulnerabilities within the free tier AWS environment.

The core remediation pipeline uses:
- CloudTrail
- EventBridge
- Lambda
- S3

 CloudTrail captures management events, EventBridge matches relevant security events, Lambda applies remediation logic, and the results are logged to CloudWatch and stored in an S3 results bucket.

Categories tested
- Publicly accessible S3 bucket misconfiguration
- Permissive IAM policy attachment misconfiguration
- Open security group inbound rule misconfiguration

## Project Goals

The project was designed to answer the following questions:

- Can automated remediation reduce mean remediation time compared to manual response?
- Can automated remediation improve consistency and reliability across repeated trials?
- Can AWS-native security services be integrated into a broader detection and response architecture?
- Can part of the architecture be represented reproducibly through Infrastructure as Code?

### Findings intake path
A second path was built for AWS security findings:

**GuardDuty / Macie -> EventBridge -> Lambda findings recorder -> CloudWatch / S3 results bucket**

- **GuardDuty** provides threat findings
- **Macie** provides S3 and sensitive-data findings
- **EventBridge** routes those finding events
- **Lambda findings recorder** stores the raw finding events
- **S3 results bucket** stores finding JSON files for evidence

### Infrastructure as Code
A CloudFormation template was created to model the findings intake architecture:

- GuardDuty EventBridge rule
- Macie EventBridge rule
- Lambda invoke permissions
- connection to the findings recorder Lambda

## How to Reproduce

### 1. Review the repository structure
- `AWS-Data-Results/` contains result files and findings summaries
- `Service/` contains exported AWS configs and Lambda files
- `iac/` contains the CloudFormation template and IaC notes

### 2. Recreate the core remediation path
- create or review the S3 buckets
- create or review the remediation Lambda
- create or review the EventBridge rules for S3, IAM, and security group events
- configure Lambda environment variables
- test each misconfiguration one at a time
- confirm remediation through CloudTrail, CloudWatch, and S3 result files

### 3. Recreate the findings intake path
- create or review the findings recorder Lambda
- create or review the EventBridge rules for GuardDuty and Macie
- enable GuardDuty and Macie in `us-east-1`
- generate sample findings
- confirm finding events are written to the results bucket

### 4. Reproduce the IaC portion
Validate the CloudFormation template with:

```bash
aws cloudformation validate-template \
  --template-body file://iac/capstone-findings-stack.yaml \
  --region us-east-1
