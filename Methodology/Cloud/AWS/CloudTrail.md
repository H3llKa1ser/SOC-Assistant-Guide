# AWS CloudTrail

### 1) View CloudTrail logs

    CloudTrail -> Event History

Splunk

    index=aws sourcetype=aws-cloudtrail

### 2) Forward logs to an S3 Bucket, then configure Splunk (or any other SIEM) to pull logs from that S3 bucket.

Splunk documentation: https://splunk.github.io/splunk-add-on-for-amazon-web-services/CloudTrail/


### 3) Log Format example

    {
      "eventID": "b12da7f9-36a9-4ac1-9cb6-7d3b4874d2a7",
      "eventTime": "2025-12-10T17:54:44Z",
      "eventSource": "signin.amazonaws.com",
      "eventName": "ConsoleLogin",
      "awsRegion": "us-east-1",
      "sourceIPAddress": "72.44.21.87",
      "userAgent": "Mozilla/5.0 [...]",
      "requestParameters": null,
      "responseElements": {
        "ConsoleLogin": "Success"
      },
      "readOnly": false,
      "recipientAccountId": "398985017225",
       "userIdentity": {
        "type": "IAMUser",
        "arn": "arn:aws:iam::398985017225:user/john.doe",
        "accountId": "398985017225",
        "userName": "john.doe"
      },
    }

## Event Types

### 1) Login Events

    index=aws eventName=ConsoleLogin

### 2) Control Plane Threats

Write events

    readOnly=false

Unusual changes in user privileges, IAM access keys and AWS logins.

Insecure changes to EC2 security groups, like exposing sensitive services.

Exposed S3 buckets they shouldn't be
