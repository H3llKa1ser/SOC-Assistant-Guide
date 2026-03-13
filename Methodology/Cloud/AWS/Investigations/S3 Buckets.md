# S3 Buckets

## Early Detection

Check for indicators like:

    Disable "S3 Public Access Block" feature (PutBucketPublicAccessBlock)
    Apply the correct bucket ACL (PutBucketAcl) or bucket policy (PutBucketPolicy)

## Late Detection

Splunk query

    index=aws (HeadObject OR GetObject) requestParameters.bucketName=BUCKET_NAME userIdentity.accountId=anonymous
    | fillnull value=Success errorMessage
    | timechart span=30s count by errorMessage
    
## GuardDuty

Findings generated:

    Policy:S3/BucketBlockPublicAccessDisabled: The "S3 Public Access Block" feature was disabled
    Policy:S3/BucketAnonymousAccessGranted: The bucket was made public via ACL or bucket policy
    Impact:S3/MaliciousIPCaller: A known-malicious IP address accessed an exposed S3 bucket
