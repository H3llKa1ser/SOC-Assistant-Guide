# AWS Lambda Functions

Splunk Query to begin hunting:

    index=aws sourcetype=lambda.amazonaws.com readOnly=false

### 1) Lambda Events to hunt:

| Event | Use Case |
|------|---------|
| `AddPermission*` | This event changes the function's trust policy. Be especially cautious with events where `principal=*`, as it allows public, anonymous access to the function. |
| `PublishLayerVersion*`, `UpdateFunctionCode*` | These events can indicate a change to the function code or its dependencies. Such changes can embed backdoors or make the function perform malicious actions in AWS. |
| `CreateFunction*`, `UpdateFunctionConfiguration*` | In these events, look at the execution role of the function. If the role is overly permissive, such as `AdministratorAccess`, raise an alarm with your IT team. |

### 2) Lambda Persistence

1) Create a stealthy totally-legit-dont-touch Lambda function (CreateFunction*)

2) Add AdministratorAccess permissions to its role (UpdateFunctionConfiguration*)

3) Edit its code to create a new access key upon Lambda execution (UpdateFunctionCode*)

4) Make the Lambda public and allow access via Function URL (AddPermissions*)

5) Open the Function URL in a browser any time they need a new access key

### 3) Lambda Privilege Escalation

Policies attached to the execution role to look out for:

    EC2FullAccess
    SSMFullAccess

