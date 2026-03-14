# AWS Lambda Functions

Splunk Query to begin hunting:

    index=aws sourcetype=lambda.amazonaws.com readOnly=false

### 1) Lambda Events to hunt:

| Event | Use Case |
|------|---------|
| `AddPermission*` | This event changes the function's trust policy. Be especially cautious with events where `principal=*`, as it allows public, anonymous access to the function. |
| `PublishLayerVersion*`, `UpdateFunctionCode*` | These events can indicate a change to the function code or its dependencies. Such changes can embed backdoors or make the function perform malicious actions in AWS. |
| `CreateFunction*`, `UpdateFunctionConfiguration*` | In these events, look at the execution role of the function. If the role is overly permissive, such as `AdministratorAccess`, raise an alarm with your IT team. |

