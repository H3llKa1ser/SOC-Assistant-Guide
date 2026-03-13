# AWS EC2

## Early Detection

A new security group has been created

| Step | Action                                                                                                          | Query Example                                                                                                  | Notes |
|------|-----------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------|-------|
| 1    | Review the group creation event and note its name and ID (check `requestParameters` and `responseElements`)     | `index=* eventName=CreateSecurityGroup`                                                                       |       |
| 2    | Review the security group for any insecure inbound rules (rules are in `requestParameters`)                     | `index=* eventName=AuthorizeSecurityGroupIngress sg-xxxxxx`                                                   |       |
| 3    | Check if any new or old VMs start using this security group (instance ID in `responseElements`)                  | `index=* eventName IN(RunInstances, ModifyInstanceAttribute) sg-xxxxxx`                                       |       |
| 4    | If rules are insecure or inappropriate for the linked VMs, reach out to Alice and ask her to harden the group    | N/A                                                                                                           |       |

One of the security group rules has been modified

| Step | Action                                                                                                          | Query Example                                                                                                       | Notes |
|------|-----------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------|-------|
| 1    | Review the changes and note the security group ID (rules are in `requestParameters`)                            | `index=* eventName IN(*SecurityGroupIngress, ModifySecurityGroupRules)`                                             |       |
| 2    | Find the group creation and note its author and description (search up to 1 year back)                          | `index=* earliest=-1y eventName=CreateSecurityGroup sg-xxxxxx`                                                      |       |
| 3    | Identify the EC2 instances that use the modified security group (note: services like RDS also use security groups) | `index=* eventName IN(RunInstances, ModifyInstanceAttribute) sg-xxxxxx`                                             |       |
| 4    | If changes are insecure or inappropriate for linked VMs, reach out to Bob and ask him to harden the security group | N/A                                                                                                                  |       |

## Late Detection

1) Alert on insecure security group modifications with CloudTrail, as described in this task

2) Enable GuardDuty, which may generate the Recon:EC2/PortProbeUnprotectedPort finding

3) Collect auth.log from the VMs and detect SSH brute force from the endpoint point of view

4) As a last resort, detect the dropped miner with installed EDR, network, or endpoint logs
