# Lateral Movement

## On-Premises

### 1) Pass-the-Hash / Pass-the-Ticket

    index=wineventlog sourcetype="WinEventLog:Security" EventCode IN (4624, 4625)
    | eval logon_type_desc = case(
        Logon_Type=3, "Network",
        Logon_Type=9, "NewCredentials",
        Logon_Type=10, "RemoteInteractive")
    | where Logon_Type IN (3, 9, 10)
    | stats count dc(dest) as unique_hosts values(dest) as targets by src_ip, user, Logon_Type
    | where unique_hosts > 5
    | sort -unique_hosts
    | table _time, user, src_ip, Logon_Type, unique_hosts, targets

### 2) Administrative access via SMB shares

    index=wineventlog sourcetype="WinEventLog:Security" EventCode=5140
    | search Share_Name IN ("\\\\*\\C$", "\\\\*\\ADMIN$", "\\\\*\\IPC$")
    | stats count dc(Share_Name) as unique_shares values(Share_Name) as shares 
            dc(dest) as systems_accessed by src_ip, user
    | where systems_accessed > 3
    | sort -systems_accessed
    | table _time, user, src_ip, systems_accessed, unique_shares, shares

### 3) PsExec / Remote Service creation

    index=wineventlog sourcetype="WinEventLog:System" EventCode=7045
    | search Service_Name IN ("PSEXESVC", "WMIC*", "RemCom*", "CSExec*")
      OR Service_File_Name="*\\ADMIN$\\*"
      OR Service_File_Name="*\\C$\\*"
    | stats count by dest, Service_Name, Service_File_Name, user
    | table _time, dest, user, Service_Name, Service_File_Name, count

### 4) WMI

    index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688
    | search (Process_Name="*wmiprvse.exe" AND Parent_Process_Name="*svchost.exe")
      OR (Process_Name="*wmic.exe" AND Process_Command_Line="*/node:*")
    | stats count dc(dest) as unique_targets by src_ip, user, Process_Command_Line
    | where unique_targets > 2
    | table _time, user, src_ip, unique_targets, Process_Command_Line

### 5) RDP 

    index=wineventlog sourcetype="WinEventLog:Security" EventCode IN (4624, 4778)
    | where Logon_Type=10
    | streamstats current=f window=1 latest(dest) as next_hop latest(_time) as next_time by user
    | eval time_diff = next_time - _time
    | where time_diff < 300 AND time_diff > 0
    | stats count as rdp_hops dc(dest) as unique_systems values(dest) as systems by user, src_ip
    | where rdp_hops > 3
    | table user, src_ip, rdp_hops, unique_systems, systems

### 6) Golden and Silver tickets

    index=wineventlog sourcetype="WinEventLog:Security" EventCode IN (4768, 4769, 4770)
    | eval ticket_type = case(
        EventCode=4768, "TGT_Request",
        EventCode=4769, "TGS_Request",
        EventCode=4770, "TGT_Renewal")
    | stats count dc(Service_Name) as unique_services dc(dest) as unique_hosts 
            values(Service_Name) as services by user, src_ip, ticket_type
    | where (ticket_type="TGS_Request" AND unique_services > 20) 
         OR (ticket_type="TGT_Request" AND unique_hosts > 10)
    | table _time, user, src_ip, ticket_type, unique_services, unique_hosts, services

### 7) Internal Network Scan

    index=network sourcetype=firewall action=allowed
    | where cidrmatch("10.0.0.0/8", dest_ip) OR cidrmatch("172.16.0.0/12", dest_ip) OR cidrmatch("192.168.0.0/16", dest_ip)
    | stats dc(dest_ip) as unique_destinations dc(dest_port) as unique_ports 
            values(dest_port) as ports by src_ip
    | where unique_destinations > 50 OR unique_ports > 20
    | sort -unique_destinations
    | table src_ip, unique_destinations, unique_ports, ports

### 8) PowerShell Remoting

    index=wineventlog sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode IN (4103, 4104)
    | search ScriptBlockText="*Enter-PSSession*" OR ScriptBlockText="*Invoke-Command*" 
            OR ScriptBlockText="*New-PSSession*" OR ScriptBlockText="*-ComputerName*"
    | rex field=ScriptBlockText "-ComputerName\s+(?<target_hosts>[^\s\|]+)"
    | stats count dc(target_hosts) as unique_targets values(target_hosts) as targets by src_ip, user
    | where unique_targets > 2
    | table _time, user, src_ip, unique_targets, targets

### 9) DCOM

    index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688
    | search Parent_Process_Name="*mmc.exe" OR Parent_Process_Name="*excel.exe" 
            OR Parent_Process_Name="*outlook.exe"
    | where Process_Name IN ("*cmd.exe", "*powershell.exe", "*wscript.exe", "*cscript.exe")
    | stats count by dest, Parent_Process_Name, Process_Name, Process_Command_Line, user
    | table _time, dest, user, Parent_Process_Name, Process_Name, Process_Command_Line

### 10) SSH

    index=linux sourcetype=linux_secure ("Accepted password" OR "Accepted publickey")
    | rex field=_raw "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
    | stats count dc(host) as unique_hosts values(host) as hosts earliest(_time) as first latest(_time) as last by user, src_ip
    | eval duration = last - first
    | where unique_hosts > 3 AND duration < 3600
    | table user, src_ip, unique_hosts, hosts, duration

## Cloud

### 1) AWS Cross-Account role assumption chains

Detects role chaining across AWS accounts.

    index=aws sourcetype=aws:cloudtrail eventName="AssumeRole"
    | stats count dc(recipientAccountId) as unique_accounts 
            values(recipientAccountId) as accounts 
            values(requestParameters.roleArn) as roles by userIdentity.arn, sourceIPAddress
    | where unique_accounts > 2
    | sort -unique_accounts
    | table _time, userIdentity.arn, sourceIPAddress, unique_accounts, accounts, roles

### 2) AWS EC2 Instance Connect / SSM Lateral Movement

Detects movement between EC2 instances via SSM.

    index=aws sourcetype=aws:cloudtrail eventName IN ("SendCommand", "StartSession", "SendSSHPublicKey")
    | stats count dc(requestParameters.instanceId) as unique_instances 
            values(requestParameters.instanceId) as instances by userIdentity.arn, sourceIPAddress
    | where unique_instances > 3
    | table _time, userIdentity.arn, sourceIPAddress, unique_instances, instances

### 3) Azure Cross-Subscription Access

Detects lateral movement across Azure subscriptions.

    index=azure sourcetype=azure:aad:audit OR sourcetype=azure:activity
    | stats dc(subscriptionId) as unique_subs 
            values(subscriptionId) as subscriptions 
            dc(resourceId) as resources by identity.claims.upn, callerIpAddress
    | where unique_subs > 1
    | table _time, identity.claims.upn, callerIpAddress, unique_subs, subscriptions, resources

### 4) Azure VM Run Command Abuse

Detects Azure Run Command for lateral movement.

    index=azure sourcetype=azure:activity operationName.localizedValue="Run Command on Virtual Machine"
    | stats count dc(properties.entity) as unique_vms 
            values(properties.entity) as target_vms by caller, callerIpAddress
    | where unique_vms > 2
    | table _time, caller, callerIpAddress, unique_vms, target_vms

### 5) GCP Cross-Project Service Account Impersonation

Detects service account hopping in GCP.

    index=gcp sourcetype=google:gcp:pubsub:message 
    | spath input=data.protoPayload
    | search methodName="*GenerateAccessToken*" OR methodName="*SignBlob*"
    | stats count dc(resource.labels.project_id) as unique_projects 
            values(resource.labels.project_id) as projects by authenticationInfo.principalEmail, callerIp
    | where unique_projects > 1
    | table _time, authenticationInfo.principalEmail, callerIp, unique_projects, projects

### 6) Cloud IAM privilege escalation chain

Detects privilege escalation as part of lateral movement.

    index=aws sourcetype=aws:cloudtrail 
    | search eventName IN ("CreateAccessKey", "AttachUserPolicy", "AttachRolePolicy", 
                            "CreateLoginProfile", "UpdateLoginProfile", "PutUserPolicy", "PutRolePolicy")
    | transaction userIdentity.arn maxspan=1h
    | where eventcount > 3
    | stats count values(eventName) as actions dc(eventName) as unique_actions by userIdentity.arn, sourceIPAddress
    | where unique_actions > 2
    | table _time, userIdentity.arn, sourceIPAddress, unique_actions, actions

## Kubernetes

### 1) Kubernetes Pod-to-Pod

Detects unusual pod access patterns in K8s.

    index=kubernetes sourcetype=kube:apiserver
    | search verb IN ("create", "exec", "attach") resource="pods"
    | stats count dc(objectRef.name) as unique_pods 
            values(objectRef.name) as pods 
            dc(objectRef.namespace) as unique_namespaces by user.username, sourceIPs{}
    | where unique_pods > 5 OR unique_namespaces > 2
    | table _time, user.username, sourceIPs{}, unique_pods, unique_namespaces, pods

### 2) Container escape to Host

Detects potential container breakout attempts.

    index=kubernetes OR index=container
    | search (process_name="nsenter" OR process_name="docker" OR cmdline="*--privileged*" 
             OR cmdline="*/proc/*/root*" OR cmdline="*mount*cgroup*")
    | stats count by host, container_id, process_name, cmdline, user
    | table _time, host, container_id, user, process_name, cmdline

## Hybrid / Cross-Tenant

### 1) On-Premises to Cloud

Detects movement from on-prem to cloud resources.

    (index=wineventlog sourcetype="WinEventLog:Security" EventCode=4624) 
    OR (index=aws sourcetype=aws:cloudtrail) 
    OR (index=azure sourcetype=azure:aad:signin)
    | eval environment = case(
        sourcetype="WinEventLog:Security", "on-prem",
        sourcetype="aws:cloudtrail", "aws",
        sourcetype="azure:aad:signin", "azure")
    | stats dc(environment) as env_count values(environment) as environments 
            dc(dest) as unique_targets by user, src_ip
    | where env_count > 1
    | table _time, user, src_ip, env_count, environments, unique_targets
