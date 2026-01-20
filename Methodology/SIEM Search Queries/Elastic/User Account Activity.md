# User Account Activity

### 1) Search for user account creation/deletion activity

    @timestamp >= "TIMESTAMP" and winlog.channel:Security and winlog.task:User Account Management

Relevant fields:

    winlog.event_id
    winlog.task
    message

### 2) Check for Administrator logon activity

    @timestamp >= "TIMESTAMP" and winlog.event_id:4624 and host.name:winserv2019.some.corp and winlog.event_data.TargetUserName:Administrator

Relevant fields:

    winlog.event_id
    host.name
    winlog.event_data.TargetUserName
    winlog.logon.type
    winlog.event_data.IpAddress

### 3) Check for suspicious process creation of the Administrator account

    @timestamp >= "TIMESTAMP" and winlog.event_id:1 and user.name:Administrator

Relevant fields:

    user.name
    process.parent.name
    process.command_line

