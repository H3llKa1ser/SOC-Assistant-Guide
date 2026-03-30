# Exchange Online

## Log Sources

### 1) Exchange Online Sign-In Logs

    index=* sourcetype="azure:aad:signin" appDisplayName="One Outlook Web"
    | table _time userPrincipalName appDisplayName ipAddress location.city status.errorCode
    | sort - _time

### 2) M365 Unified Audit Logs

    index=* sourcetype="o365:management:activity" Workload=Exchange
    | table _time UserId Operation Workload

### 3) Message Trace Logs

    index=* sourcetype="o365:reporting:messagetrace"
    | table Received SenderAddress RecipientAddress Subject Status FromIP

## Mailbox Rules

### 1) Inbox rule creation

    index=* Workload=Exchange Operation=New-InboxRule 
    | table _time UserId Name DeleteMessage ForwardTo SubjectContainsWords

### 2) Mailbox-level email forwarding

    index=* Workload=Exchange Operation=Set-Mailbox 
    | table _time UserId ForwardingSmtpAddress DeliverToMailboxAndForward

## Phishing Detection

### 1) Investigate Mail Items Accessed

    index=* Workload=Exchange Operation=MailItemsAccessed 
    | table _time UserId ClientIPAddress OperationCount

### 2) Investigate Sent Emails

    index=* Workload=Exchange Operation=Send 
    | table _time UserId Item.Subject ClientIP SaveToSentItems

### 3) Investigate Message Trace Logs

    index=* sourcetype="o365:reporting:messagetrace" 
    | table Received SenderAddress RecipientAddress Subject Status FromIP

  
