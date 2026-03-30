# SharePoint Online

## SharePoint Events

### 1) Sign-In Logs for SharePoint

    index=m365 sourcetype="azure:aad:signin"
    | table _time userPrincipalName appDisplayName ipAddress deviceDetail.browser status.errorCode

### 2) SharePoint Sharing

    index=m365 Workload=SharePoint Operation IN(AddedToSecureLink, AnonymousLinkCreated)
    | eval TargetId=lower(TargetUserOrGroupName)
    | table _time Operation UserId TargetId ObjectId

AND/OR

    index=m365 Workload=SharePoint Operation IN(SecureLinkUsed, AnonymousLinkUsed)
    | eval TargetId=lower(TargetUserOrGroupName)
    | table _time Operation UserId TargetId ObjectId

## Data Exfiltration

### 1) Detect file downloads via GUI

    index=m365 Workload=SharePoint Operation=FileDownloaded
    | stats count values(SourceFileName) by SiteUrl, SourceRelativeUrl, UserId
    | where count >= 5

### 2) Detect file downloads via App

Rclone example

    index=* rclone Operation=FileDownloaded
    | table _time UserId Operation ApplicationDisplayName ApplicationId UserAgent

## SharePoint Abuse

### 1) Identify and disable patient zero (The user account that uploaded the file)

    index=m365 Operation IN(FileUploaded, FileCreated) ObjectId=*BADFILE*
    | table _time UserId Operation ObjectId

### 2) Identify and notify all users with whom the malicious file was shared

    index=m365 Operation IN(AddedToSecureLink, SharingSet) ObjectId=*BADFILE*
    | table _time UserId TargetUserOrGroupName ObjectId

### 3) Immediately contact those who have already opened the file

    index=m365 Operation IN(*LinkUsed, FileAccessed) ObjectId=*BADFILE*
    | stats values(UserId)
