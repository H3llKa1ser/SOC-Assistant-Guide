# Access Keys

## Differences between Console login sessions:

### 1) Console session

1) Accessing a resource takes multiple calls, seeing multiple commands in succession instead.

2) STS Token starts with ASIA

3) Web Browser userAgent values.

### 2) Access Keys

1) Access Keys shows what it explicitly asked for in a single command.

2) STS Token starts with AKIA.

3) Programmatic userAgent values.

4) No sessionContext section.

## Queries

SIEM: Splunk

### 1) Filter only for access key logins

    index=aws iserIdentity.accessKeyId=AKIA*

Alternative query

    index=aws NOT userIdentity.sessionContext.attributes.creationDate=*
