# Console Logins

## SIEM Used:

Splunk

### 1) Filter CloudTrail events

    eventName=ConsoleLogin

### 2) Search if a user has logged in successfully without MFA

    "additionalEventData.MFAUsed"=No status=success

## Monitoring Tips

1) Monitor logins on the root user. Your IT team should use root for emergencies, not the daily routine

2) Monitor console logins from service users. They are expected to use roles or access keys instead

3) Monitor successful logins from VPN, Tor, cloud hostings, or otherwise suspicious IP addresses

4) A focused, aggressive brute force might indicate that adversaries target your company
