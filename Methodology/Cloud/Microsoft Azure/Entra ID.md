# Entra ID

## Sign-in logs

#### Sign-in log example format

    {
      "id": "014adaeb-c9db-4119-8a9b-a9f68dd4b700",
      "createdDateTime": "2026-02-11T17:15:10Z",
      "userDisplayName": "John Doe",
      "userPrincipalName": "john.doe@contoso.onmicrosoft.com", // The user address
      "userId": "a1b2c3d4-e5f6-7890-a1b2-c3d4e5f67890",
      "appId": "4765445b-32c6-49b0-83e6-1d93765276ca",
      "appDisplayName": "OfficeHome", // Which application the user logged in to. In this case, the main web portal (office.com)
      "ipAddress": "203.0.113.45", // The IP address used by the user.
      "clientAppUsed": "Browser",
      "correlationId": "dc8fb3db-403c-43e4-b759-21aa137a143a",
      "conditionalAccessStatus": "success",
      "isInteractive": true,
      [...]
      "resourceDisplayName": "OfficeHome",
      "resourceId": "4765445b-32c6-49b0-83e6-1d93765276ca",
      "status": {
        "errorCode": 0, // The result of the authentication. Code 0 means successful.
        "failureReason": "Other.",
        "additionalDetails": null
     [...]
      "location": {  // Details about the location from the IP address used by the user.
        "city": "New York",
        "state": "New York",
        "countryOrRegion": "US",
        "geoCoordinates": {
          "altitude": null,
          "latitude": 40.7128,
          "longitude": -74.0060
        }
      },
      "appliedConditionalAccessPolicies": [ // Information about which access control policy was applied during the authentication process.
        {
          "id": "c63499f4-64b6-4943-bfc3-52fbb641ef10",
          "displayName": "Require MFA",
          "enforcedGrantControls": ["Block"],
          "enforcedSessionControls": [],
          "result": "notApplied"
        }
      ]
    }


### 1) List all sign-in events

    index=scenario sourcetype="azure:aad:signin"

### 2) List all failed sign-ins

    index="scenario" sourcetype="azure:aad:signin" "status.errorCode"!=0
    | stats count as event_count values(ipAddress) as ip_addresses
     values(appDisplayName) as applications values(status.errorCode) as errorCodes  by userPrincipalName
    | sort - event_count
    | table applications, userPrincipalName, ip_addresses, errorCodes, event_count

#### 2.1) Filter out Conditional Access

    index="task-2" sourcetype="azure:aad:signin" "status.errorCode"!=0 conditionalAccessStatus!=success
    | table _time, userPrincipalName, appDisplayName, ipAddress, location.countryOrRegion, status.errorCode, status.failureReason
    | sort - _time

#### 2.2) List failed sign-in attempts by IP address

    index="task-2" sourcetype="azure:aad:signin" "status.errorCode"!=0 conditionalAccessStatus!=success
    | stats dc(userPrincipalName) as targeted_accounts, count as failures by ipAddress
    | sort - failures

### 3) List successful sign-ins from an IP address

    index=scenario sourcetype="azure:aad:signin" "status.errorCode"=0 ipAddress="<ADD-IP-HERE>"
    | stats values(ipAddress) as ip_addresses values(appDisplayName) as applications  by userPrincipalName
    | table applications, userPrincipalName, ip_addresses

OR 

    index="task-2" sourcetype="azure:aad:signin" "status.errorCode"=0
    | where ipAddress="<SUSPICIOUS_IP>"
    | stats count by userPrincipalName, status.errorCode
    | sort status.errorCode

#### 3.1) List successful logins by user

    index="task-2" sourcetype="azure:aad:signin" "status.errorCode"=0
    | where userPrincipalName="<TARGET_USER>"
    | stats count by userPrincipalName, status.errorCode, ipAddress
    | sort status.errorCode

### 4) List blocked sign-ins by Conditional Access Policies (CAP)

    index="task-3" sourcetype="azure:aad:signin" conditionalAccessStatus=failure
    | spath output=policies path=appliedConditionalAccessPolicies{}
    | mvexpand policies
    | spath input=policies output=policy_result path=result
    | spath input=policies output=policy_name path=displayName
    | where policy_result="failure"
    | stats values(policy_name) as FailedPolicies by _time, appDisplayName, userDisplayName, ipAddress, conditionalAccessStatus
    | eval FailedPolicies=mvjoin(FailedPolicies, ", ")
    | table _time, appDisplayName, userDisplayName, ipAddress, conditionalAccessStatus, FailedPolicies
    | sort - _time



## Entra ID Authentication error codes

| Code   | Description                                           |
|--------|-------------------------------------------------------|
| `50126`| Invalid username or password                          |
| `50053`| Account locked due to too many failed attempts        |
| `50074`| MFA required but not provided                         |
| `50055`| Password expired                                      |
| `50140`| User selects "No" for the Keep me signed in" option during login |

## Identity Protection

Link: https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks

### 1) List high-risk sign-ins

    index="task-3" sourcetype="azure:aad:signin"
    | where riskLevelDuringSignIn="high"
    | table _time, userPrincipalName, appDisplayName, ipAddress, location.countryOrRegion, riskLevelDuringSignIn, riskLevelAggregated
    | sort - _time

### 2) List all risk detection logs

    index="task-3" sourcetype="azure:aad:identity_protection:riskdetection"

### 3) List all risk detecions related to anonymized IPs

    index="task-3" sourcetype="azure:aad:identity_protection:riskdetection"
    | where riskEventType="anonymizedIPAddress"
    | table _time, userPrincipalName, activity, ipAddress, location.countryOrRegion, riskLevel, riskEventType
    | sort - _time

### 4) List all risky user alerts

    index="task-3" sourcetype="azure:aad:identity_protection:risky_user"
    | table _time, userPrincipalName, riskLevel, riskState, riskDetail 
    | sort - _time

## Multi Factor Authentication (MFA)

### 1) List MFA failures by user

    index="task-4" sourcetype="azure:aad:signin" (status.errorCode=50074 OR status.errorCode=50076 OR status.errorCode=500121)
    | stats count as mfa_failures values(status.errorCode) as errorCodes values(status.failureReason) as failureReasons by userPrincipalName, ipAddress
    | sort - mfa_failures

### 2) List ImpossibleTravel alerts in Identity Protection logs

    index="task-4" sourcetype="azure:aad:identity_protection:riskdetection"
    | where riskEventType="impossibleTravel"
    | table _time, userPrincipalName, activity, ipAddress, location.countryOrRegion, riskLevel, riskEventType
    | sort - _time

### 3) List successful sign-in activity for a user

    index="task-4" sourcetype="azure:aad:signin" status.errorCode=0
    | table _time, userPrincipalName, ipAddress, location.countryOrRegion, conditionalAccessStatus
    | sort - _time

## Audit Logs

### 1) List all Audit logs

    index=scenario sourcetype="azure:aad:audit"

### 2) List changes targeting a specific user

    index=scenario sourcetype="azure:aad:audit" targetResources{}.userPrincipalName="<ADD-USER-EMAIL>" 
    | eval initiator=coalesce('initiatedBy.user.userPrincipalName', 'initiatedBy.app.displayName')
    | sort - _time
    | table _time, initiator, activityDisplayName, result, targetResources{}.userPrincipalName

### 3) List changes performed by a user

    index=scenario sourcetype="azure:aad:audit" initiatedBy.user.userPrincipalName="<ADD-USER-EMAIL>" 
    | sort - _time
    | table _time, initiatedBy.user.userPrincipalName, activityDisplayName, result, targetResources{}.userPrincipalName

