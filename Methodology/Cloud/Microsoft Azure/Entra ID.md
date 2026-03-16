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

### 1) List all sign-in events

    index=scenario sourcetype="azure:aad:signin"

### 2) List all failed sign-ins

    index="scenario" sourcetype="azure:aad:signin" "status.errorCode"!=0
    | stats count as event_count values(ipAddress) as ip_addresses
     values(appDisplayName) as applications values(status.errorCode) as errorCodes  by userPrincipalName
    | sort - event_count
    | table applications, userPrincipalName, ip_addresses, errorCodes, event_count

### 3) List successful sign-ins from an IP address

    index=scenario sourcetype="azure:aad:signin" "status.errorCode"=0 ipAddress="<ADD-IP-HERE>"
    | stats values(ipAddress) as ip_addresses values(appDisplayName) as applications  by userPrincipalName
    | table applications, userPrincipalName, ip_addresses

## Entra ID Authentication error codes

| Code   | Description                                           |
|--------|-------------------------------------------------------|
| `50126`| Invalid username or password                          |
| `50053`| Account locked due to too many failed attempts        |
| `50074`| MFA required but not provided                         |
| `50055`| Password expired                                      |

