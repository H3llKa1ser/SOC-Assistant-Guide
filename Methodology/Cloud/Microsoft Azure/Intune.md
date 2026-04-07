# Intune

Cloud console link: https://intune.microsoft.com/

## Remote Wipe

### 1) Detect Intune logins from unmanaged devices

    index=intune sourcetype=azure:aad:signin appDisplayName=*Intune* deviceDetail.displayName=""
    | rename deviceDetail.* as dvc.*
    | table _time appDisplayName ipAddress dvc.isManaged dvc.isCompliant dvc.displayName user

### 2) Detect remote wiper (too late do actually do anything though)

    index=intune sourcetype="o365:graph:intune" wipe
    | eval deviceid=mvindex('resources{}.modifiedProperties{}.newValue', 0)
    | table _time activityType actor.userPrincipalName deviceid

## Applications and Scripts

### 1) Detect platform scripts (change sourctype according to your environment)

    index=intune sourcetype="o365:graph:intune" activityType=*DeviceManagementScript*
    | eval action=mvindex(split(activityType, " "), 0)
    | eval script='resources{}.resourceId'
    | eval target=mvindex('resources{}.modifiedProperties{}.newValue', 0)
    | eval target=if(action="assignDeviceManagementScript", target, "N/A")
    | table _time actor.userPrincipalName action script target

### 2) Detect application events (change sourcetype according to your environment)

    index=intune sourcetype="o365:graph:intune" activityType=*MobileApp*
