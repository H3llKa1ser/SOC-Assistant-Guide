# GPO

### 1) Check GPO modifications

    index=* EventCode=5136 Class="groupPolicyContainer"
    | table _time, Subject_Account_Name, DN, LDAP_Display_Name, Value
    | sort - _time

