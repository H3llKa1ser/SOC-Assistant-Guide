# Users

### 1) List local users

    Get-LocalUser | ft Name, SIDtee l-users.txt

### 2) More details for local users

    Get-CimInstance -Class Win32_UserAccount -Filter "LocalAccount=True" | Format-Table  Name, PasswordRequired, PasswordExpires, PasswordChangeable | Tee-Object "user-details.txt"

### 3) List user groups

    Get-LocalGroup | ForEach-Object { $members = Get-LocalGroupMember -Group $_.Name; if ($members) { Write-Output "`nGroup: $($_.Name)"; $members | ForEach-Object { Write-Output "`tMember: $($_.Name)" } } } | tee gp-members.txt

# Sessions

### 1) List current sessions

Tool: PsLoggedOn (Sysinternals)

    .\PsLoggedon64.exe | tee sessions.txt

