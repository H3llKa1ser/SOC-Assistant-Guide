# Processes

### 1) List current running processes

    Get-WmiObject -Class Win32_Process | ForEach-Object {$owner = $_.GetOwner(); [PSCustomObject]@{Name=$_.Name; PID=$_.ProcessId; P_PID=$_.ParentProcessId; User="$($owner.User)"; CommandLine=if ($_.CommandLine.Length -le 60) { $_.CommandLine } else { $_.CommandLine.Substring(0, 60) + "..." }; Path=$_.Path}} | ft -AutoSize | tee process-summary.txt

# Directories

### 1) List details of temp directories

    Get-ChildItem -Path "C:\Users" -Force | Where-Object { $_.PSIsContainer } | ForEach-Object { Get-ChildItem -Path "$($_.FullName)\AppData\Local\Temp" -Recurse -Force -ErrorAction SilentlyContinue | Select-Object @{Name='User';Expression={$_.FullName.Split('\')[2]}}, FullName, Name, Extension } | ft -AutoSize | tee temp-folders.txt

### 2) More details of a specific temp folder

    Get-ChildItem -Path "C:\Users\Administrator\AppData\SpcTmp\" -Recurse -Force | ft FullName, Name, Extension

# Disk Volumes

### 1) List disk volumes

    Get-CimInstance -ClassName Win32_Volume | ft -AutoSize DriveLetter, Label, FileSystem, Capacity, FreeSpace | tee disc-volumes.txt
