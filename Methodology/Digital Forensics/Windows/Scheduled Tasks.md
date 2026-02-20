# Scheduled Tasks

Tools:

1) Task Scheduler

Location:

    C:\Windows\System32\Tasks

#### Important Event IDs:

1) Scheduled task creation

- 4698

2) Scheduled task update

- 4702

### 1) List Scheduled Tasks

    $tasks = Get-CimInstance -Namespace "Root/Microsoft/Windows/TaskScheduler" -ClassName MSFT_ScheduledTask; if ($tasks.Count -eq 0) { Write-Host "No scheduled tasks found."; exit } else { Write-Host "$($tasks.Count) scheduled tasks found." }; $results = @(); foreach ($task in $tasks) { foreach ($action in $task.Actions) { if ($action.PSObject.TypeNames[0] -eq 'Microsoft.Management.Infrastructure.CimInstance#Root/Microsoft/Windows/TaskScheduler/MSFT_TaskExecAction') { $results += [PSCustomObject]@{ TaskPath = $task.TaskPath.Substring(0, [Math]::Min(50, $task.TaskPath.Length)); TaskName = $task.TaskName.Substring(0, [Math]::Min(50, $task.TaskName.Length)); State = $task.State; Author = $task.Principal.UserId; Execute = $action.Execute } } } }; if ($results.Count -eq 0) { Write-Host "No tasks with 'MSFT_TaskExecAction' actions found." } else { $results | Format-Table -AutoSize | tee scheduled-tasks.txt }

### 2) View scheduled task events

Go to:

    Run program (CTRL+R) -> eventvwr.msc -> Windows Logs -> Security -> Filter Current Log -> Type the event IDs 4698,4702 -> OK

### 3) List all running scheduled tasks

    Get-ScheduledTask | Where-Object {$_.State —ne "Disabled"}

OR

    schtasks.exe /query /fo CSV | findstr /V Disabled

OR

    Get-ScheduledTask | Where-Object {$_.Date —ne $null —and $_.State —ne "Disabled"} | Sort-Object Date | select Date,TaskName,Author,State,TaskPath | ft

One-Liner

    Get-ScheduledTask | Where-Object {$_.Date —ne $null —and $_.State —ne "Disabled" —and $_.Actions.Execute —ne $null} | Sort-Object Date

