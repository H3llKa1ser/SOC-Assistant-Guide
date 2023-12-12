# EVENT VIEWER

### Events are stored in the log files on a proprietary binary format with a .evt or .evtx extension.

### The log files with the .evtx extension typically reside in "C:\Windows\System32\wenevt\Logs"

## 3 Ways of accessing event logs in a windows system:

#### 1) Event viewer (GUI) or eventvwr.exe (CLI)

#### 2) wevtutil.exe (CLI Tool)

#### 3) Get-WinEvent (Powershell Cmdlet)

# EVENT TYPES

### 1) Error

### 2) Warning 

### 3) Information

### 4) Success Audit

### 5) Failure Audit

# WINDOWS LOGS

### 1) Application

### 2) Security

### 3) System

### 4) CustomLog

# GET-WINEVENT

## Usage example:

#### Get-WinEvent -FilterHashTable @{LogName='Application' ProviderName='WLMS'}
