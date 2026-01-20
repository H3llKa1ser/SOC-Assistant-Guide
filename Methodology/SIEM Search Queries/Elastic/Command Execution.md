# Command Execution

### 1) PowerShell usage

    @timestamp >= "TIMESTAMP" and event.module:powershell and event.code:4104

Relevant fields:

    powershell.file.script_block_text
    process.command_line
    process.name
    process.parent.name

### 2) Cmd execution as Administrator

    @timestamp >= "TIMESTAMP" and process.parent.name:cmd.exe and user.name:Administrator

Relevant fields:

    process.command_line
    process.name
    process.parent.name
