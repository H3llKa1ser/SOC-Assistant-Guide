# KAPE (Kroll Artifact Parser and Extractor)

## Collect Registry hives

### 1) KAPE GUI

    .\gkape.exe

### 2) Collect data

    Check Use Target Options -> Target Source, then choose the drive of your choice (Live system, choose C) -> Target Destination to save your collected data -> Search for "Registry Hives" -> Uncheck Flush

### 3) Btach Mode data collection

Create a _kape.cli file that contains the command you wish to be executed. Omit the .\kape.exe in the file.

Then, you can delegate it to other teams like sysadmins to run .\kape.exe in the same directory as _kape.cli without appending the flags.

