# Phishing

## Double-Extension Attachment

Important event IDs: 1, 11

### 1) Launched a web browser (ID 1)

Example

    Image: C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
    ParentImage: C:\Windows\Explorer.EXE

### 2) A file appears in Downloads. Can be either an .exe or an archive like .zip (ID 11)

    Image: C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
    TargetFilename: C:\Users\User\Downloads\invoice.zip*

### 3) The user unarchives the file to some folder (ID 11) (Optional)

    Image: C:\Windows\Explorer.EXE (or C:\Program Files\7-Zip\7zG.exe)
    TargetFilename: C:\Users\User\Downloads\invoice.pdf.exe

### 4) The user double-clicks the unarchived file (ID 1)

    Image: C:\Users\User\Downloads\invoice.pdf.exe
    ParentImage: C:\Windows\Explorer.EXE

## LNK Attachments

Check in the fields for the actual content of the .lnk file: 

"CommandLine"
"CurrentDirectory"
"ParentImage"
"ParentCommandLine"

