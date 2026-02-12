# New Technology File System (NTFS)

## Tools

1) FTKImager

2) Autopsy

3) EZ Tools

## NTFS Analysis

#### Important files:

1) Master File Table (MFT)

        $MFT

2) Boot Record

        $Boot

3) Journaling

        $J (Inside $UsnJrnl)
        $Max (Inside $UsnJrnl)
        $LogFile
        $UsnJrnl ($Extend directory location)

### Extracting the files for analysis

On FTK Imager, right-click on the file, then click export file. Choose destination folder.

Done!

### 1) MFT File analysis

Tool: https://github.com/EricZimmerman/MFTECmd

    .\MFTECmd.exe -f ..\Evidence\$MFT --csv ..\Evidence --csvf ..\Evidence\MFT_record.csv

### 2) NTFS Journaling File analysis

Tool: https://github.com/EricZimmerman/MFTECmd

    .\MFTECmd.exe -f ..\Evidence\$J --csv ..\Evidence --csvf USNJrnl.csv

USN Journal Update Reason Codes

| Opcode                          | Description                                                                 |
|---------------------------------|-----------------------------------------------------------------------------|
| USN_REASON_DATA_OVERWRITE       | File or directory data was overwritten.                                     |
| USN_REASON_DATA_EXTEND          | File or directory data was extended (e.g., file size increased).            |
| USN_REASON_DATA_TRUNCATION      | File or directory data was truncated (e.g., file size decreased).           |
| USN_REASON_NAMED_DATA_OVERWRITE | The alternate data stream was overwritten.                                  |
| USN_REASON_NAMED_DATA_EXTEND    | An alternate data stream was extended.                                      |
| USN_REASON_FILE_CREATE          | A new file or directory was created.                                        |
| USN_REASON_FILE_DELETE          | A file or directory was deleted.                                            |
| USN_REASON_RENAME_OLD_NAME      | The file or directory was renamed (old name recorded).                      |
| USN_REASON_CLOSE                | The file or directory handle was closed after changes.                      |
