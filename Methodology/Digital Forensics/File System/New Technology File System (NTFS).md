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
