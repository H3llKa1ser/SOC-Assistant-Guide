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

        $J

### Analyze the MFT file and output the results in .csv format

Tool: https://github.com/EricZimmerman/MFTECmd

    .\MFTECmd.exe -f ..\Evidence\$MFT --csv ..\Evidence --csvf ..\Evidence\MFT_record.csv

