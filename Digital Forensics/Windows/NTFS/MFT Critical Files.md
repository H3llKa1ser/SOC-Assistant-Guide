# CRITICAL FILES

### $MFT = 

#### This file contains a directory of all files present on the volume.

#### The $MFT is the first record in the volume. The Volume Boot Record (VBR) points to the cluster where it is located.

#### $MFT stores information about the clusters where all other objects present on the volume are located.

### $LOGFILE = 

#### It stores the transactional logging of the file system. It helps maintanin the integrity of the file system in the event of a crash.

### $UsnJrnl = Update Sequence Number Journal.

#### It is present in the $Extend record.

#### It contains information about all files that were changed in the file system and the reason for the change

## Tool to use: MFT Explorer (EZTools)
