# NEW TECHNOLOGY FILE SYSTEM (NTFS)

## FEATURES

#### Journaling = Kepes a log of changes to the metadata in the volume.

#### This feature helps the system recover from a crash or data movement due to defragmentation.

#### This log is stored in $LOGFILE in the volume's root directory.

#### Access controls = Define the owner of a file/directory and permissions for each user.

#### Volume shadow copy = A user can restore previous file versions for recovery or system restore. (Modern cryptomalware (ransomware) may delete the shadow copies on a victim's file system to prevent them from recovering their data)

#### Alternate Data Streams (ADS) = A file is a stream of data organized in a file system.

#### ADS allows files to have multiple streams of data stored in a single file. (Malware may hide their code in ADS)

#### Master File Table (MFT) = It is a structured database that tracks the objects stored in a volume. NTFS data is organized in the MFT.
