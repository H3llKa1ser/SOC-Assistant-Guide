# File Allocation Table (FAT)

## Tools:

1) HxD

2) Autopsy

## FAT32 Analysis

Resource: https://www.easeus.com/resource/fat32-disk-structure.html

### Long File Name

| Offset | Size | Description                                                                                                             |
|--------|------|-------------------------------------------------------------------------------------------------------------------------|
| 0x00   | 1    | Sequence number, last entry flag, deleted entry flag                                                                    |
| 0x01   | 10   | First 5 characters of the filename (UTF‑16)                                                                             |
| 0x0B   | 1    | Attributes (`0x0F` for LFN entry). No functional use at this time                                                       |
| 0x0C   | 1    | Type (reserved, set to `0x00`)                                                                                            |
| 0x0D   | 1    | Checksum of the short name                                                                                               |
| 0x0E   | 12   | Next 6 characters of the filename (UTF‑16)                                                                              |
| 0x1A   | 2    | Reserved for FAT first cluster (legacy), used for compatibility with current disk utilities                             |
| 0x1C   | 4    | Last 2 characters of the filename (UTF‑16)                                                                              |

### Short File Name

| Offset | Size | Field Name                  | Description |
|--------|------|-----------------------------|-------------|
| 0x00   | 11   | File Name                    | Short file name in 8.3 format (8 bytes for name, 3 bytes for extension) |
| 0x0B   | 1    | Attributes                   | File attributes: READ_ONLY (0x01), HIDDEN (0x02), SYSTEM (0x04), VOLUME_ID (0x08), DIRECTORY (0x10), ARCHIVE (0x20) |
| 0x0C   | 1    | Reserved                     | Reserved, usually set to `0x00` |
| 0x0D   | 1    | Creation Time (Tenths)       | Tenths of a second when the file was created |
| 0x0E   | 2    | Creation Time                | Time the file was created (hours, minutes, seconds):<br>Bits 0–4: 2‑second count (0–29) <br>Bits 5–10: Minutes (0–59) <br>Bits 11–15: Hours (0–23) |
| 0x10   | 2    | Creation Date                | Date the file was created:<br>Bits 0–4: Day (1–31) <br>Bits 5–8: Month (1–12) <br>Bits 9–15: Years since 1980 (0–127) |
| 0x12   | 2    | Last Access Date             | Date the file was last accessed |
| 0x14   | 2    | High Word of First Cluster   | High 16 bits of the file’s starting cluster number (FAT32 only) |
| 0x16   | 2    | Last Modification Time       | Time the file was last modified |
| 0x18   | 2    | Last Modification Date       | Date the file was last modified |
| 0x1A   | 2    | Low Word of First Cluster    | Low 16 bits of the file’s starting cluster number |
| 0x1C   | 4    | File Size                    | File size in bytes (max 4 GiB − 1) |
