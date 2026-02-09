# GUID Partition Table (GPT)

## Tools:

1) HxD Hex Analyzer

2) FTK Imager forensics tool (or any other image forensics tool)

## GPT Analysis

Important Bytes

| Bytes Position | Bytes Length | Field Name                       | Value                                               |
|----------------|--------------|----------------------------------|-----------------------------------------------------|
| 0–7            | 8            | Signature                        | `45 46 49 20 50 41 52 54`                           |
| 8–11           | 4            | Revision                         | `00 00 01 00`                                       |
| 12–15          | 4            | Header Size                      | `5C 00 00 00`                                       |
| 16–19          | 4            | CRC32 of Header                  | `71 89 13 1C`                                       |
| 20–23          | 4            | Reserved                         | `00 00 00 00`                                       |
| 24–31          | 8            | Current LBA                      | `01 00 00 00 00 00 00 00`                           |
| 32–39          | 8            | Backup LBA                       | `AF 32 CF 1D 00 00 00 00`                           |
| 40–47          | 8            | First Usable LBA                 | `22 00 00 00 00 00 00 00`                           |
| 48–55          | 8            | Last Usable LBA                  | `8E 32 CF 1D 00 00 00 00`                           |
| 56–71          | 16           | Disk GUID                        | `61 1D F1 B0 D6 43 BE 37 4E B1 E6 38 66 EC B1 73 89`|
| 72–79          | 8            | Partition Entry Array LBA        | `02 00 00 00 00 00 00 00`                           |
| 80–83          | 4            | Number of Partition Entries      | `80 00 00 00`                                       |
| 84–87          | 4            | Size of Each Partition Entry     | `80 00 00 00`                                       |
| 88–91          | 4            | CRC32 of Partition Array         | `41 0D C0 22`                                       |
