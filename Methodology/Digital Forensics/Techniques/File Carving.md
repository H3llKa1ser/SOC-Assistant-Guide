# File Carving

Uses metadata like file headers and footers to recover files even if the file system or the storage media has been corrupted and/or damaged.

## File Type Information

Resource: https://filesig.search.org/

## Tools:

1) Hex Editors

2) Binwalk

3) Scalpel

4) Foremost

5) PhotoRec

6) EnCase

## Manual Analysis

Steps

### 1) Use a Hex Editor to open an image file 

    HxD
    Okteta
    etc.

### 2) Search for signatures within the image like .png or .jpeg files for example using their Headers in Hex format.

Use the file type information for the correct file signature in Hex format.

### 3) If you detect any type of file, check the starting offset, and note it. If it is for example, the 10th byte in the sequence in the offset 0001000000, use 0001000010 instead.

### 4) Use the trailers (or footers) in Hex format of the corresponding file format to see in where it ends, then record the ending offset like the above example for the starter offset.

### 5) Subtract the offset values with the ending offset as the minuend to get the file size in bytes.

    Ending Offset - Starting Offset = File Size in Bytes

### 6) Extract the file

    dd if=image.img of=extracted.png bs=1 skip=STARTING_OFFSET count=FILE_SIZE_BYTES

### 7) Check the metadata of the extracted file

    exiftool extracted.png
