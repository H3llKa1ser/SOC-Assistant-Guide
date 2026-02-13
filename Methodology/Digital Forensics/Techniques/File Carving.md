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

## Manual Carving

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

    Ending Offset - Starting Offset = File Size in Bytes (Remove the zeroes from the offsets and use only the first 3 numbers for the byte size)

### 6) Extract the file

    dd if=image.img of=extracted.png bs=1 skip=STARTING_OFFSET count=FILE_SIZE_BYTES

You can also extract it manually by pressing on a Hex Editor

    Ctrl+E

Then Choose the corresponding start offset and ending offset to select all the bytes of the target file.

Copy the hexdump to a tool like Cyberchef to recover the file.

### 7) Check the metadata of the extracted file

    exiftool extracted.png

## Recovering files from Slack Space

### 1) Run binwalk to check for file types and their offsets inside the file system

    binwalk image.img

### 2) Open a Hex Editor and navigate to the offset of your interest provided by Binwalk (Optional)

### 3) Extract files using Binwalk

    binwalk -e image.img

## Automation

### 1) Foremost

Recover files using a custom configuration file for the tool

    foremost -i image.img -o DIR_OUTPUT -c /etc/custom_foremost.conf

If you know what files are you looking for, you can use this command instead for faster results

    foremost -t pdf,png,jpg -i image.img -o DIR_OUTPUT -c /etc/custom_foremost.conf

### 2) Scalpel

    scalpel image.img -o DIR_OUTPUT -c /etc/scalpel/scalpel.conf
