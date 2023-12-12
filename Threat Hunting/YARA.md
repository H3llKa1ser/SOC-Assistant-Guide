# YET ANOTHER RIDICULOUS ACRONYM (YARA)

### YARA can identify information based on both binary and textual patterns, such as hexadecimal and strings contained within a file.

## YARA RULES

### Can be used to determine if a file is malicious or not.

### Example: Search bitcoin wallets in strings for ransomware. Or search IPs for a Command and Control Server.

### File extension: .yar

### It's essentially the basics of programming to effectively create YARA rules.

### KEYWORDS:

### all, and, any, ascii, at, base64, base64wide, condition, contains, endswith, entrypoint, false, filesize, for, fullword, global, import, icontains, iendswith, iequals, in, include, int16, int16be, int32, int32be, int8, int8be, istartswith, matches, meta, nocase, none, not, of, or, private, rule, startswith, strings, them, true, uint16, uint16be, uint32, uint32be, uint8, uint8be, wide, xor, defined, desc, weight


## YARA MODULES

### 1) Cuckoo Sandbox

### 2) Python PE

## YARA TOOLS

### 1) THOR APT Scanner

### 2) FENRIR

### 3) YAYA

### 4) LOKI

#### In Loki, detection is based on 4 methods:

#### 1) File name IOC check

#### 2) Yara rule check

#### 3) Hash check

#### 4) C2 Back connect check
