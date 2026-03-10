# YARA

Useful tool link:

1) YARA Forge

https://github.com/YARAHQ/yara-forge

2) Official Documentation

https://yara.readthedocs.io/en/stable/writingrules.html

3) Python script

https://github.com/VirusTotal/yara-python

## Example YARA rule structure

    rule RULE_NAME
    {
        meta
            author = "AUTHOR"
            disclaimer = "DISCLAIMER FOR RULE USAGE"
            description = "DESCRIBE WHAT THE RULE DOES"
    
    
        strings:
           $ = "CHECK DOCUMENTATION FOR ALL COMBINATIONS" (You can add as many as you have to)
           $ = "CHECK DOCUMENTATION FOR ALL COMBINATIONS"
    
        condition:
            all of them
    }

## Modifiers

### 1) nocase

Define a string as case-insensitive

### 2) wide

Match strings that are encoded like this:

    t00r00y00h00a00c00k00m00e00

### 3) Hexadecimal Strings

Example

    $1 = { E2 10 FF BE }

##### Important values:

Wildcard

    $1 = ?

NOT operator (exclude from search)

    $1 = ~FF

Jump (Matches any value between 2 hex)

    $1 = [1-4]

Between (Boolean operator OR)

    $1 = (00|FF) 

### 4) xor

Hunt for all variations with a 1-byte XOR key

    $1 = "whatever" xor

### 5) Encoding

Base64

    $1 = "whatever" base64

### 6) Regular expressions (regex)

    $1 = /whatever\{[a-zA-Z]{3}\}/

## Conditions

### 1) Operators

| Boolean Operators | Relational Operators | Arithmetic Operators | Bitwise Operators | Keywords         |
|-------------------|----------------------|----------------------|-------------------|------------------|
| `and`             | `>=`                 | `+`                  | `&`               | `1 of them`      |
| `or`              | `<=`                 | `-`                  | `|`               | `any of them`    |
| `not`             | `<`                  | `*`                  | `<<`              | `none of them`   |
|                   | `>`                  | `/`                  | `>>`              | `contains`       |
|                   | `==`                 | `%`                  | `~`               | `icontains`      |
|                   | `!=`                 |                      |                   | `startswith`     |
|                   | `^`                  |                      |                   | `istartswith`    |
|                   |                      |                      |                   | `endswith`       |
|                   |                      |                      |                   | `iendswith`      |
|                   |                      |                      |                   | `iequals`        |
|                   |                      |                      |                   | `matches`        |
|                   |                      |                      |                   | `not defined`    |
|                   |                      |                      |                   | `filesize`       |

### 2) Statements

all of them = Matches when all defined strings are present

any of them = Matches when at least one of the defined strings is present

1 of $(*) = Identical to "any of them" condition

"$1 or $2" = Matches when values within $1 or $2 is present

$1 and $2 = Matches when $1 and $2 are present

$1 and ($2 or $3) = Matches when values $1 and $2 or $3 combinations are present

none of them = Matches only when none of the defined strings are present

filesize < 700KB = Matches all files smaller than 700 Kiobytes (Used only on files)

($1 or $2) and filesize < 300KB = Matches for values $1 or $2 in files smaller than 300KB
