# YARA

Useful tool link:

1) YARA Forge

https://github.com/YARAHQ/yara-forge

2) Official Documentation

https://yara.readthedocs.io/en/stable/writingrules.html

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
