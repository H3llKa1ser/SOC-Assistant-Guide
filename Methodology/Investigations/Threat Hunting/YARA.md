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
           $ = "STRING/INTEGER/VALUE/WHATEVER" (You can add as many as you have to)
           $ = "STRING/INTEGER/VALUE/WHATEVER"
    
        condition:
            all of them
    }
