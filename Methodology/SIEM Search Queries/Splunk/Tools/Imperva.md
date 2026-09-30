# Imperva 

### 1) Check if there are any events indexed to Splunk

    index=imperva sourcetype=imperva_sourcetype earliest=-7d@d latest=@d
    | stats count

### 2) Check which fields are actually used

    index=imperva sourcetype=imperva_sourcetype earliest=-7d@d latest=@d
    | fieldsummary
    | table field count distinct_count
    | sort - count

### 3) Event Sampling

    index=imperva sourcetype=imperva_sourcetype earliest=-7d@d latest=@d
    | head 1
    | table _raw
