# Extracting IPs and giving the OR operator for queries

### 1) Download exported file with IPs

### 2) Copy IPs into a text file

### 3) Extract IPs

    grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' IPs.txt | paste -sd '|' - | sed 's/|/ OR /g' > extracted_IP_Addresses.txt

### 4) Open the extracted file, and paste to Splunk to query

    cat extracted_IP_Addresses.txt
