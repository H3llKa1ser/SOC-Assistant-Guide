# Kerberos Analysis

### 1) Narrow down to Kerberos

    kerberos

### 2) Search for a user account

    kerberos.CNameString contains "keyword" 

Exclude hostnames

    kerberos.CNameString and !(kerberos.CNameString contains "$" )

### 3) Protocol version

    kerberos.pvno == 5

### 4) Service and domain name for the generated ticket

    kerberos.SNameString == "krbtgt"

### 5) Domain name for the generated ticket

    kerberos.realm contains ".org" 
