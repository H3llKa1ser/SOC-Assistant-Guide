### Location: /etc/passwd | column -t -s ( Makes it more readable )

### access_log = Keeps track of web server connections

### It contains 7 column separated fields:

#### 1) Username

#### 2) Password information

#### 3)User id (UID)

#### 4) Group id (GID)

#### 5) Description

#### 6) Home directory information

#### 7) Default shell that executes upon user logon

### User-created user accounts have UIDs 1000 or above (Similar to Windows)

### If password into field is "X", it means that the password is stored as a SHA-512 bcrypt hash in the /etc/shadow file.
