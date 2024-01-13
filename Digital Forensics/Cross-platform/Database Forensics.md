## DATABASE FORENSICS

#### 1) Primary data file

#### 2) Secondary data file

#### 3) Transaction log data file

### PRIMARY DATA FILE

#### 1) Starting point of the database

#### 2) Points to other files in database

#### 3) .mdf extension

#### 4) Stores all data in database objects

### SECONDARY DATA FILE

#### 1) Optional

#### 2) Database can contain multiple

#### 3) .ndf extension

### TRANSACTION LOG FILE

#### 1) Holds entire log information associated with database

#### 2) .ldf extension

### COLLECTION OF DATABASE AND LOG FILES

#### 1) C:\Program Files\Microsoft SQL Server\MSSQLII.MSSQLSERVER\MSSQL\DATA

### RESTORATION OF EVIDENCE

#### 1) Database and log files: \MSSQL\DATA

#### 2) Trace files: \MSSQL\LOG

#### 3) SQL Server error logs: MSSQL\LOG\ERRORLOG

### COMMANDS

#### 1) sqlcmd = System procedures

#### 2) mysqldump = backup of database

#### 3) mysqldbexport = exports metadata

#### 4) myisamlog = version info, recobery operations

#### 5) myisamchk = status of MyISAM Table
