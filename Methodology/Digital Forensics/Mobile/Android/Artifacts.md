# Artifacts

Tools:

1) FTK Imager

2) ALEAPP (Automated parsing) https://github.com/abrignoni/ALEAPP

### 1) SMS/MMS and Call logs

Locations:

#### SMS/MMS

    /data/data/com.android.providers.telephony/databases/mmssms.db

Access the database:

    sqlite3 mmssms.db

Check tables:

    .tables

Retrieve content of SMS table

    select * from SMS;

Change mode of output

    .mode MODE
    .mode ? (Check various options)

#### Call logs

    /data/data/com.android.providers.contacts/databases/calllog.db

Access the database:

    sqlite3 calllog.db

Check tables:

    .table

Retrieve content of Calls

    select * from calls;

### 2) Contacts and Address Book

Location:

    /data/data/com.android.providers.contacts/databases/contacts2.db

Access the database:

    sqlite3 ctntacts2.db

Check tables:

    .tables

Dump content:

    select * from data;

### 3) Browser History

Location:

    /data/data/com.android.chrome/app_chrome/Default/History

Access the database:

    sqlite3 History

Check tables:

    .tables

Dump content:

    select * from urls;

### 4) Location Data

Location:

    /data/data/com.google.android.gms/databases/

#### Important Files

    location.db, networklocations.db, or com.google.android.location

### 5) Photos, Videos and Metadata

Locations: 

    /sdcard/DCIM/
    /sdcard/Pictures/
    /sdcard/WhatsApp/Media/

### 6) Instant Messaging Apps

Locations:

    /data/data/com.whatsapp/databases/msgstore.db
    /sdcard/WhatsApp/Media/ (for images, voice notes, etc.)

### 7) Application Data

Locations:

    /data/data/[app.package.name]/

### 8) User Accounts and Google Services

Locations:

    /data/system/users/0/accounts.db
    /data/data/com.google.android.gms/databases

### 9) Installed Applications

Location:

    /data/system/packages.xml

### 10) Bluetooth information

Location:

    /data/misc/bluedroid

This is a config file and can be opened with a text editor like Notepad and use the find feature to search for information.

### 11) Wi-Fi information

Location:

    /data/misc/wifi

This is an XML file.
