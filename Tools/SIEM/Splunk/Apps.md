# APPS

#### Search app: It is where you will enter your Splunk queries to search through the data ingested by Splunk.

### TIPS & TRICKS

#### You can change various settings (properties) for any installed app by clicking 'edit properties' in the Managed Apps page which is located by clicking the cog in the Apps Panel.

#### If you want to land into the search app upon login automatically, you can do so by editing the "user-prefs.conf" file.

### Location: 

### Windows: C:\Program Files\Splunk\etc\apps\user-prefs\default\user-prefs.conf

### Linux: /opt/splunk/etc/apps/user-prefs/default/user.prefs.conf

### Before:

####   [general_default]

####    default_namespace = $default

####   appOrder = search

### After:

####   [general_default]

####    default_namespace = search

####   appOrder = search

## PRO TIP: Best practice is for any modifications to Splunk confs, you should create a directory and place custom conf settings there. When splunk is upgraded the defaults are overwritten.

## In order for the user preferences to take effecr, the splunkd service has to be restarted with these commands:

### net stop splunkd

### net start splunkd

#### We can install more Splunk Apps to the Splunk instance bu clicking "+ Find more Apps" in the apps panel or "Splunk Apps" in the Explore Splunk Panel.

#### To install apps, we can install directly within Splunk or download it from Splunkbase and manually upload it to add it to our Splunk instance.

### Note: We must have an account on Splunk.com to downlaod and install Splunk apps.
