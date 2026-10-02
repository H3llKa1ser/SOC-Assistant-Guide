# Indices

### 1) Search for a specific index (Cloudflare for example)

    | tstats count latest(_time) AS last_event WHERE index=* BY index sourcetype
    | search index="*cloudflare*" OR index="*cf*" OR sourcetype="*cloudflare*" OR sourcetype="*cf*"
    | eval last_event=strftime(last_event, "%F %T")
    | sort - count
