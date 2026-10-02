# Alerts

### 1) Check if an action in CF is on the pipeline

    index=cloudflare sourcetype=cloudflare:json earliest=-1h EdgeResponseStatus=429 SecurityRuleID="f0c1abb07e4f4a718aee610e8f025916"
    | eval indexed_at=strftime(_indextime, "%F %T"), lag_s=_indextime-_time
    | table _time indexed_at lag_s ClientIP RayID
