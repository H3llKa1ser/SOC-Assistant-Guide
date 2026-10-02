# Scheduler Log

### 1) Check if your Splunk alert fired up properly

    index=_internal sourcetype=scheduler savedsearch_name="CF Rate Limit Test" earliest=-2h
    | table _time scheduled_time status result_count suppressed alert_actions run_time
    | sort - _time
