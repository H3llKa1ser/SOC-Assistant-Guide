# Splunk Alerts Export with the Distribution List

    | rest /servicesNS/-/-/saved/searches
    | search is_scheduled=1 actions="*email*"
    | table title, actions, action.email.to, action.email.cc, action.email.bcc, action.email.subject, cron_schedule, disabled
    | rename title as "Alert Name", action.email.to as "To", action.email.cc as "CC", action.email.bcc as "BCC"
