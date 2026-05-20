# Splunk Alerts Export with the Distribution List

### 1) Retrieve all alerts

    | rest /servicesNS/-/-/saved/searches
    | search is_scheduled=1 actions="*email*"
    | table title, actions, action.email.to, action.email.cc, action.email.bcc, action.email.subject, cron_schedule, disabled
    | rename title as "Alert Name", action.email.to as "To", action.email.cc as "CC", action.email.bcc as "BCC"

### 2) Retrieve all alerts that are sent to a specific mailbox

    | rest /servicesNS/-/-/saved/searches splunk_server=local count=0
    | search is_scheduled=1 
        (action.email.to="*cybersecurity@example.com*" 
        OR action.email.cc="*cybersecurity@example.com*" 
        OR action.email.bcc="*cybersecurity@example.com*")
    | eval Status = if(disabled=0, "Active", "Disabled")
    | eval Email_To  = coalesce('action.email.to',  "-")
    | eval Email_CC  = coalesce('action.email.cc',  "-")
    | eval Email_BCC = coalesce('action.email.bcc', "-")
    | table 
        eai:acl.app, 
        title, 
        Status,
        Email_To, 
        Email_CC, 
        Email_BCC,
        action.email.subject,
        cron_schedule,
        actions
    | rename 
        eai:acl.app         as "App",
        title               as "Alert Name",
        action.email.subject as "Email Subject",
        cron_schedule       as "Schedule (Cron)",
        actions             as "Trigger Actions"
    | sort App, "Alert Name"
