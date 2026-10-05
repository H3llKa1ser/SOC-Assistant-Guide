# Imperva 

## Troubleshooting

### 1) Check if there are any events indexed to Splunk

    index=imperva sourcetype=imperva_sourcetype earliest=-7d@d latest=@d
    | stats count

### 2) Check which fields are actually used

    index=imperva sourcetype=imperva_sourcetype earliest=-7d@d latest=@d
    | fieldsummary
    | table field count distinct_count
    | sort - count

### 3) Event Sampling

    index=imperva sourcetype=imperva_sourcetype earliest=-7d@d latest=@d
    | head 1
    | table _raw

### 4) Schema Overview

    index="imperva-bot-mitigation" sourcetype="imperva_sourcetype" earliest=-15m
    | head 1000
    | fieldsummary maxvals=3
    | table field, count, distinct_count, values

## Incident Response / Threat Hunting

### 1) Top blocked IPs with location and user agent

    index="imperva-bot-mitigation" sourcetype="imperva_sourcetype" event.action="block"
    | dedup event.id
    | eval ip=mvindex('client.ip',0), country=mvindex('client.geo.country_iso_code',0), host=mvindex('server.domain',0),
           path=mvindex('url.path',0), ua_name=mvindex('user_agent.name',0),
           deciding=mvdedup('imperva.abp.bot_deciding_condition_names{}')
    | stats count AS Request_Count, values(host) AS Domain, values(path) AS URL_Path, values(ua_name) AS UA_Name,
            values(deciding) AS Blocking_Conditions BY ip, country
    | iplocation ip
    | eval Blocking_Conditions=mvjoin(Blocking_Conditions, ", ")
    | table ip, country, City, Request_Count, Domain, URL_Path, UA_Name, Blocking_Conditions
    | sort - Request_Count
    | head 20

### 2) Most targeted domain paths

    index="imperva-bot-mitigation" sourcetype="imperva_sourcetype" event.action="block"
    | dedup event.id
    | eval ip=mvindex('client.ip',0), host=mvindex('server.domain',0), path=mvindex('url.path',0)
    | stats count AS Request_Count, dc(ip) AS Unique_IPs BY host, path
    | sort - Request_Count
    | head 20

### 3) Top deciding conditions behind blocks

    index="imperva-bot-mitigation" sourcetype="imperva_sourcetype" event.action="block"
    | dedup event.id
    | eval ip=mvindex('client.ip',0), deciding=mvdedup('imperva.abp.bot_deciding_condition_names{}')
    | stats count AS Events, dc(ip) AS Unique_IPs BY deciding
    | sort - Events
    | rename deciding AS "Deciding Condition"

### 4) Credential stuffing: token and rate-limit blocks on login

Replace domain.com and /api/login with your actual target values.

    index="imperva-bot-mitigation" sourcetype="imperva_sourcetype" server.domain="domain.com" url.path="/api/login*" event.action="block"
    | dedup event.id
    | eval ip=mvindex('client.ip',0), country=mvindex('client.geo.country_iso_code',0), host=mvindex('server.domain',0),
           deciding=mvdedup('imperva.abp.bot_deciding_condition_names{}')
    | where isnotnull(mvfind(deciding, "^(Missing token|Invalid token|Rate limiting API)$"))
    | stats count AS Request_Count, values(host) AS Domain, values(deciding) AS Blocking_Condition BY ip, country
    | eval Blocking_Condition=mvjoin(Blocking_Condition, ", ")
    | sort - Request_Count

### 5) Distributed bot attacks: many IPs, same condition

Change the Unique_IPs threshold as needed.

    index="imperva-bot-mitigation" sourcetype="imperva_sourcetype" event.action="block"
    | dedup event.id
    | eval ip=mvindex('client.ip',0), host=mvindex('server.domain',0),
           deciding=mvdedup('imperva.abp.bot_deciding_condition_names{}')
    | stats dc(ip) AS Unique_IPs, count AS Total_Events, dc(host) AS Sites BY deciding
    | where Unique_IPs > 50
    | sort - Unique_IPs

### 6) API endpoint activity (DDoS or credential stuffing)

    index="imperva-bot-mitigation" sourcetype="imperva_sourcetype" event.action="block" url.path="/api/*"
    | dedup event.id
    | eval ip=mvindex('client.ip',0), host=mvindex('server.domain',0), path=mvindex('url.path',0),
           deciding=mvdedup('imperva.abp.bot_deciding_condition_names{}')
    | stats count AS API_Hits, dc(ip) AS Unique_IPs, values(deciding) AS Blocking_Conditions BY host, path
    | eval Blocking_Conditions=mvjoin(Blocking_Conditions, ", ")
    | sort - API_Hits
    | head 20

### 7) Events per domain

    index="imperva-bot-mitigation" sourcetype="imperva_sourcetype"
    | dedup event.id
    | eval host=mvindex('server.domain',0)
    | stats latest(_time) AS Last_Event, earliest(_time) AS First_Event, count AS Total_Events BY host
    | eval Last_Event=strftime(Last_Event, "%F %T"), First_Event=strftime(First_Event, "%F %T")
    | sort - Total_Events

### 8) Single IP Deep Dive

    index="imperva-bot-mitigation" sourcetype="imperva_sourcetype" client.ip="IP_ADDRESS"
    | dedup event.id
    | eval host=mvindex('server.domain',0), path=mvindex('url.path',0), action=mvindex('event.action',0),
           category=mvindex('imperva.abp.category',0), policy=mvindex('imperva.abp.policy_name',0),
           ua_name=mvindex('user_agent.name',0), ua=mvindex('user_agent.original',0),
           bot_deciding_conditions=mvjoin(mvdedup('imperva.abp.bot_deciding_condition_names{}'), ", "),
           bot_triggered_conditions=mvjoin(mvdedup('imperva.abp.bot_triggered_condition_names{}'), ", "),
           bot_behaviors=mvjoin(mvdedup('imperva.abp.bot_behaviors{}'), ", ")
    | fillnull value="-" bot_deciding_conditions bot_triggered_conditions bot_behaviors
    | table _time, host, path, action, category, policy, ua_name, ua, bot_deciding_conditions, bot_triggered_conditions, bot_behaviors
    | sort - _time
