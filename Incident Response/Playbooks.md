### Resource: https://github.com/LetsDefend/incident-response-playbooks/tree/main

## High level steps of creating a playbook

#### 1) Preparation Phase

 - For a playbook to initiate, it needs some triggers and conditions to be activated. (Examples: A SIEM/XDR Alert that contains all the relevant information, a user report, use cases depending on the playbook, recommended security controls, etc)

#### 2) Detection and Analysis

 - Once an incident is triggered, detection and analysis of the IR process occur. Create workflow diagrams to filter for False Positives and True Positives depending on use case. (Examples: Extracting important information needed to assist with the verdict of FP or TP.) If the incident is FP, the incident is closed. Else, go to step 3.

#### 3) Containment, Eradication and Recovery

 - Once an incident is considered True Positive (TP), conduct the actions necessary depending on use case with the STRICT order of:

 - 1) Containment (Ensure to contain the threat for successfully eradicating it)
  
 - 2) Eradication (Ensure to properly eradicate any traces of the threat entirely, so that you can go further with the recovery phase successfully without repercussions)
  
 - 3) Recovery (Return all systems and accounts to operational status)

#### 4) Post-Incident Activity

 - Once a True Positive Incident has been successfully handled, take steps to identify gaps during the process, make recommendations to improve your company's processes and try to make a root cause analysis and do a Business Impact Analysis (BIA).
