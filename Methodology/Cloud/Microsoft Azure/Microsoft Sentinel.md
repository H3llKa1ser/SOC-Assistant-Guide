# Microsoft Sentinel

## Prerequisites

Microsoft Sentinel Contributor permissions are required at the resource group level where the Microsoft Sentinel workspace resides. 

## Create a Log Analytics Workspace

### 1) In the Azure portal, search for and select Microsoft Sentinel

<img width="367" height="167" alt="image" src="https://github.com/user-attachments/assets/33349dce-866b-4c5c-b48e-2d46c6f72b66" />

### 2) Since there is no previously created Log Analytics workspace with Sentinel enabled, select Create Microsoft Sentinel.

<img width="1035" height="771" alt="image" src="https://github.com/user-attachments/assets/94f80f38-5499-4a9a-874a-7b5828b55acb" />

### 3) Create a new Workspace (MANDATORY FOR MS SENTINEL TO BE DEPLOYED)

<img width="1035" height="771" alt="image" src="https://github.com/user-attachments/assets/7bc230e1-ec31-4520-aefe-f369876dace1" />

### 4) Provide the necessary details below:

Subscription: Select the subscription available in the drop-down

Resource Group: Select the resource group available in the drop-down

Name: Name of LAW instance

Region: Azure region where the ingested log data will reside. This setting is significant as the organization might have certain data residency requirements. It is important to note that once created, the region of a LAW cannot be changed

### 5) Add Microsoft Sentinel to a Log Analytics Workspace

### 6) READY!

## Roles

### 1) Microsoft Sentinel Reader

View data, incidents, workbooks, and other Microsoft Sentinel resources

### 2) Microsoft Sentinel Responder (in addition to the above Sentinel Reader)

Manage incidents

### 3) Microsoft Sentinel Contributor (in addition to the above Sentinel Responder)

Install/Update solutions from the Content hub.

Create and edit workbooks, analytics rules, and other Microsoft Sentinel resources

### 4) Microsoft Sentinel Playbook Operator

List, view, and manually run playbooks

### 5) Microsoft Sentinel Automation Contributor (not for user accounts)

Allows Microsoft Sentinel to add playbooks to automation rules

## Content Hub and Data Connectors

### 1) Install Microsoft Entra ID (example) content solution type

Go to Microsoft Sentinel and open the available workspace. Under Content management, select Content hub

<img width="243" height="126" alt="image" src="https://github.com/user-attachments/assets/854047c8-f0bd-4445-87e8-5584ea09770a" />

### 2) Search for Entra ID, then click Install

<img width="1601" height="682" alt="image" src="https://github.com/user-attachments/assets/431147ee-9091-430e-b168-dc4de8f0576e" />

### 3) Review the installed content by clicking Manage for more details

<img width="971" height="725" alt="image" src="https://github.com/user-attachments/assets/f9568215-b88e-4bb1-98fd-d41fe2a3dee3" />

### 4) Review Data Connector status

Under Content name, click on Microsoft Entra ID. Review the data connector status

<img width="815" height="404" alt="image" src="https://github.com/user-attachments/assets/5aca3d0b-0277-4ee2-b144-f4c9ce392790" />

### 5) Select Manage to review the deployed Entra ID connectors

### 6) Select the Microsoft Entra ID data connector and open the connector page

### 7) Click Connect on your desired data connector

### 8) Review the data connector's status to ensure it is connected

### 9) When the log data starts to flow, the Last Log Received will be updated (this might take 10-15min, but it's not required to wait for it)

### 10) Once the connection is established, the data type icon will turn to green, indicating that the corresponding log table is populated and now contains data in the Log Analytics workspace

## Analytics Rules

### 1) Choose a rule template, then create a rule

    Microsoft Sentinel > Analytics > Rule templates > Select a rule template > Create rule

<img width="1465" height="794" alt="image" src="https://github.com/user-attachments/assets/ab1ac286-40d3-4176-86c1-eecad486083e" />

### 2) General

Description, name, severity and tactics are included in the rule

### 3) Set rule logic

You may modify the KQL logic of the rule if needed and schedule the query according to use case.

### 4) Incident creating

Youc an enable/disable incident creation, by applying alert grouping.

### 5) Automated Response (SOAR)

You can apply playbooks to run for various use cases.

Playbook actions:

- To run a playbook

- To change status/severity

- To assign an owner




- To add tags

- To add task
