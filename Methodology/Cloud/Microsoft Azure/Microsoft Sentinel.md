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


