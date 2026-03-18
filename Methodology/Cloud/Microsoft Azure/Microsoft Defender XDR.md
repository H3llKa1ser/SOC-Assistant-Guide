# Microsoft Defender XDR

## Roles and Permissions

### 1) Microsoft Entra Global Roles

    Global Administrator
    Security Administrator
    Security Operator
    Global Reader
    Security Reader

### 2) Custom Roles for specific MS Defender product

    In the navigation pane, select Permissions.
    Select Roles under the service where you want to create a custom role.

<img width="1281" height="740" alt="image" src="https://github.com/user-attachments/assets/321019cb-38fd-469e-abe8-6a67f5b90598" />

<img width="1162" height="774" alt="image" src="https://github.com/user-attachments/assets/fb7e33f6-2953-49e6-9170-97b0092ff5d6" />

### 3) Unified Role-Based Access Control (RBAC)

You can activate your workloads in the following ways:

    From the Permissions and Roles Page
    
    On the Microsoft Defender portal
    Select permissions on the navigation pane
    Select Roles under Microsoft Defender XDR

<img width="941" height="495" alt="image" src="https://github.com/user-attachments/assets/10e5ca58-56cc-44d2-a046-f80773d8f184" />

On the Permissions and roles screen, select Activate workloads (1) to show a sidebar where you can select each toggle to activate a workload. In some cases, you may not see the Activate workloads option because another administrator may have canceled it. Also, remember that the Workloads options you see are determined by the license currently available for your tenant.

<img width="608" height="430" alt="image" src="https://github.com/user-attachments/assets/16c9affa-d6c1-4286-9dfa-d3056b26d58d" />

Select Workload settings (2) back on the permissions and roles screen as a second option. This takes you to the Microsoft Defender XDR Permission and Roles page where you can then select the toggle for each workload to activate it.

From the Microsoft Defender XDR Settings

    On the Microsoft Defender portal
    Select Settings on the navigation pane
    Select Microsoft Defender XDR
    Select Permissions and roles
    On the Activate workloads page, select the toggle for the workload you want to activate

## Responding to True Positive Incidents

After investigation, if this alert is considered a malicious event, the following can be done on the device to mitigate the threat and prevent further escalation.

    Collect Investigation Package for further analysis.
    Start Microsoft Defender XDR Automated Investigation.
    Initiate Live Response Session to see the registry changes.
    Isolate the device to prevent lateral movement or the attack from getting access to other devices.

<img width="898" height="712" alt="image" src="https://github.com/user-attachments/assets/58962f94-5a58-481e-8bdd-964f12f1e111" />

## Prevention

Ensure the following Microsoft Defender for endpoint Attack Surface Reduction (ASR) Rules are in block mode to restrict Defense evasion activities.

#### Note: ASR rules are only supported on Windows operating systems.

    Block Office applications from injecting code into other processes: To prevent common Defense Evasion techniques where malicious Office macros are injected into trusted processes.
    Block execution of potentially obfuscated scripts: To prevent execution of highly obfuscated scripts from running.
    Block untrusted and unsigned processes that run from USB: To prevent malware execution from removable drives, which is a common way to bypass security tools.
    Block all Office applications from creating child processes: This will prevent malware from launching scripts or binaries through Office apps like Word or Excel files.
    Block executable content from email and webmail: This will prevent users from running malicious attachments from phishing campaigns that may lead to Defense Evasion.

Ensure Tamper Protection is enabled to stop threat actors from disabling Defender and modifying the security controls, which is a common impair defense technique.

    To see the Tamper protection setting on your Defender portal
    
    Navigate to Settings and select Endpoint 
    
    On Advanced features, ensure Tamper protection is turned on

<img width="950" height="595" alt="image" src="https://github.com/user-attachments/assets/eabc0c2d-5f17-4bc7-9996-19ffe7240466" />

