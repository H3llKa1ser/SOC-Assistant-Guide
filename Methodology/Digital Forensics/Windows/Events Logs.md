# Event Logs

Tools:

1) Event Viewer

## Event Types

### 1) RDP

RDP Logs

    Applications and Services Logs -> Microsoft -> Windows -> Terminal-Services-RemoteConnectionManager > Operational

#### Important Event IDs:

1) Successful Login

- 1149

### 2) Windows Defender

Windows Defender Logs

    Applications and Services Logs > Microsoft > Windows > Windows Defender > Operational

#### Important Event IDs:

1) Disabled AV

- 5001

### 3) User Accounts

Logs location:

    Windows Logs -> Security

#### Important Event IDs:

1) User account creation

- 4720

2) User account enabled

- 4722

3) User account modification

- 4738

4) User account locked due to repeated failed login attempts

- 4740

5) User account deletion

- 4726

6) User account succcessful login

- 4624

7) User account failed login

- 4625

8) A Kerberos authentication ticket (TGT) was requested

- 4768

9) Kerberos pre-auth failed

- 4771
