# Remote SSH Login

### 1) Check on a specific host for a specific user

    index=os host=TARGET_HOST sshd ("Accepted" OR "Disconnected from" OR "session opened" OR "session closed") TARGET_USER
    | table _time source _raw
    | sort 0 _time
