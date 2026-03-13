# IAM Roles

### 1) Use the role name in your search

    index=aws eventName=* ROLE_NAME

### 2) Check the role session name

    index=aws eventName=* ROLE_SESSION_NAME

### 3) Find for AssumeRole events, then use the aws_account_id to find the actual user assuming the role

    index=aws eventName=* ROLE_SESSION_NAME aws_account_id=AWS_ACCOUNT_ID
