# Outlook

Tools: 

1) XstReader

Location:

    C:\Users\USER\AppData\Local\Microsoft\Outlook\

### 1) Search each user's directory for email artifacts

    ls C:\Users\ | foreach {ls "C:\Users\$_\AppData\Local\Microsoft\Outlook\" 2>$null | findstr Directory}

### 2) Use XstReader to analyze .ost email files of a user

Run XstReader, then go to:

    Open -> Browse to C:\Users\USER\AppData\Local\Microsoft\Outlook\user.name@domain.local.ost

To check for email attachments, go to:

    Root - Mailbox -> IPM_SUBTREE -> Conversation History -> Click on the paperclip symbol
