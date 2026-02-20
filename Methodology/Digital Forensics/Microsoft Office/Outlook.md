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

Investigate the attachment by acquiring a copy

    Save All Attachments

View Email Headers

    Click the radio button "Properties"

### 3) Check if a user has opened a file directly using the Outlook client

Files here are stored temporarily until the client is terminated.

    ls -rec C:\Users\USER\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook

