# Teams

Tools:

1) Forensics.im https://github.com/lxndrblz/forensicsim/ (Autopsy plugin)

Location:

    C:\Users\USER\AppData\Roaming\Microsoft\Teams

### 1) Check each user's directory for Teams artifacts

    ls C:\Users\ | foreach {ls "C:\Users\$_\AppData\Roaming\Microsoft\Teams" 2>$null | findstr Directory}

### 2) Check IndexedDB folder for interesting artifacts

    ls C:\Users\USER\AppData\Roaming\Microsoft\Teams\IndexedDB\

### 3) Parse Teams metadata

    C:\Tools\ms_teams_parser.exe -f C:\Users\USER\AppData\Roaming\Microsoft\Teams\IndexedDB\https_teams.microsoft.com_0.indexeddb.leveldb\ -o output.json

### 4) List MRI and userPrincipalName key-value pairs (use parsed .json file form previous command)

    $teams_metadata = cat .\output.json | ConvertFrom-Json
    $users = @{}
    
    # Initialise user hashtable for correlation
    foreach ($data in $teams_metadata) {
       if ($data.record_type -eq "contact") {
         $users.add($data.mri, $data.userPrincipalName)
       }
    }
    $users | fl

### 5) Combine the messages with identical conversation IDs to view messages in each thread

    $teams_metadata = cat .\output.json | ConvertFrom-Json
    $messages = @{}
    # Combine all conversations/messages with the same ID
    foreach ($data in $teams_metadata) {
      if ($data.record_type -eq "message") {
        if ($messages.keys -notcontains $data.conversationId) {
          $messages[$data.conversationId] = [System.Collections.ArrayList]@()
        }
        $messages[$data.conversationId].add($data) > $null
      }

### 6) Parse each message entry, sort it based on the creation date and render only the essential details

    cat .\output.json | ConvertFrom-Json
    $users = @{}
    $messages = @{}
    
    # Initialise user hashtable for correlation
    foreach ($data in $teams_metadata) {
       if ($data.record_type -eq "contact") {
         $users.add($data.mri, $data.userPrincipalName)
       }
    }
    
    # Combine all conversations/messages with the same ID
    foreach ($data in $teams_metadata) {
      if ($data.record_type -eq "message") {
        if ($messages.keys -notcontains $data.conversationId) {
          $messages[$data.conversationId] = [System.Collections.ArrayList]@()
        }
        $messages[$data.conversationId].add($data) > $null
      }
    }
    
    # Print the parsed output focused on the significant values
    foreach ($conversationID in $messages.keys) {
      Write-Host "Conversation ID: $conversationID`n"
      $conversation = $messages[$conversationID] | Sort createdTime
      foreach ($message in $conversation) {
        $createdTime = $message.createdTime
        $fromme = $message.isFromMe
        $content = $message.content
        $sender = $users[$message.creator]
    
        Write-Host "Created Time: $createdTime"
        Write-Host "Sent by: $sender"
        Write-Host "Direction: $direction"
        Write-Host "Message content: $content"
        Write-Host "`n"
      }
    
      Write-host "----------------`n"
    }
        }
        $messages | fl

### 7) Parse the properties field and collect the file attachment information. View conversation threads as well.

     $teams_metadata = cat .\output.json | ConvertFrom-Json
    $users = @{}
    $messages = @{}
    
    # Initialise user hashtable for correlation
    foreach ($data in $teams_metadata) {
       if ($data.record_type -eq "contact") {
         $users.add($data.mri, $data.userPrincipalName)
       }
    }
    
    # Combine all conversations/messages with the same ID
    foreach ($data in $teams_metadata) {
      if ($data.record_type -eq "message") {
        if ($messages.keys -notcontains $data.conversationId) {
          $messages[$data.conversationId] = [System.Collections.ArrayList]@()
        }
        $messages[$data.conversationId].add($data) > $null
      }
    }
    
    # Print the parsed output focused on the significant values
    foreach ($conversationID in $messages.keys) {
      Write-Host "Conversation ID: $conversationID`n"
      $conversation = $messages[$conversationID] | Sort createdTime
      foreach ($message in $conversation) {
        $createdTime = $message.createdTime
        $fromme = $message.isFromMe
        $content = $message.content
        $sender = $users[$message.creator]
        $direction = if ($message.isFromMe) { 'Outbound' } else { 'Inbound' }
        $attachments = if ($message.properties.files) { 'True' } else {'False'}
    
        Write-Host "Created Time: $createdTime"
        Write-Host "Sent by: $sender"
        Write-Host "Direction: $direction"
        Write-Host "Message content: $content"
        Write-Host "Has attachment: $attachments"
        
        # Parse file attachment details
        if ($attachments -eq "True") {
          foreach ($attachment in $message.properties.files) {
            $filename = $attachment.fileName
            $location = $attachment.fileInfo.fileUrl
            $type = $attachment.fileType
            
            Write-Host "Attachment name: $filename"
            Write-Host "Attachment location: $location"
            Write-Host "Attachment type: $type"
          }
        }
        Write-Host "`n"
      }
    
      Write-host "----------------`n"
    }
