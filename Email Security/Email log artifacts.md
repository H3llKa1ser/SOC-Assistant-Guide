### An email gateway log, contains these fields:

#### 1) SMTP Server IP: SMTP server IP used by a sender to send an email to a recipient. Use it to observe any spoofing presence as well as if it is blacklisted.

#### 2) Sender email address: Use it to check if it is from a blacklisted domain, as well as for spoofing attempts.

#### 3) Recipient email address: Use it to scope petentially infected machines and users in case of a cyber incident.

#### 4) Email Subject: Describes the content of the message or its purpose. Attackers use psychological tactics to substantially increase the chance of the potential victims interact with the content. For instance, attackers may use phrases to induce stress to the recipient such as: "Urgent Action Required, Unauthorized Access Attempt, Confirm your account Details, etc", which means, this kind of attack is based mostly on the psychological factor as a result, even experienced professionals might have a bad day and accidentally interact with the content (THAT INCLUDES CYBERSECURITY PROFESSIONALS TOO!!!) 

#### 5) Attached filename: This contains the type of file attached to the email. Attackers usually prefer to name these files as: "Invoice, Important Note, Purchase Order, etc" and there is a good chance these files are .pdf, .docx, .xlsx or any kind of file that could run arbitrary code within it.

#### 6) Attached file hash: Provides the hash value of the file attached in the email. Use it to hunt for potential malicious files in threat intelligence engines like VirusTotal.

#### 7) Malware Category: If the file matches any signature in the malware signature database of the gateway, it will provide the malware family.

#### 8) Attached URL: Use it the same way as an attached file hash to filter for potentially malicious URLs, or you can run it in a sandbox environment that has access to the internet to check for potential IOCs

#### 9) Device action: Describes whether the email security solution has blocked or allowed the email to the end user.

#### 10) Block reason: Exactly what the field says :p
