# EMAIL HEADER ANALYSIS

### Email header analysis is the process of analyzing every aspect of the email header to identify the email sender, sender IP, passed hops, email subject, email recipient, email timestamps, and email authentication results. Additionally, to be able to identify the presence of email spoofing.

### An email header consists of:

#### 1) Email message content and metadata

#### 2) Email X-Headers
) From
#### 3) The header that was added by the hop servers

#### 4) Email Authentication (Explained in a separate section)

## Email message content and metadata

#### 1) Date: Timestamp based on the MUA used

#### 2) From: Display name and the email sender address (Can be spoofed)

#### 3) To: Message recipient email address

#### 4) Message-ID: Unique identifier that consists of long strings of characters anding with the FQDN of the sending mail server

#### 5) Subject: Message subject written by sender

#### 6) Multipurpose Internet Mail Extensions (MIME) Version: Version of MIME. MIME allows people to echagnge different types of data files

#### 7) Content-Type: Content types included in the message (I.E.: Documents, text, audio, etc)

#### 8) Content-Transfer-Encoding: This field’s value is used to specify how the email message’s MIME and body have been encoded and transferred from the sender to the recipient so that it can be decoded by the recipient.

#### 9) References: Includes a list of every message IDof the original email and all replies in the same email thread. In short, it allows us to track the entire conversation between the sender and the recipient.

#### 10) Content-Length: Contains the size of the message's body in bytes.
