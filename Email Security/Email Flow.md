# EMAIL FLOW

### An email flow is the f﻿low path that an email follows and the hops that the email passes when sent from the sender until it's delivered to the recipient. The email crosses multiple hops between the sender and the recipient before it is delivered. Most of them use SMTP.

#### 1) Mail User Agent (MUA): Refers to the agent that is used by the client to send the email. Examples: Outlook, Google Chrome, Mozilla Firefox, etc

#### 2) Mail Submission Agent (MSA): The server that receives the email after the client has submitted it from its MUA

#### 3) Mail Transfer Agent (MTA): AKA SMTP relay server. Meaning that this email server receives the message from MSA and passes it to several MTA servers until it's delivered to the recipient's mail exchange server.

#### 4) Mail Exchange (MX): The email server that is responsible foe receiving messages intended for a particular domain that are sent and transferred from MTAs to be delivered to recipients. This server is typically identified by an MX record in the DNS records of the recipient domain. A domain may have multiple MX servers for load-balacning purposes.

#### 5) Mail Delivery Agent (MDA): The server responsible for providing the recipient with the sent email after successful authentication.
