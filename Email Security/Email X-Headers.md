# EMAIL X-HEADERS

### Email X-headers are custom headers that are added to the email header by the mailbox providers in addition to the standard headers, such as To, From, Subject, and MIME-Version, all of which are defined by the RFC standards. Custom X-headers are added to the email header according to the needs of the mailbox provider.

#### 1) X-Mailer: A custom X-header that refers to the email client that was used to send the email. The X-Mailer header is added by mailbox providers to identify and block suspicious email messages that are sent via weird email clients such as script interpreters and uncommon email clients such as hacking tools and so on.

#### 2) X-SONIC-DKIM-SIGN: This field seems to be holding a custom DKIM signature for email authentication.

#### 3) X-Originating-IP: Contains  the IP address of the device that is the origin of the email. It helps identify the origin IP of the message and can be used for spam filtering and tracking purposes.

#### 4) X-Sonic-MF: A custom X-header that seems to refer to the email address that sent the email. It was used later by the X-SONIC-DKIM-SIGN Header.

#### 5) X-Ymail-OSG: To understand this custom X-header, let’s break down its name. YMail stands for Yahoo Mail, while OSG stands for Outbound Spam Guard, so by breaking down the name, we can conclude that this X-header is related to the spam guard solution implemented by the Yahoo email service provider


## Cited from: Effective Threat Investigation for SOC Analysts by Mostafa Yahia
