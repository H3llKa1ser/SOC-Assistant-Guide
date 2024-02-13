## EMAIL X-HEADERS

### Email X-headers are custom headers that are added to the email header by the mailbox providers in addition to the standard headers, such as To, From, Subject, and MIME-Version, all of which are defined by the RFC standards. Custom X-headers are added to the email header according to the needs of the mailbox provider.

#### 1) X-Mailer: A custom X-header that refers to the email client that was used to send the email. The X-Mailer header is added by mailbox providers to identify and block suspicious email messages that are sent via weird email clients such as script interpreters and uncommon email clients such as hacking tools and so on.

#### 2) X-SONIC-DKIM-SIGN: This field seems to be holding a custom DKIM signature for email authentication.
