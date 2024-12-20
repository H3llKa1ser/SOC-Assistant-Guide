# DISK IMAGE

#### A bit-by-bit copy of a disk drive. It saves all the data in a disk image file, including the metadata in a single file.

# DISK IMAGING

#### This is the process of creating a bit-for-bit copy of a disk, a complete replica of the original data. It allows analysts to examine the data without altering the original evidence. A much-needed step in disk imaging is using write blockers to prevent data alteration during acquisition.

# WRITE BLOCKING

#### Write blocking is a crucial method for preventing data alteration during acquisition and ensuring the integrity of the evidence. Hardware and software write blockers perform the operations. We illustrate a hardware write blocker with a USB drive on the right. It is also crucial to document the use of write blockers in the data acquisition logs to inform any other individual working on the investigation.

# PHYSICAL ACQUISITION METHODS

#### This involves removing and imaging hard drives from the target system. This method requires careful handling to avoid data corruption or damage. It is necessary to use this method when dealing with damaged devices or encrypted storage. Some of the methods used during physical acquisition include:

 - 1) Chip-off forensics: This delicate process involves removing the storage chip from the device and reading it with specialised equipment.

 - 2) JTAG forensics: This uses the Joint Test Action Group (JTAG) interface to access data from embedded systems. It is helpful for mobile and IoT devices.
  
# SECURE STORAGE

#### Once you have acquired the needed data, it must be stored securely to prevent tampering and its integrity. The best practices to use include:

 - 1) Strong encryption: Advanced encryption methods, such as AES-256, protect data at rest. Encryption ensures the data remains unreadable without the decryption key, even if unauthorised access occurs.

 - 2) Access control: Establishing access control measures will restrict data access and investigation access to authorised personnel. This goes hand in hand with chain of custody.

 - 3) Environment control: A physically secure environment, such as a locked storage safe or secure server room with controlled access, ensures protection against physical threats.
 - 4) Regular audits: Conduct regular audits of the storage environment and access logs to ensure compliance with security policies and identify any potential breaches.
  
# ENSURING INTEGRITY AND CHAIN OF CUSTODY

#### Chain of custody refers to the documentation of the responsible personnel in charge of evidence, its transfer from the point of collection to its presentation in court or required body after investigation. Maintaining a chain of custody ensures that evidence has not been tampered with and can be trusted as the factual findings of an investigation.

#### To maintain the integrity and chain of custody of forensic data, we can follow the following guidelines:

 - 1) Document every step: No matter how small an action is during the forensic analysis, it must be documented and aligned with whoever is handling the evidence, what time was taken, and the reasons behind their access to the evidence.

 - 2) Secure transport: Tamper-proof packaging should be utilised to transport disk drives and other evidence securely.

 - 3) Hashing: Using cryptographic hash functions such as MD5 and SHA-1 to create unique data fingerprints and verify that it has not been altered.
 - 4) Write blocking: As mentioned before in the acquisition step, using write blockers helps prevent any modification of the original data.

