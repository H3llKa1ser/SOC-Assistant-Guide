# Kerberos

## Kerberos Authentication Flow

| Step | What Happens | Event ID | Where Logged |
|-----|--------------|----------|--------------|
| 1 | User requests a TGT | 4768 | Domain Controller |
| 2 | User requests a TGS | 4769 | Domain Controller |
| 3 | User creates a session on the target | 4624 | Target server |

## Kerberos ticket encryption types (4768/4769)

| Value | Algorithm | When You See It |
|------|-----------|----------------|
| 0x12 | AES-256 | Modern systems, Windows 2008+ domain functional level |
| 0x17 | RC4-HMAC | Legacy systems, older applications, cross-forest trusts |
