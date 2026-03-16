# Kerberos

## Kerberos Authentication Flow

| Step | What Happens | Event ID | Where Logged |
|-----|--------------|----------|--------------|
| 1 | User requests a TGT | 4768 | Domain Controller |
| 2 | User requests a TGS | 4769 | Domain Controller |
| 3 | User creates a session on the target | 4624 | Target server |
