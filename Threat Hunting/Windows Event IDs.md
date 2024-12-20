# Windows Events

| Event ID                                                    | Description                                                  |
| ------------------------------------------------------------| ------------------------------------------------------------ |
| `4769`                                                      | Event generated when a TGS is requested. Can be indicative of Kerberoasting. |
| `4768 `                                                     | Event generated when a TGT is requested. Can be indicative of Asreproasting. |
| `4625`                                                      | Event generated when an account fails to log on. |
| `4771`                                                      | Event generated by a Kerberos pre-authentication failure. |
| `4776`                                                      | Event generated when attempting to validate the credentials of an account. |
| `5136`                                                      | Event generated when a GPO is modified, if Directory Service Changes auditing is enabled. |
| `4725`                                                      | Event generated when a user account is disabled. |
| `4624`                                                      | Event generated when an account successfully logs on to a windows computer. The S4U extension notes the presence of delegation. |
| `4662`                                                      | Event generated by a possible DCsync attack. If the account name is not a domain controller, it serves as a flag that a user generated the attack. |
| `4738`                                                      | Event generated when a user account is changed. Any association of this event with a honeypot user should trigger an alert. |
| `4742`                                                      | Event generated when a computer account is changed. |
| `4886`                                                      | Event generated when a certificate is requested. |
| `4887`                                                      | Event generated when a certificate is approved and issued. |