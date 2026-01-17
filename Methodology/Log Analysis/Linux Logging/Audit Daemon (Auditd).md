# Audit Daemon (Auditd)

Location

    /var/log/audit/audit.log

Command:

    ausearch

Auditd rules location

    /etc/audit/rules.d/audit.rules

Example usage:

    ausearch -i -k KEY_NAME

More filtered approach

    ausearch -i -k KEY_NAME | grep "WHATEVER"
