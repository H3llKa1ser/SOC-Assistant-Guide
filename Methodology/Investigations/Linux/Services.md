# Services

Services directory location:

    /etc/systemd/system

### 1) Gather information of a specific service in the logs

    cat /var/log/syslog | grep SERVICE_NAME

You can use journalctl for cleaner output instead

    sudo journalctl -u SERVICE_NAME
