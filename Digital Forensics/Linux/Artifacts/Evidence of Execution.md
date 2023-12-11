## Sudo execution history

### Location: /var/log/auth.log

#### We can use "grep" to filter out sudo commands in the log file. (Example: cat /var/log/auth.log | grep -i sudo | tail)

## Bash history

#### Any commands other than the ones run using "sudo" are stored in the bash history.

#### Every user's bash history is stored separately in that user's home folder. Therefore, when examining bash history, we need to get the .bash_history file from each user's home directory, including root.

### Location: ~/.bash_history

## Files accessed using vim

#### The vim text editor stores logs for opened files in Vim named .viminfo in the home directory.

#### This file contains command line history, search string history, etc for opened files.

### Location: ~/.viminfo
