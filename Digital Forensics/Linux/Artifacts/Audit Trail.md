# Audit Trail using Bash

| Command                          | Description                                                                 |
|----------------------------------|-----------------------------------------------------------------------------|
| `set -o history`                | Enables command history in the shell, allowing it to record the commands you enter. |
| `shopt -s histappend`           | Ensures that the command history is appended to the history file instead of overwriting it when the shell exits. |
| `export HISTCONTROL=`           | Clears any settings that control which commands are saved in the history, ensuring all commands are recorded. |
| `export HISTIGNORE=`            | Clears any settings that ignore specific patterns of commands, so all commands are saved in the history. |
| `export HISTFILE=~/.bash_history` | Sets the file where the command history is saved.                          |
| `export HISTFILESIZE=-1`        | Sets no limit on the number of lines stored in the history file.            |
| `export HISTSIZE=-1`            | Sets no limit on the number of commands retained in the shell history.      |
| `export HISTTIMEFORMAT="%F-%R "` | Formats timestamps in the history as "YYYY-MM-DD HH" for each command.     |
