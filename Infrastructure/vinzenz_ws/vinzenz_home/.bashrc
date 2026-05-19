# ~/.bashrc — Vinzenz Fedora (sysadmin)

HISTCONTROL=ignoreboth
HISTSIZE=2000
HISTFILESIZE=4000

shopt -s histappend
shopt -s checkwinsize

export PS1='\u@\h:\w# '

# Sysadmin aliases — fleet management.
alias ll='ls -lah'
alias la='ls -A'
alias l='ls -CF'

# SSH-aliased fleet hosts (see ~/.ssh/config).
alias check-apache='ssh apache "uptime && systemctl status httpd 2>/dev/null || systemctl status apache2"'
alias check-john='ssh john uptime'
alias check-luke='ssh luke uptime'
alias fleet-uptime='for h in apache john luke; do printf "%-12s " "$h:"; ssh "$h" uptime 2>/dev/null || echo "(unreachable)"; done'

# Privileged DB query — Vinzenz has superuser creds via ~/.pgpass.
alias dbshell='psql -h db-internal -U waystar -d waystar'
