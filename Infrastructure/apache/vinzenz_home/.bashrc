# vinzenz.fedora's .bashrc on the apache deploy box.
# Minimal — most of his work here is one-shot SSH commands, not interactive.

[ -z "$PS1" ] && return

HISTCONTROL=ignoreboth
HISTSIZE=1000
HISTFILESIZE=2000
shopt -s histappend
shopt -s checkwinsize

PS1='\u@\h:\w\$ '

alias ll='ls -lah'
alias rcl='journalctl --no-pager -n 100'
