# luke.smith's .bashrc on the apache deploy box (backup-pull target only).

[ -z "$PS1" ] && return

HISTCONTROL=ignoreboth
HISTSIZE=500
shopt -s histappend
shopt -s checkwinsize

PS1='\u@\h:\w\$ '

alias ll='ls -lah'
