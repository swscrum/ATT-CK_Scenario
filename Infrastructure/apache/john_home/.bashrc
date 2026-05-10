# John's apache deploy-shell .bashrc
case $- in
    *i*) ;;
      *) return;;
esac

HISTCONTROL=ignoreboth
HISTSIZE=2000
HISTFILESIZE=4000

shopt -s histappend
shopt -s checkwinsize

# Custom prompt — green for John's account, hostname tagged so deploys are obvious
PS1='\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '

alias ll='ls -lah'
alias logs='tail -f /usr/local/apache2/logs/error_log /usr/local/apache2/logs/access_log'
alias deploys='ls -lt /opt/waystar-connect/'
