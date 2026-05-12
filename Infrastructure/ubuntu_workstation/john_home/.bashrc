# John's workstation .bashrc

case $- in
    *i*) ;;
      *) return;;
esac

HISTCONTROL=ignoreboth
HISTSIZE=5000
HISTFILESIZE=10000

shopt -s histappend
shopt -s checkwinsize

# Pretty prompt — blue user@host so apache deploys (which use the green PS1
# in apache's bashrc) are visually distinct from local work.
PS1='\[\033[01;34m\]\u@\h\[\033[00m\]:\[\033[01;36m\]\w\[\033[00m\]\$ '

alias ll='ls -lah'
alias gs='git status'
alias gl='git log --oneline -20'
alias gd='git diff'
alias deploy='cd ~/projects/waystar-connect && npm run build && npm run deploy'

# Node — default to the project's pinned version if nvm is around
[ -s "$HOME/.nvm/nvm.sh" ] && . "$HOME/.nvm/nvm.sh"

if [ -f /etc/bash_completion ] && ! shopt -oq posix; then
    . /etc/bash_completion
fi
