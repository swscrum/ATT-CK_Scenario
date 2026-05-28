# ~/.profile — Luke Smith
# Sourced by /bin/sh for login shells.

# Source .bashrc if running under bash.
if [ -n "$BASH_VERSION" ] && [ -f "$HOME/.bashrc" ]; then
    . "$HOME/.bashrc"
fi

# Personal bin directory if it exists.
if [ -d "$HOME/bin" ]; then
    PATH="$HOME/bin:$PATH"
fi
