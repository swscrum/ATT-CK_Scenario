# ~/.profile — Vinzenz Fedora
if [ -n "$BASH_VERSION" ] && [ -f "$HOME/.bashrc" ]; then
    . "$HOME/.bashrc"
fi
if [ -d "$HOME/bin" ]; then
    PATH="$HOME/bin:$PATH"
fi
