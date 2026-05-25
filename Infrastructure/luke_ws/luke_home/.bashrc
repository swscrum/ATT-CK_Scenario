# ~/.bashrc — Luke Smith
# Interactive shell setup for the psychiatrist's workstation.

# Don't put duplicate lines or lines starting with space in history.
HISTCONTROL=ignoreboth
HISTSIZE=1000
HISTFILESIZE=2000

# Append to the history file, don't overwrite.
shopt -s histappend
# Check window size after each command.
shopt -s checkwinsize

# Colour prompt + handy aliases.
export PS1='\u@\h:\w\$ '
alias ll='ls -lah'
alias la='ls -A'
alias l='ls -CF'

# psql convenience — query the central patient DB using .pgpass.
alias notes='psql -h db-internal -U waystar-readonly -d waystar -c "SELECT session_date, patient_id, session_type, duration_min FROM session_notes WHERE therapist = '\''Luke Smith'\'' ORDER BY session_date DESC LIMIT 20"'
alias mypatients='psql -h db-internal -U waystar-readonly -d waystar -c "SELECT DISTINCT p.id, p.first_name, p.last_name, p.diagnosis FROM patients p JOIN session_notes s ON s.patient_id = p.id WHERE s.therapist = '\''Luke Smith'\'' ORDER BY p.last_name"'

# Local SQLite cache helper.
alias localnotes='sqlite3 ~/.local/share/waystar-psyc/patients.sqlite'
