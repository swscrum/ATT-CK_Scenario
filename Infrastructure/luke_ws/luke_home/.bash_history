whoami
hostnamectl
ip a
psql -h db-internal -U waystar-readonly -d waystar
psql -h db-internal -U waystar-readonly -d waystar -c "\dt"
psql -h db-internal -U waystar-readonly -d waystar -c "SELECT COUNT(*) FROM patients"
mypatients
notes
psql -h db-internal -U waystar-readonly -d waystar -c "SELECT * FROM session_notes WHERE therapist = 'Luke Smith' ORDER BY session_date DESC LIMIT 5"
sqlite3 ~/.local/share/waystar-psyc/patients.sqlite '.tables'
sqlite3 ~/.local/share/waystar-psyc/patients.sqlite 'SELECT * FROM patient_summary LIMIT 5'
ls -la ~/Documents/notes/
vim ~/Documents/notes/2026-05-18_session_notes.md
ls -la ~/Documents/cases/
cat ~/Documents/cases/case_A/treatment_plan.md
curl -sI http://apache/
df -h
free -h
sudo apt update
sudo apt upgrade -y
history
exit
