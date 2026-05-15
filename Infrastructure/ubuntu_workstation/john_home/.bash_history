cd ~/projects/waystar-connect/
ls
npm install
npm run dev
git status
vim src/app.js
git diff
git add src/app.js
git commit -m "wire up booking-form validation"
git log --oneline -10
npm run build
ls dist/
ssh apache 'whoami'
ssh apache 'ls /opt/waystar-connect/'
rsync -avz --delete dist/ john.stravidis@apache:/opt/waystar-connect/dist/
ssh apache 'tail /opt/waystar-connect/deploy.log'
ssh apache 'tail /usr/local/apache2/logs/access_log'
curl -sI http://apache/
firefox http://apache/ &
vim src/styles.css
git add -A && git commit -m "polish landing page typography"
npm run build && npm run deploy
ls -lah ~/Documents/
cat ~/Documents/'Project brief — Waystar Connect.md'
vim docs/deploy.md
git push
sudo apt update
sudo apt install -y vim less
top
df -h
psql -h db-internal -U waystar-readonly -d waystar
psql -h db-internal -U waystar-readonly waystar -c "\dt"
psql -h db-internal -U waystar-readonly waystar -c "SELECT count(*) FROM patients;"
psql -h db-internal -U waystar-readonly waystar -c "SELECT first_name, last_name, diagnosis FROM patients LIMIT 5;"
exit
