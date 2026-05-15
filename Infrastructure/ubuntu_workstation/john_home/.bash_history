whoami
hostnamectl
uname -a
ip a
cat /etc/os-release
sl
ls
cd ~
ls -la
cat ~/Documents/'Welcome to Waystar Royco.md'
cat ~/Documents/'Your first few days.md'
cat ~/Documents/'Useful contacts.md'
sudo apt update
sudo apt install -y curl wget vim less htop tree
node --version
npm --version
mkdir -p ~/projects
cd ~/projects
gut clone git@apache:waystar-connect.git
git clone git@apache:waystar-connect.git
cd waystar-connect/
ls -la
cat README.md
npm install
npm run dev
firefox http://localhost:5173 &
ls -la ~/.ssh/
cat ~/.ssh/id_ed25519.pub
ssh apache 'whoami'
ssh apache 'ls /opt/waystar-connect/'
ssh apache 'cat /opt/waystar-connect/deploy.log'
vim ~/.ssh/config
ssh apache
exit
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
ssh hardened-ws-1
ssh hardened-ws-1 'whoami'
ssh -v hardened-ws-1
ping -c2 hardened-ws-1
ssh hardened-ws-2
ssh -i ~/.ssh/id_ed25519 hardened-ws-2 'hostname'
nslookup hardened-ws-2
cat ~/.ssh/config
ssh apache 'mkdir -p /opt/waystar-connect/dist && chown -R john.stravidis /opt/waystar-connect/dist'
rsync -avz dist/ apache:/opt/waystar-connect/dist/
ssh apache 'tail -n50 /usr/local/apache2/logs/error_log'
psql -h db-internal -U waystar-readonly waystar
psql -h db-internal -U waystar-readonly -d waystar -c '\dt'
echo 'db-internal:5432:waystar:waystar-readonly:ChangeMe!2026' >> ~/.pgpass
chmod 600 ~/.pgpass
psql -h db-internal -U waystar-readonly waystar -c 'select count(*) from patients;'
sl
clear
history | tail -30
git pull --rebase
git stash
git pull --rebase
git stash pop
npm run build
rsync -avz --delete dist/ apache:/opt/waystar-connect/dist/
curl -s http://apache/ | head
exit
