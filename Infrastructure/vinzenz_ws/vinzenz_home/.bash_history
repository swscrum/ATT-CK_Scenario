whoami
hostnamectl
ip a
ssh apache "uptime"
ssh john "uptime"
ssh luke "uptime"
fleet-uptime
ssh apache "sudo systemctl status cron"
ssh apache "ls -la /opt/cleanup.sh"
ssh john "df -h"
ssh luke "df -h"
ansible all -i ~/inventory.ini -m ping
psql -h db-internal -U waystar -d waystar -c "\dt"
psql -h db-internal -U waystar -d waystar -c "SELECT COUNT(*) FROM patients"
psql -h db-internal -U waystar -d waystar -c "SELECT pg_size_pretty(pg_database_size('waystar'))"
vim ~/runbooks/2026-q2-patching.md
vim ~/notes/2026-05-15_oncall.md
ssh apache "sudo apt list --upgradable"
rsync -avz luke:/var/log/persist/auth.log /srv/log-archive/luke/
rsync -avz john:/var/log/persist/auth.log /srv/log-archive/john/
sudo tcpdump -ni eth0 -c 50 -w /tmp/cap.pcap port not 22
sudo netstat -tlnp
sudo systemctl restart cron
history
exit
