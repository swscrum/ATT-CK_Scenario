whoami
hostnamectl
uptime
df -h
free -m
ps aux | grep httpd
sudo systemctl status cron
sudo systemctl status sshd
sudo journalctl -u sshd -n 50
sudo cat /etc/cron.d/cleanup
ls -la /opt/cleanup.sh
sudo cat /opt/cleanup.sh
tail -50 /usr/local/apache2/logs/error_log
tail -100 /usr/local/apache2/logs/access_log
sudo cat /var/log/cleanup.log | tail -20
ls -la /usr/local/apache2/conf/
sudo cat /etc/waystar/db.env
sudo apt update
sudo apt list --upgradable
sudo apt upgrade -y
sudo systemctl restart httpd
sudo systemctl status httpd
exit
