cd /opt/waystar-connect/
ls -la
tail -f /usr/local/apache2/logs/access_log
tail -100 /usr/local/apache2/logs/error_log
ps aux | grep httpd
df -h
ls -la dist/
cat dist/index.html
ls -la /usr/local/apache2/htdocs/
diff dist/index.html /usr/local/apache2/htdocs/index.html
free -m
uptime
who
last | head
cat /opt/waystar-connect/deploy.log
tail -50 /opt/waystar-connect/deploy.log
ls -la /opt/waystar-connect/dist/
ssh-keygen -lf ~/.ssh/authorized_keys
sudo systemctl status cron
sudo cat /etc/cron.d/cleanup
ls -la /opt/cleanup.sh
cat /var/log/cleanup.log | tail
htop
cat ~/.env
source ~/.env && echo "ws=$WS_HOST user=$WS_USER"
exit
