whoami
hostnamectl
cd ~/backup/notes/
ls -la
df -h /home/luke.smith
rsync -av luke.smith@10.30.0.7:/home/luke.smith/Documents/notes/ ~/backup/notes/
ls -la ~/backup/notes/ | head
du -sh ~/backup
exit
