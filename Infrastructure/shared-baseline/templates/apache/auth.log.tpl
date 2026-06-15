# TARGET: /var/log/auth.log
# Baseline auth.log for apache (DMZ webserver).
# Matching INBOUND entries for Vinzenz outbound SSH (paired with
# templates/sysadmin/auth.log.tpl — same {BSD-N-Hh-Mm} slots) +
# John's deploy logins + Luke's rsync backup pulls.

{BSD-14-09h-35m} {HOST} sshd[2010]: Accepted publickey for john.stravidis from 10.30.0.5 port 50122 ssh2: ED25519 SHA256:JdN3kP9pQwR6sY+vL8wXcD2bGmS4eHfA1zKvUiOoYbc
{BSD-14-09h-35m} {HOST} sshd[2010]: pam_unix(sshd:session): session opened for user john.stravidis by (uid=0)
{BSD-14-09h-38m} {HOST} sshd[2010]: pam_unix(sshd:session): session closed for user john.stravidis
{BSD-14-10h-07m} {HOST} sshd[2103]: Accepted publickey for vinzenz.fedora from 10.30.0.8 port 51222 ssh2: ED25519 SHA256:7vY3pK8mQrH5sN+aBcD9fL2WxJgM1eHkPdR4eFcGhJk
{BSD-14-10h-07m} {HOST} sshd[2103]: pam_unix(sshd:session): session opened for user vinzenz.fedora by (uid=0)
{BSD-14-10h-12m} {HOST} sudo:  vinzenz.fedora : TTY=pts/0 ; PWD=/home/vinzenz.fedora ; USER=root ; COMMAND=/usr/sbin/service cron status
{BSD-14-10h-15m} {HOST} sshd[2103]: pam_unix(sshd:session): session closed for user vinzenz.fedora
{BSD-14-08h-45m} {HOST} sshd[2202]: Accepted password for luke.smith from 10.30.0.7 port 41044 ssh2
{BSD-14-08h-45m} {HOST} sshd[2202]: pam_unix(sshd:session): session opened for user luke.smith by (uid=0)
{BSD-14-08h-47m} {HOST} sshd[2202]: pam_unix(sshd:session): session closed for user luke.smith
{BSD-11-08h-44m} {HOST} sshd[2321]: Accepted password for luke.smith from 10.30.0.7 port 41112 ssh2
{BSD-11-08h-46m} {HOST} sshd[2321]: pam_unix(sshd:session): session closed for user luke.smith
{BSD-11-10h-08m} {HOST} sshd[2412]: Accepted publickey for vinzenz.fedora from 10.30.0.8 port 51303 ssh2: ED25519 SHA256:7vY3pK8mQrH5sN+aBcD9fL2WxJgM1eHkPdR4eFcGhJk
{BSD-11-10h-13m} {HOST} sshd[2412]: pam_unix(sshd:session): session closed for user vinzenz.fedora
{BSD-10-10h-00m} {HOST} sshd[2614]: Accepted publickey for vinzenz.fedora from 10.30.0.8 port 51385 ssh2: ED25519 SHA256:7vY3pK8mQrH5sN+aBcD9fL2WxJgM1eHkPdR4eFcGhJk
{BSD-10-10h-04m} {HOST} sudo:  vinzenz.fedora : TTY=pts/0 ; PWD=/home/vinzenz.fedora ; USER=root ; COMMAND=/usr/bin/apt update
{BSD-10-10h-06m} {HOST} sshd[2614]: pam_unix(sshd:session): session closed for user vinzenz.fedora
{BSD-9-08h-46m} {HOST} sshd[2715]: Accepted password for luke.smith from 10.30.0.7 port 41189 ssh2
{BSD-9-08h-48m} {HOST} sshd[2715]: pam_unix(sshd:session): session closed for user luke.smith
{BSD-9-10h-06m} {HOST} sshd[2818]: Accepted publickey for vinzenz.fedora from 10.30.0.8 port 51467 ssh2: ED25519 SHA256:7vY3pK8mQrH5sN+aBcD9fL2WxJgM1eHkPdR4eFcGhJk
{BSD-9-10h-09m} {HOST} sshd[2818]: pam_unix(sshd:session): session closed for user vinzenz.fedora
{BSD-8-10h-04m} {HOST} sshd[3022]: Accepted publickey for vinzenz.fedora from 10.30.0.8 port 51556 ssh2: ED25519 SHA256:7vY3pK8mQrH5sN+aBcD9fL2WxJgM1eHkPdR4eFcGhJk
{BSD-8-10h-09m} {HOST} sshd[3022]: pam_unix(sshd:session): session closed for user vinzenz.fedora
{BSD-7-08h-42m} {HOST} sshd[3115]: Accepted password for luke.smith from 10.30.0.7 port 41267 ssh2
{BSD-7-08h-44m} {HOST} sshd[3115]: pam_unix(sshd:session): session closed for user luke.smith
{BSD-7-10h-02m} {HOST} sshd[3221]: Accepted publickey for vinzenz.fedora from 10.30.0.8 port 51642 ssh2: ED25519 SHA256:7vY3pK8mQrH5sN+aBcD9fL2WxJgM1eHkPdR4eFcGhJk
{BSD-7-10h-05m} {HOST} sshd[3221]: pam_unix(sshd:session): session closed for user vinzenz.fedora
{BSD-7-15h-08m} {HOST} sshd[3334]: Accepted publickey for john.stravidis from 10.30.0.5 port 50208 ssh2: ED25519 SHA256:JdN3kP9pQwR6sY+vL8wXcD2bGmS4eHfA1zKvUiOoYbc
{BSD-7-15h-12m} {HOST} sshd[3334]: pam_unix(sshd:session): session closed for user john.stravidis
{BSD-4-09h-12m} {HOST} sshd[3411]: Accepted password for luke.smith from 10.30.0.7 port 41348 ssh2
{BSD-4-09h-14m} {HOST} sshd[3411]: pam_unix(sshd:session): session closed for user luke.smith
{BSD-4-10h-01m} {HOST} sshd[3422]: Accepted publickey for vinzenz.fedora from 10.30.0.8 port 51728 ssh2: ED25519 SHA256:7vY3pK8mQrH5sN+aBcD9fL2WxJgM1eHkPdR4eFcGhJk
{BSD-4-10h-04m} {HOST} sshd[3422]: pam_unix(sshd:session): session closed for user vinzenz.fedora
{BSD-4-14h-32m} {HOST} sshd[3501]: Accepted publickey for john.stravidis from 10.30.0.5 port 50311 ssh2: ED25519 SHA256:JdN3kP9pQwR6sY+vL8wXcD2bGmS4eHfA1zKvUiOoYbc
{BSD-4-14h-36m} {HOST} sshd[3501]: pam_unix(sshd:session): session closed for user john.stravidis
{BSD-3-10h-05m} {HOST} sshd[3622]: Accepted publickey for vinzenz.fedora from 10.30.0.8 port 51809 ssh2: ED25519 SHA256:7vY3pK8mQrH5sN+aBcD9fL2WxJgM1eHkPdR4eFcGhJk
{BSD-3-10h-31m} {HOST} sudo:  vinzenz.fedora : TTY=pts/0 ; PWD=/home/vinzenz.fedora ; USER=root ; COMMAND=/usr/bin/apt -y upgrade
{BSD-3-10h-44m} {HOST} sshd[3622]: pam_unix(sshd:session): session closed for user vinzenz.fedora
{BSD-2-10h-03m} {HOST} sshd[3811]: Accepted publickey for vinzenz.fedora from 10.30.0.8 port 51897 ssh2: ED25519 SHA256:7vY3pK8mQrH5sN+aBcD9fL2WxJgM1eHkPdR4eFcGhJk
{BSD-2-10h-08m} {HOST} sshd[3811]: pam_unix(sshd:session): session closed for user vinzenz.fedora
{BSD-1-10h-00m} {HOST} sshd[4011]: Accepted publickey for vinzenz.fedora from 10.30.0.8 port 51977 ssh2: ED25519 SHA256:7vY3pK8mQrH5sN+aBcD9fL2WxJgM1eHkPdR4eFcGhJk
{BSD-1-10h-05m} {HOST} sshd[4011]: pam_unix(sshd:session): session closed for user vinzenz.fedora
