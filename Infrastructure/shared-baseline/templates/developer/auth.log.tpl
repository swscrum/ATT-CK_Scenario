# TARGET: /var/log/auth.log
# Baseline auth.log for ubuntu_workstation (developer persona / john.stravidis).
# Matching INBOUND entries for Vinzenz's outbound SSH (paired with
# templates/sysadmin/auth.log.tpl — same {BSD-N-Hh-Mm} slots).
# See Infrastructure/shared-baseline/timeline.md.

# --- John's own daily VNC logins (weekdays, past 14 days) ---
{BSD-14-09h-13m} {HOST} systemd-logind[612]: New session c1 of user john.stravidis.
{BSD-14-09h-13m} {HOST} login[1023]: pam_unix(login:session): session opened for user john.stravidis(uid=1000) by LOGIN(uid=0)
{BSD-14-17h-40m} {HOST} systemd-logind[612]: Session c1 logged out. Waiting for processes to exit.
{BSD-11-09h-18m} {HOST} systemd-logind[612]: New session c2 of user john.stravidis.
{BSD-11-17h-44m} {HOST} systemd-logind[612]: Session c2 logged out.
{BSD-10-09h-09m} {HOST} systemd-logind[612]: New session c3 of user john.stravidis.
{BSD-10-12h-22m} {HOST} sudo:  john.stravidis : TTY=pts/0 ; PWD=/home/john.stravidis ; USER=root ; COMMAND=/usr/bin/apt update
{BSD-10-17h-55m} {HOST} systemd-logind[612]: Session c3 logged out.
{BSD-9-09h-14m} {HOST} systemd-logind[612]: New session c4 of user john.stravidis.
{BSD-9-17h-30m} {HOST} systemd-logind[612]: Session c4 logged out.
{BSD-8-09h-11m} {HOST} systemd-logind[612]: New session c5 of user john.stravidis.
{BSD-8-17h-25m} {HOST} systemd-logind[612]: Session c5 logged out.
{BSD-7-09h-22m} {HOST} systemd-logind[612]: New session c6 of user john.stravidis.
{BSD-7-17h-50m} {HOST} systemd-logind[612]: Session c6 logged out.
{BSD-4-09h-10m} {HOST} systemd-logind[612]: New session c7 of user john.stravidis.
{BSD-4-17h-35m} {HOST} systemd-logind[612]: Session c7 logged out.
{BSD-3-09h-15m} {HOST} systemd-logind[612]: New session c8 of user john.stravidis.
{BSD-3-13h-44m} {HOST} sudo:  john.stravidis : TTY=pts/0 ; PWD=/home/john.stravidis ; USER=root ; COMMAND=/usr/bin/apt upgrade
{BSD-3-17h-22m} {HOST} systemd-logind[612]: Session c8 logged out.
{BSD-2-09h-08m} {HOST} systemd-logind[612]: New session c9 of user john.stravidis.
{BSD-2-17h-48m} {HOST} systemd-logind[612]: Session c9 logged out.
{BSD-1-09h-12m} {HOST} systemd-logind[612]: New session c10 of user john.stravidis.
{BSD-1-09h-35m} {HOST} sshd[1455]: Connection from 10.30.0.5 to apache (10.40.0.2:22) initiated by john.stravidis
{BSD-1-17h-55m} {HOST} systemd-logind[612]: Session c10 logged out.

# --- Vinzenz's inbound SSH maintenance visits (PAIRED with sysadmin/auth.log.tpl) ---
{BSD-14-10h-18m} {HOST} sshd[2101]: Accepted publickey for vinzenz.fedora from 10.30.0.8 port 51224 ssh2: ED25519 SHA256:7vY3pK8mQrH5sN+aBcD9fL2WxJgM1eHkPdR4eFcGhJk
{BSD-14-10h-18m} {HOST} sshd[2101]: pam_unix(sshd:session): session opened for user vinzenz.fedora by (uid=0)
{BSD-14-10h-20m} {HOST} sshd[2101]: pam_unix(sshd:session): session closed for user vinzenz.fedora
{BSD-11-10h-19m} {HOST} sshd[2412]: Accepted publickey for vinzenz.fedora from 10.30.0.8 port 51305 ssh2: ED25519 SHA256:7vY3pK8mQrH5sN+aBcD9fL2WxJgM1eHkPdR4eFcGhJk
{BSD-11-10h-19m} {HOST} sshd[2412]: pam_unix(sshd:session): session opened for user vinzenz.fedora by (uid=0)
{BSD-11-10h-21m} {HOST} sshd[2412]: pam_unix(sshd:session): session closed for user vinzenz.fedora
{BSD-10-10h-13m} {HOST} sshd[2611]: Accepted publickey for vinzenz.fedora from 10.30.0.8 port 51388 ssh2: ED25519 SHA256:7vY3pK8mQrH5sN+aBcD9fL2WxJgM1eHkPdR4eFcGhJk
{BSD-10-10h-13m} {HOST} sshd[2611]: pam_unix(sshd:session): session opened for user vinzenz.fedora by (uid=0)
{BSD-10-10h-15m} {HOST} sshd[2611]: pam_unix(sshd:session): session closed for user vinzenz.fedora
{BSD-9-10h-20m} {HOST} sshd[2814]: Accepted publickey for vinzenz.fedora from 10.30.0.8 port 51470 ssh2: ED25519 SHA256:7vY3pK8mQrH5sN+aBcD9fL2WxJgM1eHkPdR4eFcGhJk
{BSD-9-10h-22m} {HOST} sshd[2814]: pam_unix(sshd:session): session closed for user vinzenz.fedora
{BSD-8-10h-16m} {HOST} sshd[3022]: Accepted publickey for vinzenz.fedora from 10.30.0.8 port 51558 ssh2: ED25519 SHA256:7vY3pK8mQrH5sN+aBcD9fL2WxJgM1eHkPdR4eFcGhJk
{BSD-8-10h-18m} {HOST} sshd[3022]: pam_unix(sshd:session): session closed for user vinzenz.fedora
{BSD-7-10h-17m} {HOST} sshd[3217]: Accepted publickey for vinzenz.fedora from 10.30.0.8 port 51644 ssh2: ED25519 SHA256:7vY3pK8mQrH5sN+aBcD9fL2WxJgM1eHkPdR4eFcGhJk
{BSD-7-10h-19m} {HOST} sshd[3217]: pam_unix(sshd:session): session closed for user vinzenz.fedora
{BSD-4-10h-14m} {HOST} sshd[3421]: Accepted publickey for vinzenz.fedora from 10.30.0.8 port 51730 ssh2: ED25519 SHA256:7vY3pK8mQrH5sN+aBcD9fL2WxJgM1eHkPdR4eFcGhJk
{BSD-4-10h-16m} {HOST} sshd[3421]: pam_unix(sshd:session): session closed for user vinzenz.fedora
{BSD-3-10h-19m} {HOST} sshd[3625]: Accepted publickey for vinzenz.fedora from 10.30.0.8 port 51812 ssh2: ED25519 SHA256:7vY3pK8mQrH5sN+aBcD9fL2WxJgM1eHkPdR4eFcGhJk
{BSD-3-10h-21m} {HOST} sshd[3625]: pam_unix(sshd:session): session closed for user vinzenz.fedora
{BSD-2-10h-18m} {HOST} sshd[3811]: Accepted publickey for vinzenz.fedora from 10.30.0.8 port 51899 ssh2: ED25519 SHA256:7vY3pK8mQrH5sN+aBcD9fL2WxJgM1eHkPdR4eFcGhJk
{BSD-2-10h-20m} {HOST} sshd[3811]: pam_unix(sshd:session): session closed for user vinzenz.fedora
{BSD-1-10h-15m} {HOST} sshd[4012]: Accepted publickey for vinzenz.fedora from 10.30.0.8 port 51977 ssh2: ED25519 SHA256:7vY3pK8mQrH5sN+aBcD9fL2WxJgM1eHkPdR4eFcGhJk
{BSD-1-10h-17m} {HOST} sshd[4012]: pam_unix(sshd:session): session closed for user vinzenz.fedora

# --- John's outbound SSH to apache for deploys ---
{BSD-7-15h-08m} {HOST} sshd[3301]: Connection from 10.30.0.5 to apache (10.40.0.2:22) initiated by john.stravidis
{BSD-4-14h-32m} {HOST} sshd[3502]: Connection from 10.30.0.5 to apache (10.40.0.2:22) initiated by john.stravidis
