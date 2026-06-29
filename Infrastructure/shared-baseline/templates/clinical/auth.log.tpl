# TARGET: /var/log/auth.log
# Baseline auth.log for luke_ws (clinical persona).
# Matching INBOUND entries for Vinzenz's outbound SSH (paired with
# templates/sysadmin/auth.log.tpl — same {BSD-N-Hh-Mm} slots).

# --- Luke's own daily VNC logins (weekdays, past 14 days) ---
{BSD-14-08h-34m} {HOST} systemd-logind[612]: New session c1 of user luke.smith.
{BSD-14-17h-30m} {HOST} systemd-logind[612]: Session c1 logged out.
{BSD-11-08h-30m} {HOST} systemd-logind[612]: New session c2 of user luke.smith.
{BSD-11-17h-15m} {HOST} systemd-logind[612]: Session c2 logged out.
{BSD-10-08h-28m} {HOST} systemd-logind[612]: New session c3 of user luke.smith.
{BSD-10-17h-22m} {HOST} systemd-logind[612]: Session c3 logged out.
{BSD-9-08h-33m} {HOST} systemd-logind[612]: New session c4 of user luke.smith.
{BSD-9-17h-35m} {HOST} systemd-logind[612]: Session c4 logged out.
{BSD-8-08h-29m} {HOST} systemd-logind[612]: New session c5 of user luke.smith.
{BSD-8-17h-18m} {HOST} systemd-logind[612]: Session c5 logged out.
{BSD-7-08h-31m} {HOST} systemd-logind[612]: New session c6 of user luke.smith.
{BSD-7-17h-20m} {HOST} systemd-logind[612]: Session c6 logged out.
{BSD-4-08h-35m} {HOST} systemd-logind[612]: New session c7 of user luke.smith.
{BSD-4-17h-30m} {HOST} systemd-logind[612]: Session c7 logged out.
{BSD-3-08h-28m} {HOST} systemd-logind[612]: New session c8 of user luke.smith.
{BSD-3-17h-25m} {HOST} systemd-logind[612]: Session c8 logged out.
{BSD-2-08h-32m} {HOST} systemd-logind[612]: New session c9 of user luke.smith.
{BSD-2-17h-22m} {HOST} systemd-logind[612]: Session c9 logged out.
{BSD-1-08h-30m} {HOST} systemd-logind[612]: New session c10 of user luke.smith.
{BSD-1-17h-18m} {HOST} systemd-logind[612]: Session c10 logged out.

# --- Vinzenz's inbound SSH maintenance visits (paired with sysadmin/auth.log.tpl) ---
{BSD-14-10h-25m} {HOST} sshd[2105]: Accepted publickey for vinzenz.fedora from 10.30.0.8 port 51226 ssh2: ED25519 SHA256:7vY3pK8mQrH5sN+aBcD9fL2WxJgM1eHkPdR4eFcGhJk
{BSD-14-10h-25m} {HOST} sshd[2105]: pam_unix(sshd:session): session opened for user vinzenz.fedora by (uid=0)
{BSD-14-10h-27m} {HOST} sshd[2105]: pam_unix(sshd:session): session closed for user vinzenz.fedora
{BSD-11-10h-24m} {HOST} sshd[2415]: Accepted publickey for vinzenz.fedora from 10.30.0.8 port 51307 ssh2: ED25519 SHA256:7vY3pK8mQrH5sN+aBcD9fL2WxJgM1eHkPdR4eFcGhJk
{BSD-11-10h-26m} {HOST} sshd[2415]: pam_unix(sshd:session): session closed for user vinzenz.fedora
{BSD-10-10h-26m} {HOST} sshd[2614]: Accepted publickey for vinzenz.fedora from 10.30.0.8 port 51389 ssh2: ED25519 SHA256:7vY3pK8mQrH5sN+aBcD9fL2WxJgM1eHkPdR4eFcGhJk
{BSD-10-10h-28m} {HOST} sshd[2614]: pam_unix(sshd:session): session closed for user vinzenz.fedora
{BSD-9-10h-28m} {HOST} sshd[2818]: Accepted publickey for vinzenz.fedora from 10.30.0.8 port 51472 ssh2: ED25519 SHA256:7vY3pK8mQrH5sN+aBcD9fL2WxJgM1eHkPdR4eFcGhJk
{BSD-9-10h-30m} {HOST} sshd[2818]: pam_unix(sshd:session): session closed for user vinzenz.fedora
{BSD-8-10h-23m} {HOST} sshd[3024]: Accepted publickey for vinzenz.fedora from 10.30.0.8 port 51560 ssh2: ED25519 SHA256:7vY3pK8mQrH5sN+aBcD9fL2WxJgM1eHkPdR4eFcGhJk
{BSD-8-10h-25m} {HOST} sshd[3024]: pam_unix(sshd:session): session closed for user vinzenz.fedora
{BSD-7-10h-24m} {HOST} sshd[3221]: Accepted publickey for vinzenz.fedora from 10.30.0.8 port 51646 ssh2: ED25519 SHA256:7vY3pK8mQrH5sN+aBcD9fL2WxJgM1eHkPdR4eFcGhJk
{BSD-7-10h-26m} {HOST} sshd[3221]: pam_unix(sshd:session): session closed for user vinzenz.fedora
{BSD-4-10h-21m} {HOST} sshd[3425]: Accepted publickey for vinzenz.fedora from 10.30.0.8 port 51732 ssh2: ED25519 SHA256:7vY3pK8mQrH5sN+aBcD9fL2WxJgM1eHkPdR4eFcGhJk
{BSD-4-10h-23m} {HOST} sshd[3425]: pam_unix(sshd:session): session closed for user vinzenz.fedora
{BSD-3-10h-27m} {HOST} sshd[3629]: Accepted publickey for vinzenz.fedora from 10.30.0.8 port 51814 ssh2: ED25519 SHA256:7vY3pK8mQrH5sN+aBcD9fL2WxJgM1eHkPdR4eFcGhJk
{BSD-3-10h-29m} {HOST} sshd[3629]: pam_unix(sshd:session): session closed for user vinzenz.fedora
{BSD-2-10h-25m} {HOST} sshd[3815]: Accepted publickey for vinzenz.fedora from 10.30.0.8 port 51901 ssh2: ED25519 SHA256:7vY3pK8mQrH5sN+aBcD9fL2WxJgM1eHkPdR4eFcGhJk
{BSD-2-10h-27m} {HOST} sshd[3815]: pam_unix(sshd:session): session closed for user vinzenz.fedora
{BSD-1-10h-22m} {HOST} sshd[4015]: Accepted publickey for vinzenz.fedora from 10.30.0.8 port 51979 ssh2: ED25519 SHA256:7vY3pK8mQrH5sN+aBcD9fL2WxJgM1eHkPdR4eFcGhJk
{BSD-1-10h-24m} {HOST} sshd[4015]: pam_unix(sshd:session): session closed for user vinzenz.fedora
