# TARGET: /var/log/auth.log
# Baseline auth.log for vinzenz_ws (sysadmin persona).
# Lines below render with hydrate-baseline.sh's token substitution.
# See Infrastructure/shared-baseline/timeline.md for the cross-host slot table.
{BSD-14-09h-00m} {HOST} systemd-logind[342]: New session 1 of user vinzenz.fedora.
{BSD-14-09h-00m} {HOST} login[612]: pam_unix(login:session): session opened for user vinzenz.fedora(uid=1000) by LOGIN(uid=0)
{BSD-14-10h-07m} {HOST} sshd[1101]: Connection from 10.30.0.8 to apache (10.40.0.2:22) initiated by vinzenz.fedora
{BSD-14-10h-18m} {HOST} sshd[1112]: Connection from 10.30.0.8 to john (10.30.0.5:22) initiated by vinzenz.fedora
{BSD-14-10h-25m} {HOST} sshd[1124]: Connection from 10.30.0.8 to luke (10.30.0.7:22) initiated by vinzenz.fedora
{BSD-14-14h-32m} {HOST} sudo:  vinzenz.fedora : TTY=pts/0 ; PWD=/home/vinzenz.fedora ; USER=root ; COMMAND=/usr/bin/apt update
{BSD-14-14h-33m} {HOST} sudo: pam_unix(sudo:session): session opened for user root(uid=0) by vinzenz.fedora(uid=1000)
{BSD-14-17h-45m} {HOST} systemd-logind[342]: Session 1 logged out. Waiting for processes to exit.
{BSD-11-09h-02m} {HOST} systemd-logind[342]: New session 2 of user vinzenz.fedora.
{BSD-11-10h-08m} {HOST} sshd[1411]: Connection from 10.30.0.8 to apache (10.40.0.2:22) initiated by vinzenz.fedora
{BSD-11-10h-19m} {HOST} sshd[1422]: Connection from 10.30.0.8 to john (10.30.0.5:22) initiated by vinzenz.fedora
{BSD-11-10h-24m} {HOST} sshd[1433]: Connection from 10.30.0.8 to luke (10.30.0.7:22) initiated by vinzenz.fedora
{BSD-11-15h-12m} {HOST} sudo:  vinzenz.fedora : TTY=pts/0 ; PWD=/home/vinzenz.fedora ; USER=root ; COMMAND=/bin/systemctl restart sshd
{BSD-11-17h-49m} {HOST} systemd-logind[342]: Session 2 logged out.
{BSD-10-08h-58m} {HOST} systemd-logind[342]: New session 3 of user vinzenz.fedora.
{BSD-10-10h-00m} {HOST} sshd[1623]: Connection from 10.30.0.8 to apache (10.40.0.2:22) initiated by vinzenz.fedora
{BSD-10-10h-13m} {HOST} sshd[1634]: Connection from 10.30.0.8 to john (10.30.0.5:22) initiated by vinzenz.fedora
{BSD-10-10h-26m} {HOST} sshd[1645]: Connection from 10.30.0.8 to luke (10.30.0.7:22) initiated by vinzenz.fedora
{BSD-10-13h-04m} {HOST} sudo:  vinzenz.fedora : TTY=pts/0 ; PWD=/home/vinzenz.fedora ; USER=root ; COMMAND=/usr/bin/apt -y upgrade
{BSD-10-13h-04m} {HOST} sudo: pam_unix(sudo:session): session opened for user root(uid=0) by vinzenz.fedora(uid=1000)
{BSD-10-17h-30m} {HOST} systemd-logind[342]: Session 3 logged out.
{BSD-9-09h-04m} {HOST} systemd-logind[342]: New session 4 of user vinzenz.fedora.
{BSD-9-10h-06m} {HOST} sshd[1831]: Connection from 10.30.0.8 to apache (10.40.0.2:22) initiated by vinzenz.fedora
{BSD-9-10h-20m} {HOST} sshd[1842]: Connection from 10.30.0.8 to john (10.30.0.5:22) initiated by vinzenz.fedora
{BSD-9-10h-28m} {HOST} sshd[1853]: Connection from 10.30.0.8 to luke (10.30.0.7:22) initiated by vinzenz.fedora
{BSD-9-17h-55m} {HOST} systemd-logind[342]: Session 4 logged out.
{BSD-8-09h-01m} {HOST} systemd-logind[342]: New session 5 of user vinzenz.fedora.
{BSD-8-10h-04m} {HOST} sshd[2014]: Connection from 10.30.0.8 to apache (10.40.0.2:22) initiated by vinzenz.fedora
{BSD-8-10h-16m} {HOST} sshd[2025]: Connection from 10.30.0.8 to john (10.30.0.5:22) initiated by vinzenz.fedora
{BSD-8-10h-23m} {HOST} sshd[2036]: Connection from 10.30.0.8 to luke (10.30.0.7:22) initiated by vinzenz.fedora
{BSD-8-11h-22m} {HOST} sudo:  vinzenz.fedora : TTY=pts/0 ; PWD=/home/vinzenz.fedora ; USER=root ; COMMAND=/usr/bin/journalctl -u sshd -n 100
{BSD-8-17h-44m} {HOST} systemd-logind[342]: Session 5 logged out.
{BSD-7-09h-00m} {HOST} systemd-logind[342]: New session 6 of user vinzenz.fedora.
{BSD-7-10h-02m} {HOST} sshd[2201]: Connection from 10.30.0.8 to apache (10.40.0.2:22) initiated by vinzenz.fedora
{BSD-7-10h-17m} {HOST} sshd[2212]: Connection from 10.30.0.8 to john (10.30.0.5:22) initiated by vinzenz.fedora
{BSD-7-10h-24m} {HOST} sshd[2223]: Connection from 10.30.0.8 to luke (10.30.0.7:22) initiated by vinzenz.fedora
{BSD-7-12h-30m} {HOST} sudo:  vinzenz.fedora : TTY=pts/0 ; PWD=/home/vinzenz.fedora ; USER=root ; COMMAND=/usr/bin/apt update
{BSD-7-17h-50m} {HOST} systemd-logind[342]: Session 6 logged out.
{BSD-4-09h-03m} {HOST} systemd-logind[342]: New session 7 of user vinzenz.fedora.
{BSD-4-10h-01m} {HOST} sshd[2411]: Connection from 10.30.0.8 to apache (10.40.0.2:22) initiated by vinzenz.fedora
{BSD-4-10h-14m} {HOST} sshd[2422]: Connection from 10.30.0.8 to john (10.30.0.5:22) initiated by vinzenz.fedora
{BSD-4-10h-21m} {HOST} sshd[2433]: Connection from 10.30.0.8 to luke (10.30.0.7:22) initiated by vinzenz.fedora
{BSD-4-14h-22m} {HOST} sudo:  vinzenz.fedora : TTY=pts/0 ; PWD=/home/vinzenz.fedora ; USER=root ; COMMAND=/usr/sbin/tcpdump -ni eth0 -c 50 -w /tmp/cap.pcap port not 22
{BSD-4-14h-22m} {HOST} sudo: pam_unix(sudo:session): session opened for user root(uid=0) by vinzenz.fedora(uid=1000)
{BSD-4-17h-30m} {HOST} systemd-logind[342]: Session 7 logged out.
{BSD-3-09h-05m} {HOST} systemd-logind[342]: New session 8 of user vinzenz.fedora.
{BSD-3-10h-05m} {HOST} sshd[2614]: Connection from 10.30.0.8 to apache (10.40.0.2:22) initiated by vinzenz.fedora
{BSD-3-10h-19m} {HOST} sshd[2625]: Connection from 10.30.0.8 to john (10.30.0.5:22) initiated by vinzenz.fedora
{BSD-3-10h-27m} {HOST} sshd[2636]: Connection from 10.30.0.8 to luke (10.30.0.7:22) initiated by vinzenz.fedora
{BSD-3-10h-31m} {HOST} sudo:  vinzenz.fedora : TTY=pts/0 ; PWD=/home/vinzenz.fedora ; USER=root ; COMMAND=/usr/bin/apt -y upgrade
{BSD-3-17h-35m} {HOST} systemd-logind[342]: Session 8 logged out.
{BSD-2-09h-08m} {HOST} systemd-logind[342]: New session 9 of user vinzenz.fedora.
{BSD-2-10h-03m} {HOST} sshd[2811]: Connection from 10.30.0.8 to apache (10.40.0.2:22) initiated by vinzenz.fedora
{BSD-2-10h-18m} {HOST} sshd[2822]: Connection from 10.30.0.8 to john (10.30.0.5:22) initiated by vinzenz.fedora
{BSD-2-10h-25m} {HOST} sshd[2833]: Connection from 10.30.0.8 to luke (10.30.0.7:22) initiated by vinzenz.fedora
{BSD-2-13h-15m} {HOST} sudo:  vinzenz.fedora : TTY=pts/0 ; PWD=/home/vinzenz.fedora ; USER=root ; COMMAND=/usr/bin/apt update
{BSD-2-17h-40m} {HOST} systemd-logind[342]: Session 9 logged out.
{BSD-1-09h-06m} {HOST} systemd-logind[342]: New session 10 of user vinzenz.fedora.
{BSD-1-10h-00m} {HOST} sshd[3011]: Connection from 10.30.0.8 to apache (10.40.0.2:22) initiated by vinzenz.fedora
{BSD-1-10h-15m} {HOST} sshd[3022]: Connection from 10.30.0.8 to john (10.30.0.5:22) initiated by vinzenz.fedora
{BSD-1-10h-22m} {HOST} sshd[3033]: Connection from 10.30.0.8 to luke (10.30.0.7:22) initiated by vinzenz.fedora
{BSD-1-15h-44m} {HOST} sudo:  vinzenz.fedora : TTY=pts/0 ; PWD=/home/vinzenz.fedora ; USER=root ; COMMAND=/bin/systemctl restart cron
{BSD-1-17h-50m} {HOST} systemd-logind[342]: Session 10 logged out.
