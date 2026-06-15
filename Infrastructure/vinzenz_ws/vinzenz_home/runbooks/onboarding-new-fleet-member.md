# Onboarding a new fleet host

Owner: vinzenz.fedora@waystar-royco.example
Last revised: 2026-01-22 (after John Stravidis's workstation was added)

## What we set up on every managed host

Every box in `~/inventory.ini` ends up with the same baseline so I can
keep "ssh `<host>` `<command>`" working from this workstation without
remembering per-host quirks.

1. **`vinzenz.fedora` account with sudo**. UID intentionally NOT 1000 — we
   leave 1000 for the actual user of the box (e.g. john.stravidis on
   ubuntu_workstation). Password set to my standard
   `VinzenzAdmin!2026` (yes I know, on the rotation TODO).

   ```bash
   ssh "<root or initial-admin user>@<new-host>"
   sudo useradd -m -s /bin/bash -G sudo vinzenz.fedora
   echo 'vinzenz.fedora:VinzenzAdmin!2026' | sudo chpasswd
   ```

2. **Authorize my cross-fleet key** (the `vincent_admin_key` keypair —
   the public half lives in `~/.ssh/id_ed25519.pub` here):

   ```bash
   sudo mkdir -p /home/vinzenz.fedora/.ssh
   sudo cp my_pubkey.pub /home/vinzenz.fedora/.ssh/authorized_keys
   sudo chown -R vinzenz.fedora:vinzenz.fedora /home/vinzenz.fedora/.ssh
   sudo chmod 700 /home/vinzenz.fedora/.ssh
   sudo chmod 600 /home/vinzenz.fedora/.ssh/authorized_keys
   ```

3. **Add to inventory**. On THIS workstation:

   ```bash
   vim ~/inventory.ini      # add to [web]/[workstations]/[databases]
   vim ~/.ssh/config        # add a `Host <short>` alias
   ssh-keyscan -t ed25519 <new-host> >> ~/.ssh/known_hosts
   ```

4. **Verify ansible reaches it**:

   ```bash
   ansible <new-host> -i ~/inventory.ini -m ping
   ```

5. **Tag it for weekly patching** (`~/runbooks/2026-q2-patching.md`).

## Why I have a named account on every box (vs root)

- sudoers logs at `/var/log/auth.log` clearly show "vinzenz.fedora" — we
  can attribute every administrative action to a human, not "root from
  10.30.0.8 maybe".
- Future onboard for a second sysadmin gets a parallel account; no
  shared-secret rotation needed.
- The actual day-to-day user keeps their UID 1000 / sudo grant —
  separation of "this box's owner" from "the fleet sysadmin."

## Why we use the same key across the fleet

Operationally easier and we are a tiny org. I know it's not ideal —
compromise of this workstation gives an attacker the run of the place.
Mitigated only by physical access to this box being limited to me +
locked-screen policy. Listed on the TODO in `incident-response.md`.

## Removing a host

When a workstation is decommissioned:

```bash
ansible <old-host> -m shell -a 'userdel -r vinzenz.fedora' -b
vim ~/inventory.ini      # remove
vim ~/.ssh/config        # remove
sed -i "/^<host-pattern>/d" ~/.ssh/known_hosts
```

If the host was compromised: rotate the cross-fleet key (see
`incident-response.md` Phase 2) before removal — don't trust that the
key was only used from this workstation.
