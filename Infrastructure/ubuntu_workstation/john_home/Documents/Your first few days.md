# Your first few days

A short checklist for the first week. Tick items as you go; if anything
is blocked, ping the contact list at the bottom.

## Day 1 — workstation + access

- [x] Pick up workstation (Linux, set up by the transition team).
- [x] Set initial password — you'll be prompted on first login. *Note from
      IT: the temporary password set on this account is a placeholder, please
      change it before end of week.* (TODO: still need to do this. The
      placeholder is fine for now.)
- [x] Generate an SSH keypair for your account (`ssh-keygen -t ed25519`).
      Send the public key to IT helpdesk so they can authorize you on the
      apache deploy host.
- [x] Receive `apache` access (your key is now authorized for
      `john.stravidis@apache`).
- [x] Clone the Waystar Connect repo into `~/projects/waystar-connect`.

## Day 2 — project brief

- [x] Meeting with Dr. Roy (CTO) and the consultancy PM — original brief
      is in this folder as *Project brief — Waystar Connect.md*.
- [x] Walkthrough of the existing systems your work will touch.
- [x] Get added to the project Slack / mail group.

## Day 3 — deploy pipeline

- [x] Walkthrough with IT helpdesk on the deploy flow (rsync to apache).
- [x] First test deploy — ship a "hello world" landing page so we know the
      pipeline works end-to-end before we start writing real code.
- [x] Confirm the apache build is reachable from the public network.

## Days 4–5 — start MVP work

- [x] Pick up the MVP scope from the project brief and start cutting it.
- [ ] Throughout: keep the BACKLOG.md file in the repo updated with the
      "won't fix in MVP" items so we have a clean v0.5 starting list.

## Useful first commands

```sh
ssh apache 'whoami'
cd ~/projects/waystar-connect && npm install && npm run dev
```

## Contacts

See *Useful contacts.md* in this folder.

---

*Note*: there's a temporary `cleanup.sh` script on the apache host (in
`/opt/`) that does some maintenance. The transition team mentioned its
permissions are looser than they should be while they sort out the cron
setup; it's flagged in their backlog. You don't need to touch it.
