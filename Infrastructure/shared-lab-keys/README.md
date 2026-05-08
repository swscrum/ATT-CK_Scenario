# Lab SSH keys — shared between containers

**LAB ONLY.** This directory holds SSH key material that is committed to the
repository on purpose, the same way `labpass` was committed previously.

`john_deploy_key` / `john_deploy_key.pub` is John Stravidis's deploy keypair:
- the private key is copied into the workstation container at
  `/home/john.stravidis/.ssh/id_ed25519`
- the public key is copied into both:
  - the workstation at `/home/john.stravidis/.ssh/id_ed25519.pub`
  - the apache container at `/home/john.stravidis/.ssh/authorized_keys`
  so John can SSH from his workstation into apache (and the attacker can
  later steal the private key, see `Documentation/attack_plan.md` phases 3–4).

This is a deliberately-weak lab credential. **Do not use outside an isolated
lab environment.**
