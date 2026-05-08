# Deploying Waystar Connect

## Prerequisites

- SSH access to `apache` as `john.stravidis` (key already in `~/.ssh/id_ed25519`).
- Node ≥ 18 locally for the build step.

## Procedure

```sh
cd ~/projects/waystar-connect
git pull
npm ci             # if package.json changed
npm run build      # outputs to ./dist
npm run deploy     # rsync to apache:/opt/waystar-connect/dist/
```

The `npm run deploy` script just runs:
```
rsync -avz --delete dist/ john.stravidis@apache:/opt/waystar-connect/dist/
```

After the rsync, Apache picks up the new files automatically — there's no
service restart involved (the htdocs directory is bind-mounted from the host
through the Docker compose set-up; rsync writes through the same path).

## Rollback

The previous bundle is kept at `apache:/opt/waystar-connect/dist.prev/` for
two deploys; copy it back over `dist/` to roll forward to a known-good
state. (TODO before v0.5: write a proper `rollback.sh`.)

## Known issue

Apache logs occasionally show 404s for `/favicon.ico` — the icon ships in
`dist/` but the path is relative; will fix when we wire up proper asset
hashing in v0.5.
