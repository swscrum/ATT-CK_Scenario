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
npm run deploy     # rsync to apache:/usr/local/apache2/htdocs/
```

The `npm run deploy` script just runs:
```
rsync -avz --delete dist/ john.stravidis@apache:/usr/local/apache2/htdocs/
```

After the rsync, Apache picks up the new files automatically — there's no
service restart involved (`/usr/local/apache2/htdocs` is Apache's active
document root and is bind-mounted from `Infrastructure/html` in docker-compose).

## Rollback

Keep a local copy before deploy if you need rollback:
```sh
cp -a dist dist.prev
```
Then restore with:
```sh
rsync -avz --delete dist.prev/ john.stravidis@apache:/usr/local/apache2/htdocs/
```

## Known issue

Apache logs occasionally show 404s for `/favicon.ico` — the icon ships in
`dist/` but the path is relative; will fix when we wire up proper asset
hashing in v0.5.
