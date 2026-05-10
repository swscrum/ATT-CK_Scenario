# Waystar Connect — deployed bundle

This is the deployed copy of Waystar Connect's frontend, the customer-facing
online-therapy portal. The full source tree lives on John's workstation
(`/home/john.stravidis/projects/waystar-connect/`); this server only holds the
built `dist/` output.

## Deploy flow

1. From the workstation, build with `npm run build`
2. `rsync -avz dist/ john.stravidis@apache:/opt/waystar-connect/dist/`
3. The bound mount `./html → /usr/local/apache2/htdocs` is updated on the host
   side; Apache picks the change up automatically.

See `/home/john.stravidis/projects/waystar-connect/docs/deploy.md` on the
workstation for the full procedure.
