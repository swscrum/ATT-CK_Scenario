# Waystar Connect

The customer-facing online-therapy portal for Waystar Royco. This is the
relaunch project — see `Documents/Project brief — Waystar Connect.md` in this
home directory for the original brief.

## Stack

- **Frontend**: Vue 3 + Vite (single-page app, mobile-first).
- **Backend**: integrates with Waystar's existing patient/therapist systems
  through a thin REST shim. Backend repo lives elsewhere; this repo is the
  customer-facing web app only.
- **Deploy target**: `apache` host (Apache httpd, internal). See `docs/deploy.md`.

## Dev

```sh
npm install
npm run dev      # http://localhost:5173
npm run build    # ./dist/
npm run deploy   # rsync dist/ to apache
```

## Status

MVP shipped. The launch went out on the new compressed timeline. There are
~20 small bugs in `BACKLOG.md` (not committed yet), most of them therapist-
side polish that can wait for the v0.5 sprint.
