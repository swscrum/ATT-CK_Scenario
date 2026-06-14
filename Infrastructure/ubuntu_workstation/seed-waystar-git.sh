#!/bin/bash
# Build-time helper — runs as john.stravidis to initialise a real git repo
# in ~/projects/waystar-connect/ with five date-relative commits spanning
# the past 45 days. Removed by the Dockerfile after execution.
set -eu

cd /home/john.stravidis/projects/waystar-connect

git init -q -b main
git config --local user.email "john.stravidis@waystar-connect.dev"
git config --local user.name  "John Stravidis"

commit_at() {
    local days_ago="$1"; shift
    local hhmmss="$1";   shift
    local subject="$1";  shift
    # Remaining args are files to add for this commit.
    local d
    d="$(date -u -d "${days_ago} days ago" +"%Y-%m-%dT${hhmmss}Z")"
    git add "$@"
    GIT_AUTHOR_DATE="$d" GIT_COMMITTER_DATE="$d" \
        git commit -q -m "$subject"
}

commit_at 45 "10:14:22" "scaffold: vite + vue3 project + readme" \
    package.json README.md vite.config.js

commit_at 31 "15:40:11" "ui: initial booking-form layout" \
    src/index.html src/styles.css

commit_at 17 "11:22:08" "vue: wire BookingForm with focus + date fields" \
    src/App.vue

commit_at 10 "16:08:55" "app.js: POST to /cgi-bin/book.py + minimal validation" \
    src/app.js

commit_at 3 "09:17:32" "docs: deploy steps; pkg-lock; dev-db seed" \
    docs/deploy.md package-lock.json seed_dev_db.sql

git log --oneline --pretty="%h  %ad  %s" --date=short
