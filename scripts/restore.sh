#!/usr/bin/env sh
set -eu
: "${DATABASE_URL:?DATABASE_URL is required}"
input="${1:?usage: restore.sh backup.dump}"
pg_restore --clean --if-exists --no-owner --no-privileges --dbname="$DATABASE_URL" "$input"

