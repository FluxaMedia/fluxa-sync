#!/usr/bin/env sh
set -eu
: "${DATABASE_URL:?DATABASE_URL is required}"
output="${1:-fluxa-sync-$(date -u +%Y%m%dT%H%M%SZ).dump}"
pg_dump --format=custom --no-owner --no-privileges "$DATABASE_URL" > "$output"
printf '%s\n' "$output"

