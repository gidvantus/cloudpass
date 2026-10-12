#!/bin/sh
#
# A consistent copy of the one volume that matters.
#
#   ./deploy/backup.sh [destination]        # default: deploy/backups
#
# `cloudpass-data` holds the accounts and everything encrypted under them. `web/compose.yaml`
# calls it "the one thing worth backing up", and it is: without it the server keeps running
# and every account on it is gone.
#
# Why the container is stopped for the length of the copy: SQLite keeps recent commits in a
# write-ahead log beside the database, and the two are only meaningful together. Copying a
# database that is being written produces a file that may not open — a backup that reports
# success and restores nothing. A few seconds of downtime is the cheaper mistake.
#
# This is a local copy, not an off-site one. A backup on the same disk as the database
# survives a mistake and not a dead machine; rsync the destination somewhere else too.

set -eu

cd "$(dirname "$0")/.."

DESTINATION=${1:-deploy/backups}
VOLUME=cloudpass_cloudpass-data
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
NAME="cloudpass-data-$STAMP.tgz"
# The archive holds every account on the server, so how many are kept is a decision about how
# long a stolen backup stays interesting. Two weeks is the deliberate compromise.
KEEP=14

if ! docker volume inspect "$VOLUME" >/dev/null 2>&1; then
    echo "no such volume: $VOLUME" >&2
    echo "the project name in web/compose.yaml decides this name — check it before trusting a backup" >&2
    exit 1
fi

mkdir -p "$DESTINATION"
DESTINATION=$(cd "$DESTINATION" && pwd)

compose() {
    docker compose --env-file deploy/.env -f deploy/compose.yaml "$@"
}

compose stop cloudpass
trap 'compose start cloudpass' EXIT INT TERM

docker run --rm \
    -v "$VOLUME":/data:ro \
    -v "$DESTINATION":/backup \
    alpine:3 \
    tar czf "/backup/$NAME" -C /data .

# A tarball of an empty volume is a successful-looking backup of nothing, and that is exactly
# the failure that goes unnoticed for a year. The database is the one entry that has to be in
# there.
docker run --rm -v "$DESTINATION":/backup alpine:3 tar tzf "/backup/$NAME" \
    | grep -qx './cloudpass.db' \
    || { echo "archive has no cloudpass.db — not a usable backup" >&2; exit 1; }

echo "wrote $DESTINATION/$NAME ($(wc -c < "$DESTINATION/$NAME") bytes)"

ls -1t "$DESTINATION"/cloudpass-data-*.tgz 2>/dev/null | tail -n "+$((KEEP + 1))" | while read -r old; do
    rm -f "$old"
    echo "removed $old"
done
