#!/bin/sh
# Copies the relay's database into ./backups and keeps the newest 14.
# Safe while the relay is running. Run it from cron, e.g. daily:
#   15 3 * * * /home/you/message_app/deploy/backup.sh
set -eu
cd "$(dirname "$0")"
mkdir -p backups
stamp=$(date +%Y-%m-%d-%H%M)
docker compose exec -T relay rm -f /data/backup.db
docker compose exec -T relay messenger-relay backup /data/backup.db
docker compose cp relay:/data/backup.db "backups/relay-$stamp.db"
docker compose exec -T relay rm -f /data/backup.db
ls -1t backups/relay-*.db | tail -n +15 | xargs -r rm --
echo "Saved backups/relay-$stamp.db"
