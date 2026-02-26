#!/bin/bash
# VFS Japan slot checker - runs via cron
# Logs output to check.log

cd /Users/timwerner/Downloads/vfs-japan-scanner

export VFS_EMAIL='tim@1pay.lu'
export WHATSAPP_NUMBER='5511956087831'
export CALLMEBOT_API_KEY='3764556'

echo "--- $(date) ---" >> check.log
python3 run.py --always-notify >> check.log 2>&1
echo "" >> check.log
