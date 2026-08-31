#!/bin/bash
D=/home/operator/Desktop/HTB/enterprise-ab/bs2-memoria
cd "$D"
exec python3 warroom.py --port 8141 >> "$D/warroom.log" 2>&1 < /dev/null
