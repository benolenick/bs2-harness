#!/bin/bash
D=/home/operator/Desktop/HTB/enterprise-ab/bs2-memoria
cd "$D"
export BS2_LADDER_NO_OPERATOR=1 BS2_LADDER_RESEARCH=1 BS2_LADDER_SECOND_OPINION=0
exec python3 "$D/escalation_ladder.py" >> "$D/escalation.log" 2>&1
