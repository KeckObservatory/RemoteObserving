#!/bin/bash
CMD="source activate KRO ; python get_vnc_sessions.py $@"
xterm -title "Launch VNCs" -e "$CMD"
# The KRO environment is created with:
# conda create -n KRO python=3.6 yaml pyyaml paramiko astropy
