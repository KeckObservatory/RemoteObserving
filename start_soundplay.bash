#!/bin/bash
CMD="source activate KRO ; python soundplay.py $@"
xterm -title "Launch Soundplay" -e "$CMD"
# The KRO environment is created with:
# conda create -n KRO python=3.6 yaml pyyaml paramiko astropy
