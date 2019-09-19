#!/bin/bash

# NOTE: The KRO environment is created with:
#   conda env create -f environment.yml

CMD="source activate KRO ; python keck_vnc_launcher.py $@"
xterm -title "Launch Keck VNCs" -e "$CMD ; bash"
