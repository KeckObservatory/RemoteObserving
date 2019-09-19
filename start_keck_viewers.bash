#!/bin/bash

# NOTE: The KRO environment is created with:
#   conda env create -f environment.yml

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd $DIR
CMD="pwd; source activate KRO ; python keck_vnc_launcher.py $@"
xterm -title "Launch Keck VNCs" -e "$CMD ; bash"
