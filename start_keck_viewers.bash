#!/bin/bash

# NOTE: The KRO environment is created with:
#   conda env create -f environment.yaml

#change to script dir (in case this is called from elsewhere)
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd $DIR

#run in remaining commands in separate xterm window
CMD="pwd; source activate KRO ; python keck_vnc_launcher.py $@"
xterm -title "Launch Keck VNCs" -e "$CMD ; bash"
