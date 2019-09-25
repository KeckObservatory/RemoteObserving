#!/bin/bash

# NOTE: The KRO environment is created with:
#   conda env create -f environment.yaml

#change to script dir (in case this is called from elsewhere)
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd $DIR

#activate conda environment and run app with args
source activate KRO
python keck_vnc_launcher.py $@

#NOTE: old method of launching in separate xterm; don't see advantage of doing it this way.
#CMD="source activate KRO ; python keck_vnc_launcher.py $@"
#xterm -title "Launch Keck VNCs" -e "$CMD ; bash"
