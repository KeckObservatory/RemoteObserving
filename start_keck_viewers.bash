#!/bin/bash

#activate conda environment
# NOTE: The KRO environment is created with: conda env create -f environment.yaml
CONDA_BASE=$(conda info --base)
source $CONDA_BASE/etc/profile.d/conda.sh
conda activate KRO
#NOTE: old method using 'source' will work too but not preferred
#source activeate KRO

#change to script dir (so we don't need full path to keck_vnc_launcher.py)
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd $DIR

#launch 
python keck_vnc_launcher.py $@

#NOTE: old method of launching in separate xterm; don't see advantage of doing it this way.
#CMD="source activate KRO ; python keck_vnc_launcher.py $@"
#xterm -title "Launch Keck VNCs" -e "$CMD ; bash"
