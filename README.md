# RemoteObserving

These scripts are to be used by remote sites to connect to Keck for remote observing.


# Hardware recommendations:

The following hardware configurations have been tested:

- Intel NUC (https://www.intel.com/content/www/us/en/products/boards-kits/nuc.html)
    - CPU: Intel Core i7-7567U CPU @ 3.50Ghz (dual core)
    - RAM: 32GB
    - OS: CentOS 7.6


# Software requirements:

### Install CentOS 7.6
- NOTE: Earlier versions of CentOS may work, but have not been tested

### Install Anaconda python3:
- Download the latest installer from here: https://www.anaconda.com/distribution/
    - (downloaded https://repo.anaconda.com/archive/Anaconda3-2019.03-Linux-x86_64.sh)
- Run the installer
    - installed to /usr/local/anaconda3-7/
- Extra python packages install:
    - conda install -c anaconda paramiko 
    - conda install -c conda-forge sshtunnel
- Add python3 to user path in .bashrc:
    - export PATH=/usr/local/anaconda3-7/bin:$PATH

### Install VNC viewer
- yum install tigervnc-x86_64

### Install misc 
- xterm: 
    - yum install xterm
- wmctrl:
    - yum install epel-release 
    - yum install wmctrl
- chrome: 
    - wget https://dl.google.com/linux/direct/google-chrome-stable_current_x86_64.rpm
    - yum install ./google-chrome-stable_current_*.rpm

# How to configure and run VNC startup script
- Download or clone this project from github: https://github.com/KeckObservatory/RemoteObserving
- Edit configurations in keck_vnc_config.yaml (optional: save as local_config.yaml)
- Generate ssh public/private key pair and email public key to mainland_observing@keck.hawaii.edu
    cd ~/.ssh
    ssh-keygen -t rsa -b 4096
