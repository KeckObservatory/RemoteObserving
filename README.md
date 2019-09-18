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
    ```
    conda install -c anaconda paramiko 
    conda install -c conda-forge sshtunnel
    ```
- Add python3 to user path in .bashrc:
    ```
    export PATH=/usr/local/anaconda3-7/bin:$PATH
    ```

### Install VNC viewer
    ```
    yum install tigervnc-x86_64
    ```

### Install misc 
- xterm: 
    ```
    yum install xterm
    ```
- wmctrl:
    ```
    yum install epel-release 
    yum install wmctrl
    ```
- chrome: 
    ```
    wget https://dl.google.com/linux/direct/google-chrome-stable_current_x86_64.rpm
    yum install ./google-chrome-stable_current_*.rpm
    ```

# Download and Configure Keck VNC software
- Download or clone this project from github: 
    ```
    cd
    git clone https://github.com/KeckObservatory/KeckRemoteObserving
    ```
- Edit configuration file: keck_vnc_config.yaml (optional: save as local_config.yaml)
    - If you are connecting outside of the Keck network, enter the firewall address, port and user info
    
- Setup SSH Keys:
    - Generate ssh public/private key pair and email public key to mainland_observing@keck.hawaii.edu
        ```
        cd ~/.ssh
        ssh-keygen -t rsa -b 4096
        ```
    - Edit the Remote Observing config file to include path to your ssh private key:
        ```
        ssh_pkey: '/home/observer/.ssh/id_rsa',
        ```
- Save VNC session password:
    - Run the 'vncpasswd' command line utility.
    - Edit the Remote Observing config file to include the password file as a VNC start option:
        ```
        vncargs: '-passwd=/home/observer/.vnc/passwd',
        ```
        
        
# Run the VNC launch script:
Running the script without option, you will start 4 VNC sessions (control0, control1, control2, telstatus) and the soundplayer:
```
cd ~/KeckRemoteObserving
./start_keck_vnc.bash [instrument account]
```
