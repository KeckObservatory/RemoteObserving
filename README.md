# RemoteObserving

These scripts are to be used by remote sites to connect to Keck for remote observing.


# Hardware recommendations:

The following hardware configurations have been tested:

- Computer: Intel NUC (https://www.intel.com/content/www/us/en/products/boards-kits/nuc.html)
    - CPU: Intel Core i7-7567U CPU @ 3.50Ghz (dual core)
    - RAM: 16GB
- Monitor: 43-inch, 4k resolution


# Software requirements:
(NOTE: Examples below assuming sudo/root installation for all users)

### Install CentOS 7.6
- NOTE: Earlier versions of CentOS may work, but have not been tested

### Install Anaconda python3:
- Download and run the latest installer: https://www.anaconda.com/distribution/
- Extra python packages install:
    ```
    sudo conda install -c anaconda paramiko 
    sudo conda install -c conda-forge sshtunnel
    ```
- Add python3 to user path in .bashrc (example below with typical install path):
    ```
    export PATH=/usr/local/anaconda3-7/bin:$PATH
    ```

### Install TigerVNC client
    TigerVNC is recommended as the VNC client for linux.  RealVNC has been tested as well.
    ```
    sudo yum install tigervnc-x86_64
    ```

### Install misc (if not already available with OS install)
- (optional) wmctrl:
    (Used for window auto-positioning)
    ```
    sudo yum install epel-release 
    sudo yum install wmctrl
    ```
- (optional) chrome: 
    Chrome browser is recommended for Zoom sessions
    ```
    wget https://dl.google.com/linux/direct/google-chrome-stable_current_x86_64.rpm
    sudo yum install ./google-chrome-stable_current_*.rpm
    ```

# Download and Configure Keck VNC software
(NOTE: Examples below assuming a user named 'observer' and installing to home directory)

- Download or clone this project from github: 
    ```
    cd
    git clone https://github.com/KeckObservatory/KeckRemoteObserving
    cd ~/KeckRemoteObserving
    ```
- Edit configuration file "keck_vnc_config.yaml" and save as "local_config.yaml".
    - If you are connecting outside of the Keck network, enter the firewall address, port and user info
    
- Create conda environment
    ```
    cd ~/KeckRemoteObserving
    conda env create -f environment.yaml
    ```
    
- Setup SSH Keys:
    - Generate ssh public/private key pair and email public key to mainland_observing@keck.hawaii.edu
        ```
        cd ~/.ssh
        ssh-keygen -t rsa -b 4096
        ```
    - Edit "local_config.yaml" file to include path to your ssh private key:
        ```
        ssh_pkey: '/home/observer/.ssh/id_rsa',
        ```
- (optional) Save VNC session password:
    - Run the 'vncpasswd' command line utility and note where it saves the VNC password file.
    - Edit "local_config.yaml" to include the password file as a VNC start option:
        ```
        vncargs: '-passwd=/home/observer/.vnc/passwd',
        ```
- (optional) Add VNC start script to path:
    ```
    export PATH=/home/observer/KeckRemoteObserving:$PATH
    ```
        
        
# Run the VNC launch script:
From the command line, cd into your install directory and run "start_keck_viewers.bash" followed by the name of the instrument account assigned for your observing night (ie 'nires1', 'mosfire2').  Running the script without options will start 4 VNC sessions (control0, control1, control2, telstatus) and the soundplayer. Additionally, you should see a command line menu with more options once you have started the script.:
```
cd ~/KeckRemoteObserving
./start_keck_vnc.bash [instrument account]
```

To get help on available command line options:
```
start_keck_viewers.bash --help
```

NOTE: Be sure to exit the script by using the 'q' quit option or control-c to ensure all VNC processes, SSH tunnels, and authentication are terminated properly.


# Troubleshooting and common problems

Verbose debug information is logged to the KeckRemoteObserving/logs/ folder.  Log files are created based on the UTC date.

If you need assistance, please email mainland_observing@keck.hawaii.edu and attach the most recent log file from the logs folder.

