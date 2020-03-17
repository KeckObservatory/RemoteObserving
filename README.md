# RemoteObserving

These scripts are to be used by remote sites to connect to Keck for remote observing.

Before embarking on setting up a Keck Remote Observing station, we recommend reading the offical remote observing policy and documentation at: [https://www2.keck.hawaii.edu/inst/mainland_observing/](https://www2.keck.hawaii.edu/inst/mainland_observing/)

## Notify Keck of your intent to connect remotely
Before you can connect to Keck remotely, we need to provide you with the firewall info and passwords.  As well, we need info about your remote observing station.

- Email `mainland_observing@keck.hawaii.edu` with the following info about your remote site:
    - Institution
    - City, State
    - Room Name/#
    - Room phone #
    - Emergency Services phone #
    - Site manager/admin names, emails and phone #s

Once we receive your request, we will respond with instructions on obtaining the firewall info, firewall password, and VNC session password.

# Hardware Setup

## Displays

The primary hardware requirement for running Keck VNCs is screen space.  Previous incarnations of the remote observing system have used four (4) 1920x1200 monitors (~24 inch diagonal) and placed one VNC session per monitor.  An alternative setup would be to use a single, very large 4k monitor and place the four VNC sessions on that one monitor.  In order for the VNC sessions to be of reasonable physical size, the monitor would have to be 43-48 inches (we've found that even 43 inches may be a bit on the small size, see below).  The pixel pitch which we used which works well is 0.272 mm/pixel (or about 93 pixels per inch) for our four 24 inch monitor setup.  

We have also tried a 43 inch 4k resolution TV screen (which works out to about 103 ppi), but it is less readable at that size.  The advantage of a single 4k monitor is that it is easy to have a second monitor beside it which is dedicated to the Zoom connection or to a web browser for documentation or displaying weather conditions.

## Computer Recommendations

The following hardware configuration has been tested at Keck HQ:

- Computer: [Intel NUC](https://www.intel.com/content/www/us/en/products/boards-kits/nuc.html)
    - CPU: Intel Core i7-7567U CPU @ 3.50Ghz (dual core)
    - RAM: 16GB

# Software Installation

## Install Software Dependencies

NOTE: Examples below assuming sudo/root installation for all users and assume linux (CentOS).  Modify as appropriate for your local OS.

The software has been tested for CentOS 7.6, RedHat, Ubuntu, and macOS.

- Install Anaconda python3
    - Download and run the latest installer: https://www.anaconda.com/distribution/
    - Add python3 to user path (example below for ~/.bashrc with typical python install path):
    ```
    export PATH=/usr/local/anaconda3-7/bin:$PATH
    ```
- Install VNC viewer client
    - **For Linux**
        - **On Linux:** TigerVNC is recommended as the VNC client.  RealVNC has been tested as well.
        ```
        sudo yum install tigervnc-x86_64
        ```
        - **Important!** If you are using TigerVNC, in the $HOME/.vnc directory, create a file `default.tigervnc` with these two lines: 
        ```
        TigerVNC Configuration file Version 1.0
        RemoteResize=0 
        ```
        - **On Linux:** (optional) Install wmctrl (Used for auto-positioning VNC windows)
            ```
            sudo yum install epel-release 
            sudo yum install wmctrl
            ```
    - **For macOS**
        - **On macOS**: Real VNC's [VNC Viewer](https://www.realvnc.com/en/connect/download/viewer/) is recommended (note, this is the free software, you do not need VNC Viewer Plus).
        - **On macOS**: It is also possible to use the built in VNC viewer on macOS, but we have seen a few instances where the screen freezes and the client needs to be closed and reopened to get an up to date screen.


## Download and Install Keck VNC software

(NOTE: Examples below assuming a user named 'observer' and installing to home directory)

- Download or clone this project from github: 
    ```
    cd
    git clone https://github.com/KeckObservatory/RemoteObserving
    cd ~/RemoteObserving
    ```

- Create configuration file: copy `keck_vnc_config.yaml` to `local_config.yaml`.
    ```
    cp keck_vnc_config.yaml local_config.yaml
    ```

- Create a KRO [conda environment](https://docs.conda.io/projects/conda/en/latest/user-guide/concepts/environments.html) using the provided environment.yaml file:
    ```
    cd ~/RemoteObserving
    conda env create -f environment.yaml
    ```

- Setup SSH Keys:
    - Generate ssh public/private key pair **(no passphrase)** 
        ```
        cd ~/.ssh
        ssh-keygen -t rsa -b 4096
        ```
    - Make sure that the resulting key is an RSA key.  The **private** key should have a first line which looks like `-----BEGIN RSA PRIVATE KEY-----` (it should not be an OPENSSH key).  If you do get an OPENSSH key (we've seen this on macOS and ubuntu linux), try generating the key with the `-m PEM` option:
        ```
        ssh-keygen -t rsa -b 4096 -m PEM
        ```
    - Email the **public** key file (i.e. `id_rsa.pub`) to `mainland_observing@keck.hawaii.edu`
    - Edit `local_config.yaml` file to include path to your ssh **private** key:
        ```
        ssh_pkey: '/home/observer/.ssh/id_rsa',
        ```

- (optional) Save VNC session password (not available on macOS):
    - NOTE: This is for the final password prompt for each VNC window.
    - Run the `vncpasswd` command line utility and note where it saves the VNC password file.
    - Edit `local_config.yaml` to include the password file as a VNC start option:
        ```
        vncargs: '-passwd=/home/observer/.vnc/passwd',
        ```
- (optional) Add VNC start script to path:
    ```
    export PATH=/home/observer/RemoteObserving:$PATH
    ```

## Configure Keck VNC software

Edit the configuration file as appropriate.  Read the comments in the configuration file itself as they can guide you.  You may need to uncomment (remove the leading `#`) from lines you want to customize.

- **Configure Firewall:** If you are connecting outside of the Keck network, enter the firewall address, port and user info.  You'll need to get this information from someone at Keck.

    ```
    firewall_address: ???.???.???.???,
    firewall_port: ???,
    firewall_user: '???',
    ```

- **Configure Local VNC Viewer Software:** This is where one sets `vncviewer` with the path and executable for the local VNC viewer client (we recommend TigerVNC as the most compatible with our system).  Some VNC viewers (such as the built in macOS one) may need a prefix such as `vnc://` which can be set via the `vncprefix` value.  Options which should be passed to the vncviewer application are set in the `vncargs` value (defaults should be good for Tiger VNC).
    - **Important:** Make sure you have configured your client **not** to resize the sessions (see the note about TigerVNC above).

- **Configure Default Sessions:** Keck instruments typically use 4 VNC sessions for instrument control named "control0", "control1", "control2", and "telstatus".  On a normal invocation of the software (via the `start_keck_viewers` command) it will open the four sessions specified here.  For stations which split the duties among 2 computers, one could set this line to control which computer opens which sessions.

- **Soundplay Configuration:** For compatible systems, uncomment the `soundplayer` line to specify which compiled executable for soundplay to use.  Other operating systems sometimes need other soundplay versions, contact `mainland_observing@keck.hawaii.edu` for help configuring this value.  Also, if you local machine's path to the `aplay` executable is non-standard, specify that in the `aplay` value.
    - At the moment, the default linux executable seems to work for CentOS and Ubuntu linux.  We do not have a functioning soundplay executable for MacOS.
    - If your system is not compatible, or if you do not want it to have sounds, add a line to your `local_config.yaml` file: `nosound: True,` to avoid starting sounds.  This is important for sites which are using multiple computers for each set of VNC sessions.  Choose one to handle sounds, and set the `nosound: True,` option for the other.

# Test your connection to Keck

Only after your SSH key is successfully installed at Keck, you can test your system.

From the directory where the Keck VNC software is installed (e.g. `~/RemoteObserving/`), run pytest:

```
conda activate KRO
pytest
```

This may query you for passwords, depending on your local configuration. It should print out a report which indicates that all tests passed. Make sure there are no test failures.

If there are test failures, email your logfile to `mainland_observing@keck.hawaii.edu`.  Verbose debug information is logged to the `RemoteObserving/logs/` folder.  Log files are created based on the UTC date.


# Run the VNC launch script

From the command line, cd into your install directory and run `start_keck_viewers` followed by the name of the instrument account assigned for your observing night (ie `nires1`, `mosfire2`).  Running the script without options will start 4 VNC sessions (control0, control1, control2, telstatus) and the soundplayer. Additionally, you should see a command line menu with more options once you have started the script.:
```
cd ~/RemoteObserving
./start_keck_viewers [instrument account]
```

To get help on available command line options:
```
./start_keck_viewers --help
```

**NOTE:** Be sure to exit the script by using the 'q' quit option or control-c to ensure all VNC processes, SSH tunnels, and authentication are terminated properly.


# Troubleshooting and common problems

Verbose debug information is logged to the `RemoteObserving/logs/` folder.  Log files are created based on the UTC date.

If you need assistance, please email `mainland_observing@keck.hawaii.edu` and attach the most recent log file from the logs folder.

