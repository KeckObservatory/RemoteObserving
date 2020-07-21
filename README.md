# RemoteObserving

These scripts are to be used by remote sites and by individual
observers to connect to W. M. Keck Observatory for remote observing.

Before embarking on setting up a Keck Remote Observing station, we recommend reading the offical remote observing policy and documentation at: [https://www2.keck.hawaii.edu/inst/mainland_observing/](https://www2.keck.hawaii.edu/inst/mainland_observing/)

## Notify Keck of your intent to connect remotely
Before you can connect to Keck remotely, we need to provide you with the firewall info and passwords.  As well, we need info about your remote observing station.

### If you are setting up remote observing from home for yourself

- Email
  [remote-observing@keck.hawaii.edu](mailto:remote-observing@keck.hawaii.edu)
  with the following info:

    - Institution
    - First and Last name of observer
    - Date of observation (HST or UT, please specify)
    - TAC assigned program ID (from the Keck [schedule](https://www2.keck.hawaii.edu/observing/keckSchedule/keckSchedule.php) )
    - Staff Astronomer assigned to your night
    - Cellphone number capable of receiving texts
    - Have you used pajamas mode successful before and do you have the software installed?
    - If yes, is your ssh key still valid?
    - If no, include a new id_rsa.pub key as specified in the installation instructions

### if you are using an official site, or are setting up a new official site

- Email [remote-observing@keck.hawaii.edu](mailto:remote-observing@keck.hawaii.edu) with the following info about your remote site:
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

A number of computer hardware configurations have been tested.  Various intel-based computers running linux, numerous mac laptops and desktops, and even a Raspberry Pi 4.

This hardware configuration has been tested at Keck HQ and found to work well: 

- [Intel NUC](https://www.intel.com/content/www/us/en/products/boards-kits/nuc.html), CPU: Intel Core i7-7567U CPU @ 3.50Ghz (dual core), RAM: 16GB


# Software Installation

## Install Software Dependencies

The software has been tested on CentOS/RedHat 7.6, Ubuntu, Raspbian, and macOS.  This software will **not** work under Microsoft Windows as distributed here.

Note: The examples below assuming sudo/root installation for all users and were originally written for Linux (CentOS).  Modify as appropriate for your local OS.

- Install Anaconda python3
    - Download and run the latest [anaconda installer](https://www.anaconda.com/distribution/)
    - Add python3 to user path (example below for `~/.bashrc` with typical python install path):
    ```
    export PATH=/usr/local/anaconda3-7/bin:$PATH
    ```
    - Other python distributions should work (using python 3.7+), but the user may have to manually install the python dependencies described in the `environment.yaml` file in addition to other python packages included with anaconda.
- Install VNC viewer client
    - **For Linux**
        - TigerVNC is recommended as the VNC client.  RealVNC has been tested as well.
            ```
            sudo yum install tigervnc-x86_64
            ```
            or
            ```
            sudo apt-get install tigervnc-viewer
            ```

        - **Important!** If you are using TigerVNC, in the `~/.vnc` directory, create a file `default.tigervnc` with these two lines:
            ```
            TigerVNC Configuration file Version 1.0
            RemoteResize=0
            ```
        - In order for sounds to work, you will need a local sound player.  The
          `aplay` tool is installed by default on many linux distributions, but
          if yours does not have it, it is part of the
          [ALSA](https://alsa.opensrc.org/Aplay) package (often part of
          `alsa-utils` or a similar package in your package manager).
        - (optional) Install wmctrl (Used for auto-positioning VNC windows)
            ```
            sudo yum install epel-release
            sudo yum install wmctrl
            ```
    - **For macOS**: Install a VNC viewer application if needed.
        - [Tiger VNC](https://tigervnc.org) is recommended as it supports automatic window positioning.
        - Real VNC's [VNC Viewer](https://www.realvnc.com/en/connect/download/viewer/) also works, but without automatic window positioning (note, this is the free software, you do not need VNC Viewer Plus).
        - It is also possible to use the built in VNC viewer on macOS, but we have seen a few instances where the screen freezes and the client needs to be closed and reopened to get an up to date screen.


## Install the Keck Remote Observing software

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
    - Generate ssh public/private key pair **(do not set a passphrase)**
        ```
        cd ~/.ssh
        ssh-keygen -t rsa -b 4096
        ```
    - Make sure that the resulting key is an RSA key.  The **private** key should have a first line which looks like `-----BEGIN RSA PRIVATE KEY-----` (it should not be an OPENSSH key).  If you do get an OPENSSH key (we've seen this on macOS and Ubuntu Linux), try generating the key with the `-m PEM` option:
        ```
        ssh-keygen -t rsa -b 4096 -m PEM
        ```
    - Email the **public** key file (i.e. `id_rsa.pub`) to [remote-observing@keck.hawaii.edu](mailto:remote-observing@keck.hawaii.edu)

- (optional) Add VNC start script to path:
    ```
    export PATH=/home/observer/RemoteObserving:$PATH
    ```

## Configure Keck VNC software

Edit the `local_config.yaml` file you created above.  Read the comments in the configuration file itself as they can guide you.  You may need to uncomment (remove the leading `#`) lines you want to customize.

- **Configure Firewall:** If you are connecting outside of the Keck network, enter the firewall address, port and user info.  You'll need to get this information from someone at Keck.

    ```
    firewall_address: ???.???.???.???
    firewall_port: ???
    firewall_user: ???
    ```

- **Configure Path to Private SSH Key:** Enter the path to the **private** key corresponding to the public key that you emailed to Keck in the appropriate field.  For example:

    ```
    ssh_pkey: '~/.ssh/id_rsa'
    ```

- **Configure Local VNC Viewer Software:** This is where one sets `vncviewer` with the path and executable for the local VNC viewer client.  Some VNC viewers (such as the built in macOS one) may need a prefix such as `vnc://` which can be set via the `vncprefix` value.  Options which should be passed to the vncviewer application are set in the `vncargs` value.
    - **Important:** Make sure you have configured your client **not** to resize the sessions (see the note about TigerVNC above).
    - **On Linux:** (optional) Save VNC session password (not available on macOS):
        - NOTE: This is for the final password prompt for each VNC window.
        - Run the `vncpasswd` command line utility and note where it saves the VNC password file.
        - Edit `local_config.yaml` to include the password file as a VNC start option:
            ```
            vncargs: '-passwd=/home/observer/.vnc/passwd'
            ```

- **Soundplay Configuration:** For compatible systems, uncomment the `soundplayer` line to specify which compiled executable for soundplay to use.  Other operating systems sometimes need other soundplay versions, contact [remote-observing@keck.hawaii.edu](mailto:remote-observing@keck.hawaii.edu) for help configuring this value if needed.  Also, if your local machine's path to the `aplay` executable is non-standard, specify that in the `aplay` value.
    - At the moment, the default Linux executable seems to work for CentOS and Ubuntu Linux.
    - For macOS, use the settings as described in the `keck_vnc_config.yaml` section which specify a specific soundplay executable and a specific aplay calling format:
        ```
        soundplayer: 'soundplay.darwin.x86_64'
        aplay: '/usr/bin/afplay -v %v %s'
        ```
        As described in the comments in that file, replace `%v` with a value from 0 to 100 if you want to override the volume control in eventsounds.  Many users find the macOS sounds too loud, so replacing `%v` with `1` can help.
    - If your system is not compatible, or if you do not want it to have sounds, add a line to your `local_config.yaml` file:
        ```
        nosound: True
        ```
    to avoid starting sounds.  This is important for sites which are using multiple computers for each set of VNC sessions.  Choose one to handle sounds, and set the `nosound: True,` option for the other.

- **Configure Default Sessions:** Keck instruments typically use 4 VNC sessions for instrument control named "control0", "control1", "control2", and "telstatus".  On a normal invocation of the software (via the `start_keck_viewers` command) it will open the four sessions specified here.  For stations which split the duties among 2 computers, one could set this line to control which computer opens which sessions.


# Test your connection to Keck

Only after your SSH key is successfully installed at Keck, you can test your system.

From the directory where the Keck VNC software is installed (e.g. `~/RemoteObserving/`), run:

```
./start_keck_viewers --test
```

This may query you for passwords, depending on your local configuration. It should print out a report which indicates that all tests passed. Make sure there are no test failures.

If there are test failures, email your logfile to [remote-observing@keck.hawaii.edu](mailto:remote-observing@keck.hawaii.edu).  Verbose debug information is logged to the `RemoteObserving/logs/` folder.  Log files are created based on the UTC date.


# Run the VNC launch script

From the command line, cd into your install directory and run `start_keck_viewers` followed by the name of the instrument account assigned for your observing night (i.e. `nires1`, `mosfire2`).  Running the script without options will start 4 VNC sessions (control0, control1, control2, telstatus) and the soundplayer. Additionally, you should see a command line menu with more options once you have started the script.:
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

If you need assistance, please email [remote-observing@keck.hawaii.edu](mailto:remote-observing@keck.hawaii.edu) and attach the most recent log file from the logs folder.

