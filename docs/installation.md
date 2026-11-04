# Software Installation

This software depends on a few outside software packages including python (we recommend the [Anaconda Python](https://www.anaconda.com/) installer), a VNC Viewer Client (which can be one of several options), and a few command line tools.  **Our installation instructions below should only be taken as an example.**  When dealing with outside packages, users should follow the installation instructions for those packages.

In addition, users will need a basic understanding of command line interactions as individual customizations (e.g. shell choice), differences between operating system versions, and differences in available command line tools may make the details of these examples inaccurate in some cases.

The software has been tested on CentOS/RedHat 7.6, Ubuntu, Raspbian, and macOS.  This software will **not** work under Microsoft Windows as distributed here.

Note: The examples below assume sudo/root installation for all users and were originally written for Linux (CentOS).  Modify as appropriate for your local OS.

### Install python3

- If you are using Anaconda, download and run the latest [anaconda installer](https://www.anaconda.com/download)
- If needed, add python3 to user path (example below for `~/.bashrc` with one possible python install path): `export PATH=/usr/local/anaconda3-7/bin:$PATH`
- Other python distributions should work (using python 3.7+), but the user may have to manually install the python dependencies described in the `environment.yaml` file in addition to other python packages included with anaconda.

### Install VNC viewer client (Linux)

- TigerVNC is recommended as the VNC client.  RealVNC has been tested as well. Example installation commands (will depend on your local linux version and local package manager): `sudo yum install tigervnc-x86_64` or `sudo apt-get install tigervnc-viewer`
- In order for sounds to work, you will need a local sound player.  The
`aplay` tool is installed by default on many linux distributions, but
if yours does not have it, it is part of the
[ALSA](https://alsa.opensrc.org/Aplay) package (often part of
`alsa-utils` or a similar package in your package manager).
- (optional) Install wmctrl (Used for auto-positioning VNC windows): `sudo yum install epel-release wmctrl`

### Install VNC viewer client (macOS)

- [Tiger VNC](https://tigervnc.org) has the advantage of supporting automatic window positioning, but does not support scaling, and can not enter and exit view only mode interactively.
    - Tiger VNC is available for install via the macOS [Homebrew package manager](https://brew.sh). This provides the same software as is available from the download links above, but may be an easier install for users who already use homebrew. To install Tiger VNC Viewer: `brew install tigervnc-viewer`
- It is also possible to use the built in VNC viewer on macOS.  The example configuration file has an example setup for this in the "VNC Viewer Command" section for users who want to try it.  Be aware, however, that we have seen a few instances where the screen freezes and the client needs to be closed and reopened to get an up to date screen, so if you see that problem, please try another VNC Viewer client.
- Real VNC's [VNC Viewer](https://www.realvnc.com/en/connect/download/viewer/) does not support automatic window positioning, but allows window scaling for use on small or high resolution monitors.  In addition, it supports changing modes both interactively and on the command line (e.g. scaling and the toggling of view only mode).  **Note: the free version of RealVNC appears to have been retired and this route is no longer available for new installations.**

### Configure VNC Viewer

**--> Important! <--** If you are using TigerVNC on either OS, in the `~/.vnc` directory, create a file named `default.tigervnc` with these two lines:
```
TigerVNC Configuration file Version 1.0
RemoteResize=0
```

## Install the Keck Remote Observing Software

(NOTE: Examples below assuming a user named 'observer' and installing to home directory)

Download or clone this project from github:
```
git clone https://github.com/KeckObservatory/RemoteObserving
cd RemoteObserving
```
Create configuration file: copy `keck_vnc_config.yaml` to `local_config.yaml`.
```
cp keck_vnc_config.yaml local_config.yaml
```
If you are using anaconda python, you can create a KRO [conda environment](https://docs.conda.io/projects/conda/en/latest/user-guide/concepts/environments.html) using the provided environment.yaml file:
```
conda env create -f environment.yaml
```
This will mean you have a python configuration named "KRO" specifically for  Keck Remote Observing. The `start_keck_viewers` script will automatically attempt to use this if it exists.

(optional) Add VNC start script to path:
```
export PATH=~/RemoteObserving:$PATH
```

## Configure Keck Remote Observing Software

Edit the `local_config.yaml` file you created above.  Read the comments in the configuration file itself as they can guide you.  You may need to uncomment (remove the leading `#`) lines you want to customize.

- **Configure API Key:** If you are connecting outside of the Keck network, enter your uniquely generated "API Key".  This is generated when you upload your SSH public key (see "Upload your SSH key" above).  Visit your [Observer Login Page](https://www2.keck.hawaii.edu/inst/PILogin/login.php) and click on "Manage Your Remote Observing SSH Key".

- **Configure Path to Private SSH Key:** Enter the path to the **private** key corresponding to the public key that you emailed to Keck in the appropriate field.  For example:

    ```
    ssh_pkey: '~/.ssh/id_rsa'
    ```

- **Configure Local VNC Viewer Software:** This is where one sets `vncviewer` with the path and executable for the local VNC viewer client.  The value for this field needs to be to the **executable** not the "app" on macOS.  You should be able to type this command in a terminal and get a VNC Viewer window to pop up.  Note that in a terminal, you will need to escape the spaces in the path with `\` while the value in the local config field can handle spaces, so it should **not** have those escape characters.
    - Some VNC viewers (such as the built in macOS one) may need a prefix such as `vnc://` which can be set via the `vncprefix` value.
    - Options which should be passed to the vncviewer application are set in the `vncargs` value.
- **Important:** Make sure you have configured your VNC viewer **not** to resize the sessions (see the note about TigerVNC above).
- **Soundplay Configuration:** Uncomment the `soundplayer` line to specify which compiled executable for soundplay to use.  Other operating systems sometimes need other soundplay versions, contact the [remote observing help desk](https://keckobservatory.atlassian.net/servicedesk/customer/portals)  for help configuring this value if needed.  Also, if your local machine's path to the `aplay` executable is non-standard, specify that in the `aplay` value.
    - At the moment, the default Linux executable seems to work for CentOS and Ubuntu Linux.
    - For macOS, use the settings as described in the `keck_vnc_config.yaml` section which specify a specific soundplay executable and a specific aplay calling format as described in the comments in that file, replace `%v` with a value from 0 to 100 if you want to override the volume control in eventsounds.  Many users find the macOS sounds too loud, so replacing `%v` with a value less than 1 can help.

```
soundplayer: 'soundplay.darwin.x86_64'
aplay: '/usr/bin/afplay -v %v %s'
```

- If your system is not compatible, or if you do not want it to have sounds, add a line to your `local_config.yaml` file which contains `nosound: True` to avoid starting sounds.  This is important for sites which are using multiple computers for each set of VNC sessions.  Choose one to handle sounds, and set the `nosound: True,` option for the other.
- **Configure Default Sessions:** Keck instruments typically use 4 VNC sessions for instrument control named "control0", "control1", "control2", and "telstatus".  On a normal invocation of the software (via the `start_keck_viewers` command) it will open the four sessions specified here.  For stations which split the duties among 2 computers, one could set this line to control which computer opens which sessions.


## Test your Connection to Keck

Only after your SSH key is successfully installed at Keck, you can test your system.  You can see the status of your SSH Key approval and deployment by clicking "Manage Your Remote Observing SSH Key" on your [Observer Login Page](https://www2.keck.hawaii.edu/inst/PILogin/login.php).

**--> Important! <--** SSH Keys are deployed on a time window based on your scheduled observing dates.  This window is roughly several days before and a few days after observing.  Check your Keck SSH Key Management page for exact deployment times.  If you need to connect outside this window, contact your SA.

From the directory where the Keck VNC software is installed (e.g. `~/RemoteObserving/`), run the software with an instrument account (e.g. `mosfire9` or use an account you will be using in the future) and the `--test` option:

```
./start_keck_viewers mosfire9 --test
```

This should print out a report which indicates that all tests passed. Make sure there are no test failures.

If there are test failures, submit your logfile when you create a ticket at the [remote observing help desk](https://keckobservatory.atlassian.net/servicedesk/customer/portals).  Verbose debug information is logged to the `RemoteObserving/logs/` folder.  Log files are created based on the UTC date.

# Upgrading the Software

The software does a simple check to see if it is the latest released version.  You can see a log line with this information on startup, or you can get the saem result using the `v` command.

Upgrading the software is done via a `git pull` in the directory where the software is installed.  If your software version is earlier than v1.0, this may require rebuilding your `local_config.yaml` file.  If you need to do this, just copy values from your old local config file in to a new one generated from the template as per the instructions above.
