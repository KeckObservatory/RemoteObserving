# RemoteObserving

These scripts are to be used by remote sites and by individual observers to connect to W. M. Keck Observatory for remote observing. Before embarking on setting up a Keck Remote Observing station, we recommend reading the offical remote observing policy and documentation at: [https://www2.keck.hawaii.edu/inst/mainland_observing/](https://www2.keck.hawaii.edu/inst/mainland_observing/)

# Table of Contents

- Requirements for Remote Observing at Keck
    - 1 - Have an approved remote observing request
    - 2 - Be listed as an observer
    - 3 - Upload your SSH key
- Hardware Recommendations
    - Displays
    - Computer Recommendations
- Software Installation
    - Install Software Dependencies
    - Install the Keck Remote Observing Software
    - Configure Keck Remote Observing Software
    - Test your Connection to Keck
- Running the Keck Remote Observing Software
    - Opening and Closing Individual VNC Sessions
    - Getting a List of VNC Sessions
    - Uploading a log file to Keck
- Troubleshooting Common Problems
    - Can not see entire VNC desktop / VNC desktop is small
    - Connection Quality Problems
    - No Sounds
- Upgrading the Software

# Requirements for Remote Observing at Keck

**IMPORTANT**: Last minute additions of observers to an observing night will not be possible.  Observers **must** complete the items below at least two days ahead of time.

## 1 - Have an approved remote observing request

You must have an approved remote observing request before you can observe remotely.  Please submit your request from your [Observer Login Page](https://www2.keck.hawaii.edu/inst/PILogin/login.php).

## 2 - Be listed as an observer

Each person wanting to connect **must** be listed in the [Keck Observing Schedule](https://www2.keck.hawaii.edu/observing/keckSchedule/keckSchedule.php?calType=classic&telnr=0&viewType=schedule) as an observer.

The schedule is filled based on your remote observing request, but this is a manual step and thus it must be done at least **two days in advance of your run**.

## 3 - Upload your SSH key

- Generate ssh public/private key pair **(do not set a passphrase)**
    ```
    cd ~/.ssh
    ssh-keygen -t ed25519
    ```

- Upload your **public** key file at your [Observer Login Page](https://www2.keck.hawaii.edu/inst/PILogin/login.php). Click on "Manage Your Remote Observing SSH Key" and follow the instructions.

- After you have uploaded the key, note the "API key".  This will be a long string of letters and numbers.  You will need this key to connect (see the section below titled "Configure Keck Remote Observing Software").

# Hardware Recommendations

## Displays

The primary hardware requirement for running Keck VNCs is screen space.  Previous incarnations of the remote observing system have used four (4) 1920x1200 monitors (~24 inch diagonal) and placed one VNC session per monitor.  An alternative setup would be to use a single, very large 4k monitor and place the four VNC sessions on that one monitor.  In order for the VNC sessions to be of reasonable physical size, the monitor would have to be 43-48 inches (we've found that even 43 inches may be a bit on the small size, see below).  The pixel pitch which we used which works well is 0.272 mm/pixel (or about 93 pixels per inch) for our four 24 inch monitor setup.

We have also tried a 43 inch 4k resolution TV screen (which works out to about 103 ppi), but it is less readable at that size.  The advantage of a single 4k monitor is that it is easy to have a second monitor beside it which is dedicated to the Zoom connection or to a web browser for documentation or displaying weather conditions.

## Computer Recommendations

A number of computer hardware configurations have been tested.  Various Intel based computers running linux, numerous Mac laptops and desktops (both Intel based and Apple silicon based), and even a Raspberry Pi 4.

This hardware configuration has been tested at Keck HQ and found to work well:  [Intel NUC](https://www.intel.com/content/www/us/en/products/boards-kits/nuc.html), CPU: Intel Core i7-7567U CPU @ 3.50Ghz (dual core), RAM: 16GB


# Software Installation

This software depends on a few outside software packages including python (we recommend the [Anaconda Python](https://www.anaconda.com/) installer), a VNC Viewer Client (which can be one of several options), and a few command line tools.  **Our installation instructions below should only be taken as an example.**  When dealing with outside packages, users should follow the installation instructions for those packages.

In addition, users will need a basic understanding of command line interactions as individual customizations (e.g. shell choice), differences between operating system versions, and differences in available command line tools may make the details of these examples inaccurate in some cases.

## Install Software Dependencies

The software has been tested on CentOS/RedHat 7.6, Ubuntu, Raspbian, and macOS.  This software will **not** work under Microsoft Windows as distributed here.

Note: The examples below assume sudo/root installation for all users and were originally written for Linux (CentOS).  Modify as appropriate for your local OS.

- Install python3
    - If you are using Anaconda, download and run the latest [anaconda installer](https://www.anaconda.com/download)
    - If needed, add python3 to user path (example below for `~/.bashrc` with one possible python install path):
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
        - [Tiger VNC](https://tigervnc.org) has the advantage of supporting automatic window positioning, but does not support scaling, and can not enter and exit view only mode interactively.
        - Real VNC's [VNC Viewer](https://www.realvnc.com/en/connect/download/viewer/) does not support automatic window positioning, but allows window scaling for use on small or high resolution monitors.  In addition, it supports changing modes both interactively and on the command line (e.g. scaling and the toggling of view only mode).  Note: this is the free software, you do not need VNC Viewer Plus.
        - Both Tiger VNC and Real VNC have the viewers available for install via the macOS [Homebrew package manager](https://brew.sh). This provides the same software as is available from the download links above, but may be an easier install for users who already use homebrew.
            - To install Real VNC Viewer: `brew install vnc-viewer`
            - To install Tiger VNC Viewer: `brew install tigervnc-viewer`
        - It is also possible to use the built in VNC viewer on macOS.  The example configuration file has an example setup for this in the "VNC Viewer Command" section for users who want to try it.  Be aware, however, that we have seen a few instances where the screen freezes and the client needs to be closed and reopened to get an up to date screen, so if you see that problem, please try another VNC Viewer client.

**--> Important! <--** If you are using TigerVNC on either OS, in the `~/.vnc` directory, create a file named `default.tigervnc` with these two lines:
```
TigerVNC Configuration file Version 1.0
RemoteResize=0
```


## Install the Keck Remote Observing Software

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

- If you are using anaconda python, you can create a KRO [conda environment](https://docs.conda.io/projects/conda/en/latest/user-guide/concepts/environments.html) using the provided environment.yaml file:
    ```
    cd ~/RemoteObserving
    conda env create -f environment.yaml
    ```
    This will mean you have a python configuration named "KRO" specifically for  Keck Remote Observing. The `start_keck_viewers` script will automatically attempt to use this if it exists.

- (optional) Add VNC start script to path:
    ```
    export PATH=/home/observer/RemoteObserving:$PATH
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
- **Soundplay Configuration:** Uncomment the `soundplayer` line to specify which compiled executable for soundplay to use.  Other operating systems sometimes need other soundplay versions, contact [remote-observing@keck.hawaii.edu](mailto:remote-observing@keck.hawaii.edu) for help configuring this value if needed.  Also, if your local machine's path to the `aplay` executable is non-standard, specify that in the `aplay` value.
    - At the moment, the default Linux executable seems to work for CentOS and Ubuntu Linux.
    - For macOS, use the settings as described in the `keck_vnc_config.yaml` section which specify a specific soundplay executable and a specific aplay calling format:
        ```
        soundplayer: 'soundplay.darwin.x86_64'
        aplay: '/usr/bin/afplay -v %v %s'
        ```
        As described in the comments in that file, replace `%v` with a value from 0 to 100 if you want to override the volume control in eventsounds.  Many users find the macOS sounds too loud, so replacing `%v` with a value less than 1 can help.
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

If there are test failures, email your logfile to [remote-observing@keck.hawaii.edu](mailto:remote-observing@keck.hawaii.edu).  Verbose debug information is logged to the `RemoteObserving/logs/` folder.  Log files are created based on the UTC date.


# Running the Keck Remote Observing Software

From the command line, cd into your install directory and run `start_keck_viewers` followed by the name of the instrument account assigned for your observing night (i.e. `nires1`, `mosfire2`).  Running the script without options will start 4 VNC sessions (control0, control1, control2, telstatus) and the soundplayer.

```
cd ~/RemoteObserving
./start_keck_viewers [instrument account]
```

**NOTE:** Be sure to exit the script by using the 'q' quit option or control-c to ensure all VNC processes, SSH tunnels, and authentication are terminated properly.

To get help on available command line options:
```
./start_keck_viewers --help
```

Unlike the previous incarnation of the Keck VNC launch script, this software is not actually a script, but an app.  After being run, the terminal in which you ran the `start_keck_viewers` command will have a prompt and a menu.  For example:

```
|--------------------------------------------------|
|          Keck Remote Observing (v1.2.4)          |
|                     MENU                         |
|--------------------------------------------------|
|  l               List sessions available         |
|  [session name]  Open VNC session by name        |
|  w               Position VNC windows            |
|  s               Soundplayer restart             |
|  u               Upload log to Keck              |
|  p               Play a local test sound         |
|  t               List local ports in use         |
|  c [port]        Close ssh tunnel on local port  |
|  v               Check if software is up to date |
|  q               Quit (or Control-C)             |
|--------------------------------------------------|
> 
```

The user can type commands at the `>` prompt.  The most important is the `q` (quit) command which closes down the SSH tunnels and VNC viewer sessions and exits the app.

## Zoom Meeting Information

Information on the Zoom meeting for nighttime observing (Zoom link, meeting ID, password) will be printed to the terminal above the menu.

## Opening and Closing Individual VNC Sessions

The user can close individual VNC sessions, by simply closing the VNC viewer window for that session (using whatever UI scheme is used by their local OS).  To reopen a session, just type the name at the command prompt.  For example, if I close `control0`  session and later I want it back, I just type `control0`  in the app command line.

## Getting a List of VNC Sessions

The `l` command lists the available VNC sessions.  For example:

```
> l
     INFO: Recieved command "l"
     INFO: Connecting to kvnc@mosfire.keck.hawaii.edu to get VNC sessions list

Sessions found for account 'mosfire3':
  control0     :19   mosfire-mosfire3-control0
  control1     :20   mosfire-mosfire3-control1
  control2     :21   mosfire-mosfire3-control2
  telstatus    :22   mosfire-mosfire3-telstatus
```

in this example, we see that there are the usual 4 VNC sessions for MOSFIRE.

## Uploading a log file to Keck

The `u` command will copy your local log file to a Keck computer.  This will only be useful if the software has established SSH connections to Keck, so it will not help in the case of catastrophic problems.  If you upload a log, you need to tell Keck Staff when you upload it and tell them which instrument you are logged in to and when you uploaded it.  These logs are not permanently stored and may be overwritten by other users, so if you want your log examined for issues, notify Keck Staff promptly.

# Troubleshooting Common Problems

Verbose debug information is logged to the `RemoteObserving/logs/` folder.  Log files are created based on the UTC date.

If you need assistance, please email [remote-observing@keck.hawaii.edu](mailto:remote-observing@keck.hawaii.edu) and attach the most recent log file from the logs folder.

## Can not see entire VNC desktop / VNC desktop is small

If the user can not see the entire VNC desktop of the remote computer or if the VNC desktop is rendered small and hard to read, then try to look for sizing options on the local VNC viewer.  For some users, scaling the VNC screen to the window may be a good option to reveal areas they can not see at the cost of smaller UI element size.  For others, rendering the window very small may be worse than having to scroll around the desktop.  The local VNC viewer client will have options for controlling this behavior.  The best solution is to have a lot of local screen real estate (pixel count) and a lot of screen area (inches).  There is more detail is the [Keck Remote Observing Policy](https://www2.keck.hawaii.edu/realpublic/inst/mainland_observing/policy).

## Connection Quality Problems

If your connection quality is poor (bad color rendition, blurry (compressed) graphics, etc., play with the quality and color settings on the local VNC viewer client software.  There's a tradeoff between responsiveness and quality as you would imagine.  The default option set is `--FullColor`  (in your local config file), try with other settings.  There is also a quality adjustment option for most VNC viewers.

Another option would simply be to use fewer VNC sessions.  If you can get all your GUIs on to 3 sessions instead of 4, that helps.

A more extreme version would be to only keep one or two sessions open at a time and then open and close them as needded.  You can close a particular VNC session by closing that VNC viewer window and then reopen it from the app's command line.  

## No Sounds

VNC does not carry sounds, so we have a separate system for playing instrument sounds such as "exposure complete" indicators on the remote machine.  This system has several moving parts, so troubleshooting can be challenging.  The vast majority of sound problems however are local to the users machine.  To play a test sound, type the `p` command.  This will play a local sound file (it will need to be downloaded on the first instance of this).  If you can't hear this test sound (the quality is poor and scratchy, but it sounds like a doorbell), then check your local machine's volume settings and speaker configuration.  You may also not have configured your local `aplay` instance properly.

# Upgrading the Software

The software does a simple check to see if it is the latest released version.  You can see a log line with this information on startup, or you can get the saem result using the `v` command.

Upgrading the software is done via a `git pull` in the directory where the software is installed.  If your software version is earlier than v1.0, this may require rebuilding your `local_config.yaml` file.  If you need to do this, just copy values from your old local config file in to a new one generated from the template as per the instructions above.
