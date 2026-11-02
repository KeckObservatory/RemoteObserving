# Running the Keck Remote Observing Software

From the command line, run `start_keck_viewers` followed by the name of the instrument account assigned for your observing night (e.g. `kcwi1`, `mosfire2`).  Running the script without options will start 4 VNC sessions (control0, control1, control2, telstatus) and the soundplayer.

```
start_keck_viewers [instrument account]
```

A brief log will be printed to the terminal.  **Please note any WARNING or ERROR lines which appear there.**  Those will have human readable messages about anything that may have gone wrong and are often easily fixable by users.

You can find the instrument account assigned to your night on the [Keck Observing Schedule](https://www2.keck.hawaii.edu/observing/keckSchedule/keckSchedule.php).

If `start_keck_viewers` is not in your `PATH`, then either specify the full path for the executable or `cd` into the directory where the remote observing client software is installed.

Be sure to exit the script by using the 'q' quit option to ensure all VNC processes, SSH tunnels, and authentication are terminated properly.

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
