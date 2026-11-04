# Troubleshooting Common Problems

Verbose debug information is logged to the `RemoteObserving/logs/` folder.  Log files are created based on the UTC date.

If you need assistance, please submit a ticket to our [remote observing help desk](https://keckobservatory.atlassian.net/servicedesk/customer/portals) and attach the most recent log file from the logs folder.

## Can not see entire VNC desktop / VNC desktop is small

If the user can not see the entire VNC desktop of the remote computer or if the VNC desktop is rendered small and hard to read, then try to look for sizing options on the local VNC viewer.  For some users, scaling the VNC screen to the window may be a good option to reveal areas they can not see at the cost of smaller UI element size.  For others, rendering the window very small may be worse than having to scroll around the desktop.  The local VNC viewer client will have options for controlling this behavior.  The best solution is to have a lot of local screen real estate (pixel count) and a lot of screen area (inches).  There is more detail is the [Keck Remote Observing Policy](policy.md).

## Connection Quality Problems

If your connection quality is poor (bad color rendition, blurry (compressed) graphics, etc., play with the quality and color settings on the local VNC viewer client software.  There's a tradeoff between responsiveness and quality as you would imagine.  The default option set is `--FullColor`  (in your local config file), try with other settings.  There is also a quality adjustment option for most VNC viewers.

Another option would simply be to use fewer VNC sessions.  If you can get all your GUIs on to 3 sessions instead of 4, that helps.

A more extreme version would be to only keep one or two sessions open at a time and then open and close them as needded.  You can close a particular VNC session by closing that VNC viewer window and then reopen it from the app's command line.  

## No Sounds

VNC does not carry sounds, so we have a separate system for playing instrument sounds such as "exposure complete" indicators on the remote machine.  This system has several moving parts, so troubleshooting can be challenging.  The vast majority of sound problems however are local to the users machine.  To play a test sound, type the `p` command.  This will play a local sound file (it will need to be downloaded on the first instance of this).  If you can't hear this test sound (the quality is poor and scratchy, but it sounds like a doorbell), then check your local machine's volume settings and speaker configuration.  You may also not have configured your local `aplay` instance properly.

## No Sounds on macOS

The Remote Observing software triggers sounds using one of several `soundplay` executables packaged with the software (in the `soundplayer/` subdirectory).  This has not been compiled on macOS for ARM (for "Apple Silicon") and relies on Apple's Rosetta software to convert an `x86_64` executable to something which can execute on modern Apple hardware.

Normally the need to run the executable through Rosetta is detected automatically, but since we are calling the executable within a python program, it appears this is not happening.  Thus, if you are not getting sounds and everything else appears to be working, what may be happening is that the executable is not getting routed through Rosetta to be translated for Apple Silicon.

The workaround for this is to manually call the executable once from the command line.  This attaches the proper metadata to the executable and it will work properly from within python thereafter.  This means one should navigate to the `soundplayer/` directory and call `arch -x86_64 soundplay.darwin.x86_64` once.  Ignore the errors, and `control-c` out immediately.  After that, future connections to sounds via the Remote Observing software should run normally.
