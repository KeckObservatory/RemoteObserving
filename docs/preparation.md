# Preparing for Remote Observing at Keck

**IMPORTANT**: Last minute additions of observers to an observing night will not be possible.  Observers **must** complete the items below at least two days ahead of time.

### 1) Have an approved remote observing request

You must have an approved remote observing request before you can observe remotely.  Please submit your request from your [Observer Login Page](https://www2.keck.hawaii.edu/inst/PILogin/login.php).

### 2) Be listed as an observer

Each person wanting to connect **must** be listed in the [Keck Observing Schedule](https://www2.keck.hawaii.edu/observing/keckSchedule/keckSchedule.php) as an observer.

The schedule is filled based on your remote observing request, it must be done at least **two days in advance of your run**.

### 3) Upload your SSH key

- Generate ssh public/private key pair **(do not set a passphrase)**

```
cd ~/.ssh
ssh-keygen -t ed25519
```

- Upload your **public** key file at your [Observer Login Page](https://www2.keck.hawaii.edu/inst/PILogin/login.php). Click on "Manage Your Remote Observing SSH Key" and follow the instructions.

- After you have uploaded the key, note the "API key".  This will be a long string of letters and numbers.  You will need this key to connect (see the [installation instructions](installation.md) section titled "Configure Keck Remote Observing Software").

# Hardware Recommendations

## Displays

The primary hardware requirement for running Keck VNCs is screen space.  Previous incarnations of the remote observing system have used four (4) 1920x1200 monitors (~24 inch diagonal) and placed one VNC session per monitor.  An alternative setup would be to use a single, very large 4k monitor and place the four VNC sessions on that one monitor.  In order for the VNC sessions to be of reasonable physical size, the monitor would have to be 43-48 inches (we've found that even 43 inches may be a bit on the small size, see below).  The pixel pitch which we used which works well is 0.272 mm/pixel (or about 93 pixels per inch) for our four 24 inch monitor setup.

We have also tried a 43 inch 4k resolution TV screen (which works out to about 103 ppi), but it is less readable at that size.  The advantage of a single 4k monitor is that it is easy to have a second monitor beside it which is dedicated to the Zoom connection or to a web browser for documentation or displaying weather conditions.

## Computer Recommendations

A number of computer hardware configurations have been tested.  Various Intel based computers running linux, numerous Mac laptops and desktops (both Intel based and Apple silicon based), and even a Raspberry Pi 4.
