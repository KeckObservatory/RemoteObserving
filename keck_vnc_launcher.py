#! /usr/bin/env python3

## Import standard modules
import os
import argparse
import atexit
from datetime import datetime, timedelta
from getpass import getpass
import json
import logging
import os
from pathlib import Path
import platform
import re
import socket
import subprocess
import sys
from threading import Thread
import time
import traceback
import requests
import warnings
import yaml

## Import local modules
import soundplay


## Module vars
__version__ = '3.0.0'
supportEmail = 'remote-observing@keck.hawaii.edu'
KRO_API = 'https://www3.keck.hawaii.edu/api/kroApi'
SESSION_NAMES = ('control0', 'control1', 'control2',
                 'analysis0', 'analysis1', 'analysis2',
                 'telanalys', 'telstatus')
KROException = Exception


##-------------------------------------------------------------------------
## Main
##-------------------------------------------------------------------------
def main():
    args = create_parser()
    create_logger(args)
    kvl = KeckVncLauncher(args)
    #catch all exceptions so we can exit gracefully
    try:
        kvl.start()
    except Exception as error:
        kvl.handle_fatal_error(error)


##-------------------------------------------------------------------------
## Create argument parser
##-------------------------------------------------------------------------
def create_parser():
    ## create a parser object for understanding command-line arguments
    description = (f"Keck VNC Launcher (v{__version__}). This program is used "
                   f"by approved Keck Remote Observing sites to launch VNC "
                   f"sessions for the specified instrument account. For "
                   f"help or information on how to configure the code, please "
                   f"see the included README.md file or email "
                   f"{supportEmail}")
    parser = argparse.ArgumentParser(description=description)

    ## add flags
    parser.add_argument("--test", dest="test",
        default=False, action="store_true",
        help="Test system rather than connect to VNC sessions.")
    parser.add_argument("--authonly", dest="authonly",
        default=False, action="store_true",
        help="Authenticate through firewall, but do not start VNC sessions.")
    parser.add_argument("--nosound", dest="nosound",
        default=False, action="store_true",
        help="Skip start of soundplay application.")
    parser.add_argument("--viewonly", dest="viewonly",
        default=False, action="store_true",
        help="Open VNC sessions in View Only mode (only for TigerVnC viewer)")
    parser.add_argument("-v", "--verbose", dest="verbose",
        default=False, action="store_true",
        help="Be verbose.")
    for name in SESSION_NAMES:
        parser.add_argument(f"--{name}",
            dest=name,
            default=False,
            action="store_true",
            help=f"Open {name} VNC session")

    ## add arguments
    parser.add_argument("account", type=str.lower, nargs='?', default='',
                        help="The user account.")

    ## add options
    parser.add_argument("-c", "--config", dest="config", type=str,
        help="Path to local configuration file.")
    parser.add_argument("--vncserver", type=str,
        help="Name of VNC server to connect to.  Takes precedence over all.")
    parser.add_argument( '--vncports', nargs='+', type=str,
        help="Numerical list of VNC ports to connect to.  Takes precedence over all.")

    #parse
    args = parser.parse_args()

    ## If authonly is set, also set nosound because if the user doesn't want
    ## VNCs, they likely don't want sound as well.
    if args.authonly is True:
        args.nosound = True

    ## Change default behavior if no account is given.
    if args.account == '':
        ## Message user to specify an instrument account
        print()
        print("    ----------------------------------------------------------------")
        print("    Due to updates to Keck's internal security systems, we no longer")
        print("    support running start_keck_viewers without an instrument account")
        print("    argument.")
        print()
        print("    If you wish to authenticate through the firewall without opening")
        print("    VNC sessions, run start_keck_viewers with an instrument account")
        print("    and the --authonly flag.")
        print("    ----------------------------------------------------------------")
        print()
        sys.exit(0)

    return args


##-------------------------------------------------------------------------
## Create logger
##-------------------------------------------------------------------------
def create_logger(args):

    ## Create logger object
    log = logging.getLogger('KRO')

    ## Only add handlers if none already exist (eliminates duplicate lines)
    if len(log.handlers) > 0:
        return

    #create log file and log dir if not exist
    try:
        Path('logs/').mkdir(parents=True, exist_ok=True)
    except PermissionError as error:
        print(str(error))
        print(f"ERROR: Unable to create logger at logs/")
        print("Make sure you have write access to this directory.\n")
        log.info("EXITING APP\n")
        sys.exit(1)

    # Set up formats
    logFormat_no_time = logging.Formatter(' %(levelname)8s: %(message)s')
    logFormat_no_time.converter = time.gmtime
    logFormat_with_time = logging.Formatter('%(asctime)s UT - %(levelname)s: %(message)s')
    logFormat_with_time.converter = time.gmtime

    #stream/console handler
    logConsoleHandler = logging.StreamHandler()
    if args.verbose is True:
        logConsoleHandler.setLevel(logging.DEBUG)
        logConsoleHandler.setFormatter(logFormat_with_time)
    else:
        logConsoleHandler.setLevel(logging.INFO)
        logConsoleHandler.setFormatter(logFormat_no_time)
    log.addHandler(logConsoleHandler)

    #file handler (full debug logging)
    ymd = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    logFile = Path(f'logs/keck-remote-log-utc-{ymd}.txt')
    logFileHandler = logging.FileHandler(logFile)
    logFileHandler.setLevel(logging.DEBUG)
    logFileHandler.setFormatter(logFormat_with_time)
    log.addHandler(logFileHandler)


##-------------------------------------------------------------------------
## Is the local port in use?
##-------------------------------------------------------------------------
def is_local_port_in_use_lsof(port):
    '''Determine if the specified local port is in use using the lsof
    command line tool.
    '''
    cmd = f'lsof -i -P -n | grep LISTEN | grep ":{port} (LISTEN)" | grep -v grep'
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    data = proc.communicate()[0]
    data = data.decode("utf-8").strip()
    return (len(data) != 0)


def is_local_port_in_use_socket(port):
    '''Determine if the specified local port is in use using the python
    socket package.
    '''
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0


is_local_port_in_use = is_local_port_in_use_socket


##-------------------------------------------------------------------------
## Define VNC Session Object
##-------------------------------------------------------------------------
class VNCSession(object):
    '''An object to contain information about a VNC session.
    '''
    def __init__(self, name=None, display=None, desktop=None, user=None, pid=None):
        if name is None and display is not None:
            try:
                name = desktop.split('-')[2]
            except IndexError:
                name = desktop

        self.name = name
        self.display = display
        self.desktop = desktop
        self.user = user
        self.pid = pid

    def __str__(self):
        return f"  {self.name:12s} {self.display:5s}"


##-------------------------------------------------------------------------
## Define SSH Tunnel Object
##-------------------------------------------------------------------------
class SSHTunnel(object):
    '''An object to contain information about an SSH tunnel.
    '''
    def __init__(self, server, username, ssh_pkey, remote_port, local_port,
                 session_name='unknown', timeout=10,
                 ssh_additional_kex=None,
                 ssh_additional_hostkeyalgo=None,
                 ssh_additional_keytypes=None,
                 proxy_jump=None):
        self.log = logging.getLogger('KRO')
        self.server = server
        self.username = username
        self.ssh_pkey = ssh_pkey
        self.remote_port = remote_port
        self.local_port = local_port
        self.session_name = session_name
        self.remote_connection = f'{username}@{server}:{remote_port}'
        self.ssh_additional_kex = ssh_additional_kex
        self.ssh_additional_hostkeyalgo = ssh_additional_hostkeyalgo
        self.ssh_additional_keytypes = ssh_additional_keytypes

        address_and_port = f"{username}@{server}:{remote_port}"
        self.log.info(f"Opening SSH tunnel for {address_and_port} "
                 f"on local port {local_port}.")

        if re.match('svncserver\d.keck.hawaii.edu', server) is not None:
            self.log.debug('Extending timeout for svncserver connections')
            timeout = 60

        # We now know everything we need to know in order to establish the
        # tunnel. Build the command line options and start the child process.
        # The -N and -T options below are somewhat exotic: they request that
        # the login process not execute any commands and that the server does
        # not allocate a pseudo-terminal for the established connection.

        forwarding = f"{local_port}:localhost:{remote_port}"
        if proxy_jump is None:
            cmd = ['ssh', server, '-l', username, '-L', forwarding, '-N', '-T', '-x']
        else:
            cmd = ['ssh', '-J', f"{username}@{proxy_jump}", f"{username}@{server}", '-L', forwarding, '-N', '-T', '-x']
        cmd.append('-oStrictHostKeyChecking=no')
        cmd.append('-oCompression=yes')

        if self.ssh_additional_kex is not None:
            cmd.append('-oKexAlgorithms=' + self.ssh_additional_kex)
        if self.ssh_additional_hostkeyalgo is not None:
            cmd.append('-oHostKeyAlgorithms=' + self.ssh_additional_hostkeyalgo)
        if self.ssh_additional_keytypes is not None:
            cmd.append('-oPubkeyAcceptedKeyTypes=' + self.ssh_additional_keytypes)

        if ssh_pkey is not None:
            cmd.append('-i')
            cmd.append(ssh_pkey)

        self.command = ' '.join(cmd)
        self.log.debug(f'ssh command: {self.command}')
        self.proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)

        # Having started the process let's make sure it's actually running.
        # First try polling,  then confirm the requested local port is in use.
        # It's a fatal error if either check fails.

        if self.proc.poll() is not None:
            raise RuntimeError('subprocess failed to execute ssh')

        # A delay is built-in here as it takes some finite amount of time for
        # ssh to establish the tunnel. 

        waittime = 0.1
        checks = int(timeout/waittime)
        while checks > 0:
            result = is_local_port_in_use(local_port)
            if result == True:
                break
            elif self.proc.poll() is not None:
                raise RuntimeError('ssh command exited unexpectedly')

            checks -= 1
            time.sleep(waittime)

        if checks == 0:
            raise RuntimeError(f'ssh tunnel failed to open after {timeout:.0f} seconds')


    def close(self):
        '''Close this SSH tunnel
        '''
        self.log.info(f" Closing SSH tunnel for local port {self.local_port}: {self.session_name}")
        self.proc.kill()


    def __str__(self):
        address_and_port = f"{self.username}@{self.server}:{self.remote_port}"
        return f"SSH tunnel for {address_and_port} on local port {self.local_port}."


##-------------------------------------------------------------------------
## Define SSH Proxy Object
##-------------------------------------------------------------------------
class SSHProxy(object):
    '''An object to contain information about an SSH proxy.
    '''
    def __init__(self, server, username, ssh_pkey, local_port,
                 session_name='unknown', timeout=10,
                 ssh_additional_kex=None,
                 ssh_additional_hostkeyalgo=None,
                 ssh_additional_keytypes=None,
                 ):
        self.log = logging.getLogger('KRO')
        self.server = server
        self.username = username
        self.ssh_pkey = ssh_pkey
        self.local_port = local_port
        self.session_name = session_name
        self.remote_connection = f'{username}@{server}'
        self.ssh_additional_kex = ssh_additional_kex
        self.ssh_additional_hostkeyalgo = ssh_additional_hostkeyalgo
        self.ssh_additional_keytypes = ssh_additional_keytypes

        # We now know everything we need to know in order to establish the
        # tunnel. Build the command line options and start the child process.
        # The -N and -T options below are somewhat exotic: they request that
        # the login process not execute any commands and that the server does
        # not allocate a pseudo-terminal for the established connection.

        cmd = ['ssh', server, '-l', username, '-N', '-T', '-x', '-D', f"{local_port}"]
        cmd.append('-oStrictHostKeyChecking=no')
        cmd.append('-oCompression=yes')

        if self.ssh_additional_kex is not None:
            cmd.append('-oKexAlgorithms=' + self.ssh_additional_kex)
        if self.ssh_additional_hostkeyalgo is not None:
            cmd.append('-oHostKeyAlgorithms=' + self.ssh_additional_hostkeyalgo)
        if self.ssh_additional_keytypes is not None:
            cmd.append('-oPubkeyAcceptedKeyTypes=' + self.ssh_additional_keytypes)

        if ssh_pkey is not None:
            cmd.append('-i')
            cmd.append(ssh_pkey)

        self.command = ' '.join(cmd)
        self.log.debug(f'ssh command: {self.command}')
        self.proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)

        # Having started the process let's make sure it's actually running.
        # First try polling,  then confirm the requested local port is in use.
        # It's a fatal error if either check fails.

        if self.proc.poll() is not None:
            raise RuntimeError('subprocess failed to execute ssh')

        # A delay is built-in here as it takes some finite amount of time for
        # ssh to establish the tunnel. 

        waittime = 0.1
        checks = int(timeout/waittime)
        while checks > 0:
            result = is_local_port_in_use(local_port)
            if result == True:
                break
            elif self.proc.poll() is not None:
                raise RuntimeError('ssh command exited unexpectedly')

            checks -= 1
            time.sleep(waittime)

        if checks == 0:
            raise RuntimeError(f'ssh tunnel failed to open after {timeout:.0f} seconds')


    def close(self):
        '''Close this SSH tunnel
        '''
        self.log.info(f" Closing SSH tunnel for local port {self.local_port}: {self.session_name}")
        self.proc.kill()


    def __str__(self):
        address_and_port = f"{self.username}@{self.server}:{self.remote_port}"
        return f"SSH tunnel for {address_and_port} on local port {self.local_port}."


##-------------------------------------------------------------------------
## Define Keck VNC Launcher
##-------------------------------------------------------------------------
class KeckVncLauncher(object):

    def __init__(self, args):
        #init vars we need to shutdown app properly
        self.config = None
        self.log = None
        self.sound = None
        self.ssh_tunnels = dict()
        self.vnc_threads = list()
        self.vnc_processes = list()
        self.firewall_requested = False
        self.instrument = None
        self.vncserver = None
        self.ssh_key_valid = False
        self.ssh_additional_kex = '+diffie-hellman-group1-sha1'
        self.ssh_additional_hostkeyalgo = '+ssh-dss,ssh-rsa'
        self.ssh_additional_keytypes = '+ssh-dss,ssh-rsa'
        self.exit = False
        self.geometry = list()
        self.tigervnc = None
        self.vncviewer_has_geometry = None
        self.api_data = None

        self.args = args
        self.log = logging.getLogger('KRO')

        #default start sessions
        self.default_sessions = []
        self.sessions_found = []

        #local port start (can be overridden by config file)
        self.LOCAL_PORT_START = 5901

        #ssh key constants
        self.kvnc_account = 'kvnc'


    ##-------------------------------------------------------------------------
    ## Start point (main)
    ##-------------------------------------------------------------------------
    def start(self):
        '''Start the main program control loop.
        
        This contains the basic sequence of events for running the program.
        '''

        ##---------------------------------------------------------------------
        ## Parse command line args
        self.log.debug("\n***** PROGRAM STARTED *****")
        self.log.debug(f"Command: {' '.join(sys.argv)}")

        ##---------------------------------------------------------------------
        ## Log basic system info
        self.log_system_info()
        self.test_yaml_version()
        self.check_version()
        if self.args.authonly is False:
            self.get_display_info()

        ##---------------------------------------------------------------------
        ## Read configuration
        self.get_config()
        self.check_config()
        if self.args.authonly is False:
            self.get_vncviewer_properties()

        ##---------------------------------------------------------------------
        ## Run tests
        if self.args.test is True:
            self.test_all()
            self.exit_app()

        ##---------------------------------------------------------------------
        # Verify Tiger VNC Config
        if self.args.authonly is False:
            if self.test_tigervnc() > 0:
                self.log.error('TigerVNC is not configured properly. See instructions.')
                self.log.error('This can have negative effects on other users.')
                self.log.error('Exiting program.')
                self.exit_app()

        ##---------------------------------------------------------------------
        ## Get connect info from API
        if self.api_key:
            self.get_api_data(self.api_key, self.args.account)
            if self.api_data is None:
                self.exit_app('API query failed.')

        ##---------------------------------------------------------------------
        ## Open web proxy if requested
        if self.config.get('proxy_port', None) is not None:
            self.open_ssh_for_proxy()

        if self.args.authonly is False:
            ##-----------------------------------------------------------------
            ## Determine sessions to open
            self.sessions_requested = self.get_sessions_requested(self.args)

            ##-----------------------------------------------------------------
            ## Determine instrument
            self.instrument, self.tel = self.determine_instrument(self.args.account)
            if self.instrument is None:
                self.exit_app(f'Invalid instrument account: "{self.args.account}"')

            ##-----------------------------------------------------------------
            ## Determine VNC server
            self.vncserver = self.get_vnc_server(self.kvnc_account,
                                                 self.instrument)
            if self.vncserver is None:
                self.exit_app("Could not determine VNC server.")

            ##-----------------------------------------------------------------
            ## Determine VNC Sessions
            self.sessions_found = self.get_vnc_sessions(self.vncserver,
                                                        self.instrument,
                                                        self.kvnc_account,
                                                        self.args.account)

            if (not self.sessions_found or len(self.sessions_found) == 0):
                self.exit_app(f"No VNC sessions found for '{self.args.account}'")

            ##-----------------------------------------------------------------
            ## Open requested sessions
            self.calc_window_geometry()
            if self.args.vncports is not None:
                for port in self.args.vncports:
                    self.start_vnc_session(port)
            else:
                for session_name in self.sessions_requested:
                    self.start_vnc_session(session_name)

            ##-----------------------------------------------------------------
            ## Open Soundplay
            sound = None
            if self.args.nosound is False and self.config.get('nosound', False) != True:
                self.start_soundplay()

            ##-----------------------------------------------------------------
            ## Final output should be connection info
            if self.api_data is not None:
                self.view_connection_info()

        if self.args.authonly is False or self.is_proxy_open():
            ##---------------------------------------------------------------------
            ## Wait for quit signal, then all done
            atexit.register(self.exit_app, msg="App exit")
            self.prompt_menu()
            self.exit_app()


    ##-------------------------------------------------------------------------
    ## Retrieve or log basic system info
    ##-------------------------------------------------------------------------
    def log_system_info(self):
        '''Add info about the local system to the log for debugging
        '''
        try:
            uname_result = os.uname()
            self.log.debug(f'System Info: {uname_result}')
            if re.search('Microsoft', uname_result.release) is not None\
                or re.search('Microsoft', uname_result.version) is not None:
                self.log.warning("This system appears to be running linux within "
                                 "a Microsoft Windows environment. While this "
                                 "can work, it is not a supported mode of this "
                                 "software. WMKO will be unable to provide "
                                 "support for this mode of operation.")

            hostname = socket.gethostname()
            self.log.debug(f'System hostname: {hostname}')
            python_version_str = sys.version.replace("\n", " ")
            self.log.info(f'Python {python_version_str}')
            self.log.debug(f'yaml {yaml.__version__}')
            self.log.info(f'Remote Observing Software Version = {__version__}')
        except:
            self.log.error("Unable to log system info.")
            trace = traceback.format_exc()
            self.log.debug(trace)

        try:
            whereisssh = subprocess.check_output(['which', 'ssh'])
            self.log.debug(f'SSH command is {whereisssh.decode().strip()}')
            sshversion = subprocess.check_output(['ssh', '-V'],
                                    stderr=subprocess.STDOUT)
            self.log.debug(f'SSH version is {sshversion.decode().strip()}')
        except:
            self.log.error("Unable to log SSH info.")
            trace = traceback.format_exc()
            self.log.debug(trace)


    def check_version(self):
        '''Compare the version of the local software against releases available
        on GitHub.
        '''
        url = 'https://api.github.com/repos/KeckObservatory/RemoteObserving/releases'
        try:
            import requests
            from packaging import version
            self.log.debug("Checking for latest version available on GitHub")
            r = requests.get(url, timeout=5)
            result = r.json()
            remote_version = version.parse(result[0]['name'])
            self.log.debug(f'Retrieved remote release version: {remote_version}')
            local_version = version.parse(__version__)

            if remote_version == local_version:
                self.log.info(f'Your software is up to date (v{__version__})')
            elif remote_version < local_version:
                self.log.info(f'Your software (v{__version__}) is ahead of the released version')
            else:
                self.log.warning(f'Your local software (v{__version__}) is behind '
                                 f'the currently available version '
                                 f'(v{remote_version})')
                if remote_version.base_version == local_version.base_version:
                    self.log.warning('You may update by running "git pull" in '
                                     'the directory where the software is installed')
        except ModuleNotFoundError as e:
            self.log.warning("Unable to verify remote version")
            self.log.debug(e)
        except requests.ConnectionError as e:
            self.log.warning("Unable to verify remote version")
            self.log.debug(e)
        except Exception as e:
            self.log.warning("Unable to verify remote version")
            self.log.debug(e)


    def get_display_info(self):
        '''Determine the screen number and size
        '''
        #get screen dimensions
        #alternate command: xrandr |grep \* | awk '{print $1}'
        self.log.debug('Determining display info')
        self.screens = list()
        self.geometry = list()
        try:
            xpdyinfo = subprocess.run('xdpyinfo', stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, timeout=5)
        except FileNotFoundError as e:
            self.log.debug('xpdyinfo not found')
            self.log.debug(e)
            return
        except subprocess.TimeoutExpired as e:
            # If xpdyinfo fails just log and keep going
            self.log.debug('xpdyinfo failed')
            self.log.debug(e)
            return
        except TimeoutError as e:
            # If xpdyinfo fails just log and keep going
            self.log.debug('xpdyinfo failed')
            self.log.debug(e)
            return
        stdout = xpdyinfo.stdout.decode()
        if xpdyinfo.returncode != 0:
            self.log.debug(f'xpdyinfo failed')
            for line in stdout.split('\n'):
                self.log.debug(f"xdpyinfo: {line}")
            stderr = xpdyinfo.stderr.decode()
            for line in stderr.split('\n'):
                self.log.debug(f"xdpyinfo: {line}")
            return None
        find_nscreens = re.search('number of screens:\s+(\d+)', stdout)
        nscreens = int(find_nscreens.group(1)) if find_nscreens is not None else 1
        self.log.debug(f'Number of screens = {nscreens}')

        find_dimensions = re.findall('dimensions:\s+(\d+)x(\d+)', stdout)
        if len(find_dimensions) == 0:
            self.log.debug(f'Could not find screen dimensions')
            return None
        # convert values from strings to int
        self.screens = [[int(val) for val in line] for line in find_dimensions]
        for screen in self.screens:
            self.log.debug(f"Screen size: {screen[0]}x{screen[1]}")


    ##-------------------------------------------------------------------------
    ## Get & Check Configuration
    ##-------------------------------------------------------------------------
    def get_config(self):
        '''Read the configuration file.
        '''
        #define files to try loading in order of pref
        filenames=['local_config.yaml', 'keck_vnc_config.yaml']

        #if config file specified, put that at beginning of list
        filename = self.args.config
        if filename is not None:
            if not Path(filename).is_file():
                self.log.error(f'Specified config file "{filename}" does not exist.')
                self.exit_app()
            else:
                filenames.insert(0, filename)

        #find first file that exists
        file = None
        for f in filenames:
            if Path(f).is_file():
                file = f
                break
        if file is None:
            self.log.error(f'No config files found in list: {filenames}')
            self.exit_app()

        #load config file and make sure it has the info we need
        self.log.info(f'Using config file: {file}')

        # open file a first time just to log the raw contents
        contents = open(file).read()
        self.log.debug(f"Contents of config file:\n{contents}")

        # Look for syntax error in configuration file
        self.log.debug('Checking config format')
        configok = True
        lines = contents.split('\n')
        for line in lines:
            if re.match('^([\w_]+):[\w\d\'\"]', line):
                self.log.error(f'The format of the config is "keyword: value"')
                self.log.error(f'A space is missing in line: {line}')
                configok = False
            if re.match('^\s([\w_]+):\s?[\w\d\'\"]', line):
                self.log.error(f'The format of the config is "keyword: value"')
                self.log.error(f'There is a leading space in line: {line}')
                configok = False
        if configok is False:
            self.log.error('Exiting app')
            sys.exit(1)

        # open file a second time to properly read config
        config = yaml.load(open(file), Loader=yaml.FullLoader)

        for key in ['ssh_pkey', 'vncviewer', 'soundplayer', 'aplay']:
            if key in config.keys():
                config[key] = os.path.expanduser(config[key])
                config[key] = os.path.expandvars(config[key])

        cstr = "Parsed Configuration:\n"
        for key, c in config.items():
            cstr += f"\t{key} = " + str(c) + "\n"
        self.log.debug(cstr)

        self.config = config

        # Load some values
        self.ssh_pkey = self.config.get('ssh_pkey', None)
        lps = self.config.get('local_port_start', None)
        self.local_port = self.LOCAL_PORT_START if lps is None else lps


    def check_config(self):
        '''Do some basic checks on the configuration.
        '''

        #check API key config
        self.api_key = self.config.get('api_key', None)
        if self.api_key is None:
            self.log.error("API key is not set.")
        else:
            self.firewall_requested = True


    def get_vncviewer_properties(self):
        '''Determine whether we are using TigerVNC
        '''
        vncviewercmd = self.config.get('vncviewer', 'vncviewer')
        cmd = [vncviewercmd, '--help']
        self.log.debug(f'Checking VNC viewer: {" ".join(cmd)}')
        result = subprocess.run(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)

        output = result.stdout.decode() + '\n' + result.stderr.decode()
        if re.search(r'TigerVNC', output):
            self.log.info(f'We ARE using TigerVNC')
            self.tigervnc = True
        else:
            self.log.debug(f'We ARE NOT using TigerVNC')
            self.tigervnc = False

        if re.search(r'[Gg]eometry', output):
            self.log.info(f'Found geometry argument')
            self.vncviewer_has_geometry = True
        else:
            self.log.debug(f'Could not find geometry argument')
            self.vncviewer_has_geometry = False

        # TigerVNC Viewer 64-bit v1.10.1
        # VNC(R) Viewer 6.17.731 (r29523) x64 (Aug 3 2017 17:19:47)
        self.log.debug(f"VNC Viewer Info:")
        for line in output.split('\n'):
            if line.strip('\n') != '':
                self.log.debug(f"  {line}")
            version_match = re.search('(\d+\.\d+\.\d+)', line)
            if version_match is not None:
                self.log.info(f'Matched VNC version pattern: {version_match.group(0)}')
                break

    def get_api_data(self, api_key, account):
        '''Get data from API which contains all info needed to connect.'''
        self.api_data = None

        #form API url and get data
        params = {'key': f'{self.api_key}',
                  'account': f"{account}"}
        self.log.info(f'Calling KRO API to get account info')
        self.log.debug(f'Using URL: {KRO_API} with {params}')
        data = None
        try:
            tick = datetime.now()
            data = requests.post(KRO_API, data=params, timeout=60)
            data = json.loads(data.text)
            for key in data.keys():
                self.log.debug(f"  Got data for {key}: {data[key]}")
            tock = datetime.now()
            duration = (tock-tick).total_seconds()
            self.log.debug(f'API call took {duration:.1f} s')
        except Exception as e:
            self.log.error(f'Could not get data from API.')
            self.log.error(str(e))
            return
        if data is None:
            self.log.error('No response from API.')
            return

        #Look for any errors
        stdmsg = ('API failed to retrieve connection info.  Please try again. '
                 f'If this reoccurs, email us at {supportEmail} or create a support ticket at: '
                  'https://keckobservatory.atlassian.net/servicedesk/customer/portals '
                  'and be sure to attach the log file.')
        stdmsg2 = ('Please check your Keck Observer Homepage for information '
                   'regarding when your key is approved and deployed according '
                   'to the observing schedule.')
        api_err_map = {
            'DATABASE_ERROR': stdmsg,
            'FIREWALL_INFO_ERROR': stdmsg,
            'INSTRUMENT_ACCOUNT_ERROR': f'API does not recognize instrument account "{self.args.account}"',
            'KVNC_INFO_ERROR':  stdmsg,
            'KVNC_STATUS_ERROR': stdmsg,
            'NO_API_KEY': f'No matching API key found. Please check your "api_key" config value.',
            'SSH_KEY_NOT_APPROVED': f'Your SSH key is not yet approved.\n{stdmsg2}',
            'SSH_KEY_NOT_DEPLOYED': f'Your SSH key is not deployed.\n{stdmsg2}',
        } 
        code = data.get('apiCode', '').upper()
        self.log.debug(f'API response code is: {code}')
        if code in api_err_map:
            self.log.debug(f'API error code: {code}')
            self.log.error(api_err_map[code])
            return
        if code != 'SUCCESS':
            self.log.error(f'Invalid status code returned from API: {code}')
            return

        #all good
        self.api_data = data
        self.log.debug('API call was successful')


    ##-------------------------------------------------------------------------
    ## Get sessions to open
    ##-------------------------------------------------------------------------
    def get_sessions_requested(self, args):
        '''Determine which sessions to open based on command line arguments
        '''
        sessions = list()
        # First check the command line arguments
        for session in SESSION_NAMES:
            try:
                requested = getattr(args, session)
            except AttributeError:
                continue
            if requested == True:
                sessions.append(session)

        if len(sessions) > 0:
            self.log.debug(f'Got {sessions} sessions from command line args')

        # Use the configuration file if no command line arguments specified
        if len(sessions) == 0:
            sessions = self.config.get('default_sessions', [])
            self.log.debug(f'Got {sessions} sessions from configuration file')

        # Finally use the default sessions list as a last resort
        if len(sessions) == 0:
            sessions = self.default_sessions
            self.log.debug(f'Using default sessions: {sessions}')

        self.log.debug(f'Sessions to open: {sessions}')
        return sessions


    ##-------------------------------------------------------------------------
    ## Determine Instrument
    ##-------------------------------------------------------------------------
    def determine_instrument(self, account):
        '''Given an account name, determine the instrument and telescope.
        '''
        accounts = {'mosfire':  [f'mosfire{i}' for i in range(1,10)],
                    'hires':    [f'hires{i}'   for i in range(1,10)],
                    'osiris':   [f'osiris{i}'  for i in range(1,10)],
                    'lris':     [f'lris{i}'    for i in range(1,10)],
                    'nires':    [f'nires{i}'   for i in range(1,10)],
                    'deimos':   [f'deimos{i}'  for i in range(1,10)],
                    'esi':      [f'esi{i}'     for i in range(1,10)],
                    'nirc2':    [f'nirc{i}'    for i in range(1,10)],
                    'nirspec':  [f'nspec{i}'   for i in range(1,10)],
                    'kcwi':     [f'kcwi{i}'    for i in range(1,10)],
                    'kpf':      [f'kpf{i}'     for i in range(1,10)],
                    'k1ao':     ['k1obsao'],
                    'k2ao':     ['k2obsao'],
                    'k1inst':   ['k1insttech'],
                    'k2inst':   ['k2insttech'],
                    'k1pcs':   ['k1pcs'],
                    'k2pcs':   ['k2pcs'],
                   }
        accounts['mosfire'].append('moseng')
        accounts['hires'].append('hireseng')
        accounts['osiris'].append('osrseng')
        accounts['lris'].append('lriseng')
        accounts['nires'].append('nireseng')
        accounts['deimos'].append('dmoseng')
        accounts['esi'].append('esieng')
        accounts['nirc2'].append('nirc2eng')
        accounts['nirspec'].append('nspeceng')
        accounts['kcwi'].append('kcwieng')
        accounts['kpf'].append('kpfeng')

        telescope = {'mosfire': 1,
                     'hires':   1,
                     'osiris':  1,
                     'lris':    1,
                     'kpf':     1,
                     'k1ao':    1,
                     'k1inst':  1,
                     'k1pcs':   1,
                     'nires':   2,
                     'deimos':  2,
                     'esi':     2,
                     'nirc2':   2,
                     'nirspec': 2,
                     'kcwi':    2,
                     'k2ao':    2,
                     'k2inst':  2,
                     'k2pcs':   2,
                    }

        for instrument in accounts.keys():
            if account.lower() in accounts[instrument]:
                return instrument, telescope[instrument]

        return None, None


    ##-------------------------------------------------------------------------
    ## SSH Command
    ##-------------------------------------------------------------------------
    def do_ssh_cmd(self, cmd, server, account):
        '''Utility function for opening ssh client, executing command and
        closing.
        '''
        timeout = self.config.get('ssh_timeout', 30)

        output = None
        self.log.debug(f'Trying SSH connect to {server} as {account}:')
        if re.match('svncserver\d.keck.hawaii.edu', server) is not None:
            self.log.debug('Extending timeout for svncserver connections')
            timeout = 60

        command = ['ssh', server, '-l', account, '-T', '-x']
        if self.args.verbose is True:
            command.append('-v')
            command.append('-v')

        if self.ssh_pkey is not None:
            command.append('-i')
            command.append(self.ssh_pkey)

        if self.ssh_additional_kex is not None:
            command.append('-oKexAlgorithms=' + self.ssh_additional_kex)
        if self.ssh_additional_hostkeyalgo is not None:
            command.append('-oHostKeyAlgorithms=' + self.ssh_additional_keytypes)
        if self.ssh_additional_keytypes is not None:
            command.append('-oPubkeyAcceptedKeyTypes=' + self.ssh_additional_keytypes)

        command.append('-oStrictHostKeyChecking=no')
        command.append(cmd)
        self.log.debug('ssh command: ' + ' '.join(command))

        proc = subprocess.run(command, timeout=timeout,
                               stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        stdout = proc.stdout.strip().decode()
        self.log.debug(f'RETURNCODE = {proc.returncode}')
        for line in stdout.split('\n'):
            self.log.debug(f'STDOUT: {line}')
        for line in proc.stderr.strip().decode().split('\n'):
            if line not in ['', ' ']:
                self.log.debug(f'STDERR: {line}')

        if proc.returncode != 0:
            message = '  command failed with error ' + str(proc.returncode)
            self.log.error(message)

            if re.search('timeout', stdout.lower()):
                self.log.error('  SSH timeouts may be due to network instability.')
                self.log.error('  Please retry to see if the problem is intermittant.')

            # Older ssh binaries don't like the '+' option when specifying
            # key exchange algorithms. Any binaries that old won't need the
            # value specified at all, so remove the option for all future
            # ssh calls.

            # This check is only made here instead of in all the places
            # KexAlgorithms is specified because do_ssh_cmd() is always
            # the first method to attempt an ssh connection regardless of
            # how the launcher is invoked.

            # If the recursive call still fails that's a real failure that
            # the caller will need to address.

            if self.ssh_additional_kex is not None:
                self.ssh_additional_kex = None
                self.log.info('Retrying ssh with different key exchange flag')
                return self.do_ssh_cmd(cmd, server, account)

        # The first line might be a warning about accepting a ssh host key.
        # Check for that, and get rid of it from the output.

        lines = stdout.split('\n')

        if len(lines) > 1:
            if 'Warning: Permanently added' in lines[0]:
                self.log.debug('Removed warning from command output:')
                self.log.debug(lines[0])
                lines = lines[1:]
                stdout = '\n'.join(lines)

        return stdout, proc.returncode


    ##-------------------------------------------------------------------------
    ## Determine VNC Server
    ##-------------------------------------------------------------------------
    def get_vnc_server(self, account, instrument):
        '''Determine the VNC server to connect to given the instrument.
        '''

        #cmd line option
        if self.args.vncserver is not None:
            self.log.info("Using VNC server defined on command line")
            vncserver = self.args.vncserver

        # Manual override for PCS
        elif instrument in ['k1pcs', 'k2pcs']:
            vncserver = f"vm-{instrument}"

        #API Route
        elif self.api_data:
            self.log.info(f"Determining VNC server for '{self.args.account}' (via API)")
            vncserver = self.api_data.get('vncserver')
            if not vncserver:
                self.log.error(f'Could not determine VNC server from API')

        if vncserver:
            self.log.info(f"Got VNC server: '{vncserver}'")

        if vncserver is not None and 'keck.hawaii.edu' not in vncserver:
            vncserver += '.keck.hawaii.edu'

        return vncserver


    ##-------------------------------------------------------------------------
    ## Determine VNC Sessions
    ##-------------------------------------------------------------------------
    def get_vnc_sessions(self, vncserver, instrument, account, instr_account, requery=False):
        '''Determine the VNC sessions running for the given account.
        '''
        sessions = list()

        #If vncports defined use that
        if self.args.vncports is not None:
            self.log.info(f"Using VNC ports defined from command line.")
            for port in self.args.vncports:
                name = port
                if not port.startswith(':'): port = ':'+port
                s = VNCSession(name=name, display=port, user=self.args.account)
                sessions.append(s)
            return sessions

        #Override for PCS
        if instrument in ['k1pcs', 'k2pcs']:
            self.args.vncports = ['1']
            self.log.info(f"Guessing at VNC port for PCS: {self.args.vncports}")
            for port in self.args.vncports:
                name = port
                if not port.startswith(':'): port = ':'+port
                s = VNCSession(name=name, display=port, user=self.args.account)
                sessions.append(s)
            return sessions

        #If called from menu, requery API again 
        if self.api_key and requery:
            self.log.info(f"Recontacting API to get VNC sessions list")
            self.get_api_data(self.api_key, self.args.account)

        #API Route
        if self.api_data:
            vncports = self.api_data.get('vncports')
            if vncports is None or not isinstance(vncports, list):
                self.log.error(f'Could not determine get VNC session list from API')
                return sessions

            for vp in vncports:
                port = vp.get('port')
                name = vp.get('name')
                if port is None or name is None:
                    self.log.error('Invalid VNC session info: {port}, {name}')
                    continue
                s = VNCSession(name=name, display=port, user=self.args.account)
                sessions.append(s)

        #SSH Route
        else:
            self.log.info(f"Connecting to {account}@{vncserver} to get VNC sessions list")
            cmd = f'setenv INSTRUMENT {instrument}; kvncstatus -a'
            try:
                data, rc = self.do_ssh_cmd(cmd, vncserver, account)
            except Exception as e:
                self.log.error('  Failed: ' + str(e))
                trace = traceback.format_exc()
                self.log.debug(trace)
                data = ''

            if data is None:
                return sessions

            lines = data.split('\n')
            for line in lines:
                if line[0] != '#':
                    if len(line.split()) != 4:
                        self.log.error(f'Unable to parse line: "{line}"')
                    else:
                        display, desktop, user, pid = line.split()
                        s = VNCSession(display=display, desktop=desktop, user=user, pid=pid)
                        if s.user == instr_account:
                            sessions.append(s)

        #print and return
        self.log.debug(f'  Got {len(sessions)} sessions')
        for s in sessions:
            self.log.debug(s)
        return sessions


    ##-------------------------------------------------------------------------
    ## Calculate vnc windows size and position
    ##-------------------------------------------------------------------------
    def calc_window_geometry(self):
        '''If window positions are not set in config file, make a guess.
        '''
        window_positions = self.config.get('window_positions', None)
        if window_positions is not None:
            self.geometry = window_positions
        elif len(self.screens) > 0:
            self.log.debug(f"Calculating VNC window geometry...")
            num_win = len(self.sessions_requested)
            cols = 2
            rows = 2
            screen = self.screens[0]
            #get x/y coords (assume two rows)
            for row in range(0, rows):
                for col in range(0, cols):
                    x = round(col * screen[0]/cols)
                    y = round(row * screen[1]/rows)
                    if window_positions is not None:
                        index = len(self.geometry) % len(window_positions)
                        x = window_positions[index][0]
                        y = window_positions[index][1]
                    self.geometry.append([x, y])
        else:
            self.geometry = list()
        self.log.debug('geometry: ' + str(self.geometry))


    ##-------------------------------------------------------------------------
    ## Open ssh tunnel
    ##-------------------------------------------------------------------------
    def open_ssh_tunnel(self, server, username, ssh_pkey, remote_port,
                        local_port=None, session_name='unknown'):
        '''Open an SSH tunnel.
        
        If the local port is not specified attempt to find one dynamically.
        '''
        if local_port is None:
            for i in range(0,100):
                if is_local_port_in_use(self.local_port):
                    self.local_port += 1
                    continue
                else:
                    local_port = self.local_port
                    self.local_port += 1
                    break

        if local_port is None:
            self.log.error(f"Could not find an open local port for SSH tunnel "
                           f"to {username}@{server}:{remote_port}")
            self.local_port = self.LOCAL_PORT_START
            return False

        if server in ['vm-k1obs.keck.hawaii.edu', 'vm-k2obs.keck.hawaii.edu']:
            self.log.debug('Using proxy jump to open SSH tunnel')
            t = SSHTunnel(server, username, ssh_pkey, remote_port, local_port,
                          session_name=session_name,
                          timeout=self.config.get('ssh_timeout', 10),
                          ssh_additional_kex=self.ssh_additional_kex,
                          ssh_additional_hostkeyalgo=self.ssh_additional_hostkeyalgo,
                          ssh_additional_keytypes=self.ssh_additional_keytypes,
                          proxy_jump='mosfire.keck.hawaii.edu')
        else:
            t = SSHTunnel(server, username, ssh_pkey, remote_port, local_port,
                          session_name=session_name,
                          timeout=self.config.get('ssh_timeout', 10),
                          ssh_additional_kex=self.ssh_additional_kex,
                          ssh_additional_hostkeyalgo=self.ssh_additional_hostkeyalgo,
                          ssh_additional_keytypes=self.ssh_additional_keytypes,
                          )
        self.ssh_tunnels[local_port] = t
        return local_port


    ##-------------------------------------------------------------------------
    ## Open SSH For Proxy
    ##-------------------------------------------------------------------------
    def open_ssh_for_proxy(self):
        local_port = int(self.config.get('proxy_port'))
        if self.is_proxy_open() is True:
            self.log.warning(f'SSH proxy already open on port 8080')
            return
        if is_local_port_in_use(local_port) is True:
            self.log.warning(f'Port 8080 is in use, not starting proxy connection')
            return
        self.log.info(f'Opening SSH for proxy to port 8080')
        t = SSHProxy(self.api_data.get('vncserver'),
                     self.kvnc_account, self.ssh_pkey,
                     local_port,
                     session_name='proxy',
                     timeout=self.config.get('ssh_timeout', 10),
                     ssh_additional_kex=self.ssh_additional_kex,
                     ssh_additional_hostkeyalgo=self.ssh_additional_hostkeyalgo,
                     ssh_additional_keytypes=self.ssh_additional_keytypes,
                     )
        self.ssh_tunnels[local_port] = t
        return local_port


    def is_proxy_open(self):
        names = [self.ssh_tunnels[p].session_name for p in self.ssh_tunnels.keys()]
        return ('proxy' in names)


    ##-------------------------------------------------------------------------
    ## Start VNC session
    ##-------------------------------------------------------------------------
    def launch_vncviewer(self, vncserver, port, geometry=None):
        '''Open local VNC viewer program given a server and port.
        '''
        vncviewercmd = self.config.get('vncviewer', 'vncviewer')
        vncprefix = self.config.get('vncprefix', '')
        vncargs = self.config.get('vncargs', None)
        cmd = list()

        if isinstance(geometry, list) is True:
            if geometry[0] is not None and geometry[1] is not None:
                geometry_str = f'+{geometry[0]}+{geometry[1]}'
                self.log.debug(f'Geometry for vncviewer command: {geometry_str}')
            if len(geometry) == 3:
                display = geometry[2]
                # setenv DISPLAY ${xhostnam}:${xdispnum}.$screen
                self.log.debug(f'Display number for vncviewer command: {display}')
                os.environ['DISPLAY'] = f':{display}'

        cmd.append(vncviewercmd)
        if vncargs is not None:
            vncargs = vncargs.split()
            cmd.extend(vncargs)
        if self.args.viewonly == True:
            cmd.append('-ViewOnly')
        if self.tigervnc is True:
            cmd.append(f"-RemoteResize=0")
        if geometry is not None and geometry != '' and geometry_str is not None:
            cmd.append(f'-geometry={geometry_str}')
        cmd.append(f'{vncprefix}{vncserver}:{port:4d}')

        self.log.debug(f"VNC viewer command: {cmd}")
        null = subprocess.DEVNULL
        proc = subprocess.Popen(cmd, stdin=null, stdout=null, stderr=null)

        #append to proc list so we can terminate on app exit
        self.vnc_processes.append(proc)


    def start_vnc_session(self, session_name):
        '''Open VNC viewer program for a given session.
        '''
        self.log.info(f"Opening VNCviewer for '{session_name}'")

        #get session data by name
        session = None
        for s in self.sessions_found:
            if s.name == session_name:
                session = s
        if session is None:
            self.log.error(f"No server VNC session found for '{session_name}'.")
            self.print_sessions_found()
            return

        #determine vncserver
        vncserver = self.vncserver

        #get remote port
        display = int(session.display[1:])
        remote_port = int(f"59{display:02d}")

        ## If authenticating, open SSH tunnel for appropriate ports
        if self.firewall_requested == True:
            # determine if there is already a tunnel for this session
            local_port = None
            for p in self.ssh_tunnels.keys():
                t = self.ssh_tunnels[p]
                if t.session_name == session_name:
                    self.log.info(f"Found existing SSH tunnel on local port {p}")

                    # Check to make sure the tunnel is still working. It's not
                    # enough to check whether the process is still running,
                    # if the user has connection sharing set up the process
                    # will have exited but the tunnel will still be up and
                    # functional. Check the functional aspect first, and then
                    # think to ask why.

                    if is_local_port_in_use(p):
                        vncserver = 'localhost'
                        local_port = p
                    else:
                        status = t.proc.poll()
                        if status is not None:
                            error = f"SSH tunnel on local port {p} is dead ({status})"
                        else:
                            error = f"SSH tunnel on local port {p} was closed ({status})"
                        self.log.error(error)
                        del(self.ssh_tunnels[p])
                    break

            #open ssh tunnel if necessary
            if local_port is None:
                try:
                    local_port = self.open_ssh_tunnel(vncserver, self.kvnc_account,
                                                      self.ssh_pkey,
                                                      remote_port, None,
                                                      session_name=session_name)
                except:
                    self.log.error(f"Failed to open SSH tunnel for "
                              f"{self.kvnc_account}@{vncserver}:{remote_port}")
                    trace = traceback.format_exc()
                    self.log.debug(trace)
                    return

                vncserver = 'localhost'
        else:
            local_port = port

        #If vncviewer is not defined, then prompt them to open manually and
        # return now
        if self.config['vncviewer'] in [None, 'None', 'none']:
            self.log.info(f"\nNo VNC viewer application specified")
            self.log.info(f"Open your VNC viewer manually\n")
            return

        #determine geometry
        geometry = None
        if self.vncviewer_has_geometry is None:
            self.get_vncviewer_properties()
        if self.vncviewer_has_geometry is True and len(self.geometry) > 0:
            i = len(self.vnc_threads) % len(self.geometry)
            geometry = self.geometry[i]

        ## Open vncviewer as separate thread
        args = (vncserver, local_port, geometry)
        vnc_thread = Thread(target=self.launch_vncviewer, args=args, name=session_name)
        vnc_thread.start()
        self.vnc_threads.append(vnc_thread)
        time.sleep(0.05)


    ##-------------------------------------------------------------------------
    ## Start soundplay
    ##-------------------------------------------------------------------------
    def start_soundplay(self):
        '''Start the soundplay process.
        '''
        try:
            #check for existing first and shutdown
            if self.sound is not None:
                self.sound.terminate()

            #config vars
            sound_port = 9798

            self.log.info("Re-reading config file")
            self.get_config()
            aplay = self.config.get('aplay', None)
            soundplayer = self.config.get('soundplayer', None)
            vncserver = self.vncserver

            if self.firewall_requested == True:

                account = self.kvnc_account
                try:
                    sound_port = self.open_ssh_tunnel(self.vncserver, account,
                                                      self.ssh_pkey,
                                                      sound_port,
                                                      session_name='soundplay')
                except:
                    self.log.error(f"Failed to open SSH tunnel for "
                              f"{account}@{self.vncserver}:{sound_port}")
                    trace = traceback.format_exc()
                    self.log.debug(trace)
                    return

                vncserver = 'localhost'

            self.sound = soundplay.soundplay()
            self.sound.connect(self.instrument, vncserver, sound_port,
                               aplay=aplay, player=soundplayer)
        except:
            self.log.error('Unable to start soundplay.  See log for details.')
            trace = traceback.format_exc()
            self.log.debug(trace)


    ##-------------------------------------------------------------------------
    ## Prompt command line menu and wait for quit signal
    ##-------------------------------------------------------------------------
    def prompt_menu(self):
        '''Print the user menu to the screen
        '''
        line_length = 50
        lines = [f"-"*(line_length),
                 f"          Keck Remote Observing (v{__version__})",
                 f"          Currently connected to: {self.args.account}",
                 f"                     MENU",
                 f"-"*(line_length)]

        if self.args.authonly is False:
            morelines = [f"  l               List sessions available",
                         f"  [session name]  Open VNC session by name",
                         f"  w               Position VNC windows",
                         f"  s               Soundplayer restart",
                         f"  p               Play a local test sound",
                         ]
            lines.extend(morelines)
        if self.api_data is not None and self.args.authonly is False:
            lines.append(f"  i               View extra connection info")
        lines.extend([f"  v               Check if software is up to date",
                      f"  u               Upload log to Keck",
                      f"  t               List local ports in use",
                      f"  c [port]        Close ssh tunnel on local port",
#                       f"  proxy           Open SSH for proxy",
                      f"  q               Quit (or Control-C)",
                      f"-"*(line_length),
                      ])

        boxed = list()
        for line in lines:
            boxed.append('|' + line.ljust(line_length) + '|')

        menu = list()
        menu.append('')
        menu.extend(boxed)
        menu.append('> ')
        menu = '\n'.join(menu)

        quit = False
        while quit == False:
            cmd = input(menu)
            cmd = cmd.strip()
            cmd = cmd.lower()

            if cmd == '':
                continue

            self.log.info(f'Recieved command "{cmd}"')
            cmatch = re.match(r'c (\d+)', cmd)

            if cmd == 'q':
                quit = True
            elif cmd == 'l' and self.args.authonly is False:
                self.sessions_found = self.get_vnc_sessions(self.vncserver,
                                                            self.instrument,
                                                            self.kvnc_account,
                                                            self.args.account,
                                                            True)
                self.print_sessions_found()
            elif cmd == 'w' and self.args.authonly is False:
                self.position_vnc_windows()
            elif cmd == 's' and self.args.authonly is False:
                self.start_soundplay()
            elif cmd == 'p' and self.args.authonly is False:
                self.play_test_sound()
            elif cmd == 'i' and self.args.authonly is False and self.api_data is not None:
                self.view_connection_info()
            elif cmd == 'v':
                self.check_version()
            elif cmd == 'u':
                try:
                    self.upload_log()
                except Exception as e:
                    self.log.error('  Unable to upload logfile: ' + str(e))
                    trace = traceback.format_exc()
                    self.log.debug(trace)
            elif cmd == 't':
                self.list_tunnels()
            elif cmd in [s.name for s in self.sessions_found]:
                self.start_vnc_session(cmd)
            elif cmatch is not None:
                self.close_ssh_thread(int(cmatch.group(1)))
            else:
                self.log.error('Unrecognized command: ' + repr(cmd))


    ##-------------------------------------------------------------------------
    ## Print sessions found for instrument
    ##-------------------------------------------------------------------------
    def print_sessions_found(self):
        '''Print the VNC sessions found on the VNC server for this account
        '''
        print(f"\nSessions found for account '{self.args.account}':")
        for s in self.sessions_found:
            print(s)


    ##-------------------------------------------------------------------------
    ## List Open Tunnels
    ##-------------------------------------------------------------------------
    def list_tunnels(self):
        '''Print the SSH tunnels that the program has opened
        '''
        if len(self.ssh_tunnels.keys()) == 0:
            print(f"No SSH tunnels opened by this program")
        else:
            print(f"\nSSH tunnels:")
            print(f"  Local Port | Desktop   | Remote Connection")
            
            for p in self.ssh_tunnels.keys():
                t = self.ssh_tunnels[p]
                print(f"  {t.local_port:10d} | {t.session_name:9s} | {t.remote_connection:s}")


    ##-------------------------------------------------------------------------
    ## Play a test sound
    ##-------------------------------------------------------------------------
    def play_test_sound(self):
        '''Play a test sound.
        
        This sound will be a local file, so is a good test of the local system
        hardware and software setup.
        '''
        if self.config.get('nosound', False) is True:
            self.log.warning('Sounds are not enabled.  See config file.')
            return

        # Build the soundplay test command.
        soundplayer = self.config.get('soundplayer', None)
        soundplayer = soundplay.full_path(soundplayer)

        command = [soundplayer, '-l']

        aplay = self.config.get('aplay', 'aplay')
        command.append('-px')
        command.append(aplay)

        self.log.info('Playing test sound')
        self.log.debug('Calling: ' + ' '.join(command))
        test_sound_STDOUT = subprocess.check_output(command)
        for line in test_sound_STDOUT.decode().split('\n'):
            self.log.debug(f'  {line}')
        self.log.info('  You should have heard a sound through your local system')


    ##-------------------------------------------------------------------------
    ## Close ssh threads
    ##-------------------------------------------------------------------------
    def close_ssh_thread(self, p):
        '''Close an SSH thread.
        '''
        try:
            t = self.ssh_tunnels.pop(p, None)
        except KeyError:
            return
        t.close()


    def close_ssh_threads(self):
        '''Close all SSH threads.
        '''
        for p in list(self.ssh_tunnels.keys()):
            self.close_ssh_thread(p)


    ##-------------------------------------------------------------------------
    ## Position VNC Windows
    ##-------------------------------------------------------------------------
    def position_vnc_windows(self):
        '''Reposition the VNC windows to the preferred positions
        '''
        #get all x-window processes
        #NOTE: using wmctrl (does not work for Mac)
        #alternate option: xdotool?
        if 'darwin' in platform.system().lower():
            self.log.warning('Positioning windows after opening does not work on macOS.')
            return

        self.log.info("Re-reading config file")
        self.get_config()
        self.log.info(f"Positioning VNC windows...")
        self.calc_window_geometry()

        which_wmctrl = subprocess.run(['which', 'wmctrl'],
                                      stdout=subprocess.PIPE, timeout=5)
        if which_wmctrl.returncode != 0:
            self.log.warning('Could not find wmctrl. Can not reposition windows.')
            return
        where_is_wmctrl = which_wmctrl.stdout.decode().strip('\n')

        cmd = [where_is_wmctrl, '-l']
        wmctrl_l = subprocess.run(cmd, stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE, timeout=5)
        stdout = wmctrl_l.stdout.decode()
        for line in stdout.split('\n'):
            self.log.debug(f'wmctrl STDOUT: {line}')
        stderr = wmctrl_l.stderr.decode()
        for line in stderr.split('\n'):
            self.log.debug(f'wmctrl STDERR: {line}')
        if wmctrl_l.returncode != 0:
            self.log.debug(f'wmctrl failed')
            return None
        win_ids = dict([x for x in zip(self.sessions_requested,
                                [None for entry in self.sessions_requested])])
        for line in stdout.split('\n'):
            for thread in self.vnc_threads:
                session = thread.name
                if session in line:
                    self.log.debug(f"Found {session} in {line}")
                    win_id = line.split()[0]
                    win_ids[session] = line.split()[0]

        for i,thread in enumerate(self.vnc_threads):
            session = thread.name
            if win_ids.get(session, None) is not None:
                index = i % len(self.geometry)
                geom = self.geometry[index]
                self.log.debug(f'{session} has geometry: {geom}')

                cmd = ['wmctrl', '-i', '-r', win_ids[session], '-e',
                       f'0,{geom[0]},{geom[1]},-1,-1']
                self.log.debug(f"Positioning '{session}' with command: " + ' '.join(cmd))
                wmctrl = subprocess.run(cmd, stdout=subprocess.PIPE, timeout=5)
                if wmctrl.returncode != 0:
                    return None
                stdout = wmctrl.stdout.decode()
#                 for line in stdout.split('\n'):
#                     self.log.debug(f'wmctrl line: {line}')
            else:
                self.log.warning(f"Could not find window process for VNC session '{session}'")


    ##-------------------------------------------------------------------------
    ## View extra connection info (VNC passwords, zoom info, etc)
    ##-------------------------------------------------------------------------
    def view_connection_info(self):
        '''View extra connection info (VNC passwords, zoom info, etc)
        '''
        print("\n========================================")
        pw = self.api_data.get('vncpwd', '')
        if pw != '':
            print(f'VNC password: {pw}')

        zoom = self.api_data.get('zoom')
        if not zoom:
            self.log.error(f'API did not return Zoom info.')
        else:
            print(f"Zoom info:")
            print(f"\tURL: {zoom.get('url', '')}")
            print(f"\tMeeting ID: {zoom.get('meetingId', '')}")
            print(f"\tPassword: {zoom.get('pwd', '')}")
        print("========================================")


    ##-------------------------------------------------------------------------
    ## Upload log file to Keck
    ##-------------------------------------------------------------------------
    def upload_log(self):
        '''Upload the current log file to the VNC server at Keck.
        
        The file will ens up in the ~kvnc directory for the VNC server.
        '''
        account = self.kvnc_account

        logfile_handlers = [lh for lh in self.log.handlers if
                            isinstance(lh, logging.FileHandler)]
        logfile = Path(logfile_handlers.pop(0).baseFilename)

        source = str(logfile)
        destination = self.vncserver
        self.log.debug(f"Uploading to: {account}@{destination}:{logfile.name}")
        destination = account + '@' + destination + ':' + logfile.name

        command = ['scp',]

        if self.ssh_pkey is not None:
            command.append('-i')
            command.append(self.ssh_pkey)

        if self.ssh_additional_kex is not None:
            command.append('-oKexAlgorithms=' + self.ssh_additional_kex)

        command.append('-oStrictHostKeyChecking=no')
        command.append('-oCompression=yes')
        command.append(source)
        command.append(destination)

        self.log.debug('scp command: ' + ' '.join(command))

        null = subprocess.DEVNULL

        proc = subprocess.Popen(command, stdin=null, stdout=null, stderr=null)
        if proc.poll() is not None:
            raise RuntimeError('subprocess failed to execute scp')

        try:
            return_code = proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.log.error('  Timeout attempting to upload log file')
            return

        if return_code != 0:
            message = '  command failed with error ' + str(return_code)
            self.log.error(message)
        else:
            self.log.info(f'  Uploaded {logfile.name}')
            self.log.info(f'  to {destination}')

    ##-------------------------------------------------------------------------
    ## Terminate all vnc processes
    ##-------------------------------------------------------------------------
    def kill_vnc_processes(self, msg=None):
        '''Terminate all VNC sessions
        '''
        self.log.info('Terminating all VNC sessions.')
        try:
            while self.vnc_processes:
                proc = self.vnc_processes.pop()
                self.log.debug('terminating VNC process: ' + str(proc.args))
                # poll() value of None means it still exists.
                if proc.poll() == None:
                    proc.terminate()

        except:
            self.log.error("Failed to terminate VNC sessions.  See log for details.")
            trace = traceback.format_exc()
            self.log.debug(trace)


    ##-------------------------------------------------------------------------
    ## Common app exit point
    ##-------------------------------------------------------------------------
    def exit_app(self, msg=None):
        '''Exit the app
        '''
        #hack for preventing this function from being called twice
        #todo: need to figure out how to use atexit with threads properly
        if self.exit == True:
            return

        self.exit = True
        #todo: Fix app exit so certain clean ups don't cause errors
        #(ie thread not started, etc
        if msg is not None:
            self.log.info(msg)

        if self.sound is not None:
            self.sound.terminate()

        self.close_ssh_threads()

        #close vnc sessions
        self.kill_vnc_processes()

        self.log.info("EXITING APP\n")
        sys.exit(1)


    ##-------------------------------------------------------------------------
    ## Handle fatal error
    ##-------------------------------------------------------------------------
    def handle_fatal_error(self, error):
        '''Wrapper to handle uncaught errors
        '''
        #helpful user error message
        print("\n****** PROGRAM ERROR ******\n")
        print("Error message: " + str(error) + "\n")
        print()
        print("Please search for your error message in this form:")
        print("https://keckobservatory.atlassian.net/servicedesk/customer/portals?q=")
        print()
        print("If that does not yield an answer, please contact us:")
        print("https://keckobservatory.atlassian.net/servicedesk/customer/portal/2/group/3/create/10")
        print(f"or email us at {supportEmail}")
        print()

        #Log error if we have a log object (otherwise dump error to stdout)
        #and call exit_app function
        msg = traceback.format_exc()

        if self.log is None:
            print(msg)
        else:
            logfiles = [h.baseFilename for h in self.log.handlers if isinstance(h, logging.FileHandler)]
            if len(logfiles) > 0:
                print(f"* Attach log file at: {logfiles[0]}\n")
            self.log.debug(f"\n\n!!!!! PROGRAM ERROR:\n{msg}\n")

#         raise error
        self.exit_app()


    ##-------------------------------------------------------------------------
    ## Tests
    ##-------------------------------------------------------------------------
    def test_config_format(self):
        '''Test:
        - The config file has a valid api_key specified
        - The config file has a valid ssh_pkey path specified
        - The config file has a valid vncviewer executable path specified
        '''
        import socket
        failcount = 0

        #API must be defined
        self.log.info('Checking config file: api_key')
        api_key = self.config.get('api_key', None)
        if api_key in [None, '']:
            self.log.error(f'api_key should be specified')
            failcount += 1

        self.log.info('Checking config file: ssh_pkey')
        ssh_pkey = self.config.get('ssh_pkey', '~/.ssh/id_rsa')
        ssh_pkey = Path(ssh_pkey)
        if ssh_pkey.expanduser().exists() is False or ssh_pkey.expanduser().is_file() is False:
            self.log.error(f'ssh_pkey: "{ssh_pkey}" not found')
            failcount += 1

        self.log.info('Checking config file: vncviewer')
        vncviewer_from_config = self.config.get('vncviewer', None)
        # the line below will throw and error if which fails
        try:
            output_of_which = subprocess.check_output(['which', vncviewer_from_config])
        except subprocess.CalledProcessError as e:
            self.log.error(f'Unable to locate VNC viewer "{vncviewer_from_config}"')
            failcount += 1

        if failcount > 0:
            self.log.error(f'Found {failcount} failures in configuration file')
        return failcount


    def test_tigervnc(self):
        '''Test (only executes test in the vncviewer is TigerVNC):
        - Check that ~/.vnc/default.tigervnc exists
        - Check that ~/.vnc/default.tigervnc has a RemoteResize entry
        - Check that the RemoteResize entry is set to 0
        '''
        failcount = 0
        if self.tigervnc is None:
            self.get_vncviewer_properties()
        if self.tigervnc is False:
            return failcount
        
        self.log.info(f'Checking TigerVNC defaults')
        tigervnc_config_file = Path('~/.vnc/default.tigervnc').expanduser()
        if tigervnc_config_file.exists() is False:
            self.log.error(f'Could not find {tigervnc_config_file}')
            self.log.error('This file is required. See README for details.')
            failcount += 1
            return failcount

        with open(tigervnc_config_file) as FO:
            tiger_config = FO.read()
        RRsearch = re.search(r'RemoteResize=(\d)', tiger_config)
        if RRsearch is None:
            self.log.error('Could not find RemoteResize setting')
            failcount += 1
        else:
            remote_resize_value  = int(RRsearch.group(1))
            self.log.debug(f'Found RemoteResize set to {remote_resize_value}')
            if remote_resize_value !=0:
                self.log.error('RemoteResize must be set to 0')
                failcount += 1

        self.log.info(f'Checking TigerVNC command line options')
        vncargs = self.config.get('vncargs', '')
        RRsearchcl = re.search('RemoteResize', vncargs)
        if RRsearchcl is not None:
            self.log.error('RemoteResize option is not allowed')
            failcount += 1

        return failcount


    def test_ssh_key_format(self):
        '''The SSH key must be RSA and must not use a passphrase
        '''
        failcount = 0
        self.log.info('Checking SSH private key permissions')
        permissions = oct(os.stat(self.ssh_pkey).st_mode)[-3:]
        if permissions != '600':
            self.log.error(f'The permissions on your private SSH key ({permissions}) may not be secure')
            self.log.error('Please verify that your SSH key is useable normally before trying again')
            failcount += 1

        self.log.info('Checking SSH private key format')
        with open(self.ssh_pkey, 'r') as f:
            contents = f.read()

        # Check if this is an RSA key
#         foundrsa = re.search('BEGIN RSA PRIVATE KEY', contents)
#         if not foundrsa:
#             self.log.error(f"Your private key does not appear to be an RSA key")
#             failcount += 1

        # Check if this is an OPENSSH key
        foundopenssh = re.search('BEGIN OPENSSH PRIVATE KEY', contents)
        if foundopenssh:
            self.log.warning(f"Your SSH key may or may not be formatted correctly.")
            self.log.warning(f"If no other tests fail and you can connect to the Keck VNCs,")
            self.log.warning(f"then you can ignore this message.  If you can not connect,")
            self.log.warning(f"then try regenerating and uploading your SSH key and make")
            self.log.warning(f"sure you use the `-m PEM` option when generating the key.")

        # Check that there is no passphrase
        foundencrypt = re.search('Proc-Type: \d,ENCRYPTED', contents)
        if foundencrypt:
            self.log.error(f"Your private key appears to require a passphrase.  This is not supported.")
            failcount += 1
        
        return failcount


    def test_api(self):
        '''Test:
        - If api_key is set, must get valid response.
        '''
        if self.api_key is None:
            self.log.warning("API key is not defined.  Unable to test API.")
            return 0

        failcount = 0    
        #todo: jriley: need ability to bypass account param in API call
        self.get_api_data(self.api_key, 'kcwi1')
        if self.api_data is None:
            self.log.error(f'Could not get a valid reponse from API.')
            failcount += 1

        return failcount


    def test_basic_connectivity(self):
        '''Test:
        - Successfully connect to the listed servers at Keck and get a valid
        response from an SSH command.
        - Now that the access list os limited to the destination instrument, we
        only check connection to kcwi as that is the instrument used in the
        `test_api` step.
        '''
        failcount = 0
#         servers_and_results = [('mosfire', 'vm-mosfire'),
#                                ('hires', 'vm-hires'),
#                                ('lris', 'vm-lris'),
#                                ('osiris', 'vm-osiris'),
#                                ('kpf', 'kpf'),
#                                ('deimos', 'deimos'),
#                                ('kcwi', 'vm-kcwi'),
#                                ('nirc2', 'vm-nirc2'),
#                                ('nires', 'vm-nires'),
#                                ('nirspec', 'vm-nirspec')]
        servers_and_results = [('kcwi', 'vm-kcwi')]
        for server, result in servers_and_results:
            self.log.info(f'Testing SSH to {self.kvnc_account}@{server}.keck.hawaii.edu')
            tick = datetime.now()

            output, rc = self.do_ssh_cmd('hostname', f'{server}.keck.hawaii.edu',
                                        self.kvnc_account)
            if output is None:
                # On timeout, the result returned by do_ssh_cmd is None
                # Just try a second time
                output, rc = self.do_ssh_cmd('hostname', f'{server}.keck.hawaii.edu',
                                            self.kvnc_account)
            tock = datetime.now()
            elapsedtime = (tock-tick).total_seconds()
            self.log.debug(f'Got hostname "{output}" from {server} after {elapsedtime:.1f}s')
            if output in [None, '']:
                self.log.error(f'Failed to connect to {server}')
                failcount += 1
            else:
                if output.strip() not in [server, result]:
                    self.log.error(f'Got invalid response from {server}')
                    failcount += 1

        return failcount


    def test_yaml_version(self):
        '''Check to see if we have the safe_load function in yaml
        '''
        failcount = 0
        self.log.debug(f'Checking yaml version: {yaml.__version__}')
        self.log.debug(f'yaml version must be > 5.1')
        try:
            func = yaml.safe_load
            self.log.debug('yaml.safe_load = {func}')
            self.safe_load = True
        except AttributeError:
            self.log.error('Unable to use safe_load. Please upgrade the pyyaml package.')
            self.log.error(f'Current pyyaml package version is {yaml.__version__}')
            self.safe_load = False
            failcount += 1
        return failcount


    def test_all(self):
        '''Run all of the tests.
        '''
        failcount = 0
        failcount += self.test_yaml_version()
        failcount += self.test_config_format()
        failcount += self.test_tigervnc()
        failcount += self.test_ssh_key_format()
        failcount += self.test_api()
        failcount += self.test_basic_connectivity()

        if failcount == 0:
            self.log.info('--> All tests PASSED <--')
        else:
            self.log.error(f'--> Found {failcount} failures during tests <--')

        if self.config.get('vncviewer', False) is not True:
            self.play_test_sound()


##-------------------------------------------------------------------------
## Start from command line
##-------------------------------------------------------------------------
if __name__ == '__main__':
    main()

