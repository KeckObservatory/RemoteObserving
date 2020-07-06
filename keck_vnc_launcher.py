#! /usr/bin/env python3

## Import standard modules
import os
import argparse
import atexit
from datetime import datetime
from getpass import getpass
import logging
import os
from pathlib import Path
import platform
import re
import socket
import subprocess
import sys
from telnetlib import Telnet
from threading import Thread
import time
import traceback
import warnings
import yaml

## Import local modules
import soundplay


__version__ = '1.2.2'
supportEmail = 'remote-observing@keck.hawaii.edu'

SESSION_NAMES = ('control0', 'control1', 'control2',
                 'analysis0', 'analysis1', 'analysis2',
                 'telanalys', 'telstatus', 'status')
KROException = Exception


##-------------------------------------------------------------------------
## Main
##-------------------------------------------------------------------------
def main():
    create_logger()
    kvl = KeckVncLauncher()
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
    for name in SESSION_NAMES:
        parser.add_argument(f"--{name}",
            dest=name,
            default=False,
            action="store_true",
            help=f"Open {name} VNC session")

    ## add arguments
    parser.add_argument("account", type=str, nargs='?', default='hires1',
                        help="The user account.")

    ## add options
    parser.add_argument("-c", "--config", dest="config", type=str,
        help="Path to local configuration file.")

    #parse
    args = parser.parse_args()

    ## If authonly is set, also set nosound because if the user doesn't want
    ## VNCs, they likely don't want sound as well.
    if args.authonly is True:
        args.nosound = True

    return args


##-------------------------------------------------------------------------
## Create logger
##-------------------------------------------------------------------------
def create_logger():

    ## Create logger object
    log = logging.getLogger('KRO')

    ## Only add handlers if none already exist (eliminates duplicate lines)
    if len(log.handlers) > 0:
        return

    #create log file and log dir if not exist
    ymd = datetime.utcnow().strftime('%Y%m%d')
    try:
        Path('logs/').mkdir(parents=True, exist_ok=True)
    except PermissionError as error:
        print(str(error))
        print(f"ERROR: Unable to create logger at {logFile}")
        print("Make sure you have write access to this directory.\n")
        log.info("EXITING APP\n")
        sys.exit(1)

    #stream/console handler (info+ only)
    logConsoleHandler = logging.StreamHandler()
    logConsoleHandler.setLevel(logging.INFO)
    logFormat = logging.Formatter(' %(levelname)8s: %(message)s')
    logFormat.converter = time.gmtime
    logConsoleHandler.setFormatter(logFormat)
    log.addHandler(logConsoleHandler)

    #file handler (full debug logging)
    logFile = f'logs/keck-remote-log-utc-{ymd}.txt'
    logFileHandler = logging.FileHandler(logFile)
    logFileHandler.setLevel(logging.DEBUG)
    logFormat = logging.Formatter('%(asctime)s UT - %(levelname)s: %(message)s')
    logFormat.converter = time.gmtime
    logFileHandler.setFormatter(logFormat)
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
## Define Firewall Function
##-------------------------------------------------------------------------
def do_firewall_command(firewall_address, firewall_port, firewall_user,
                        authpass, selection):
    '''Interact with the firewall to authenticate or deauthenticate.
    
    The selection value is the response to the firewall's query after
    authenticating past the username and password steps.
    '''
    log = logging.getLogger('KRO')

    if selection == 1:
        log.info(f'Authenticating through firewall as:')
        log.info(f' {firewall_user}@{firewall_address}:{firewall_port}')
    elif selection == 2:
        log.info('Closing firewall hole')

    tn = Telnet(firewall_address, int(firewall_port))

    # Find Username Prompt
    user_prompt = tn.read_until(b"User: ", timeout=5).decode('ascii')
    for line in user_prompt.split('\n'):
        line = line.strip().strip('\n')
        log.debug(f"Firewall says: {line}")
    if user_prompt[-6:] != 'User: ':
        log.error('Got unexpected response from firewall:')
        log.error(user_prompt)
        raise KROException('Got unexpected response from firewall')
    log.debug(f'Sending response: {firewall_user}')
    tn.write(f'{firewall_user}\n'.encode('ascii'))

    # Find Password Prompt
    password_prompt = tn.read_until(b"password: ", timeout=5).decode('ascii')
    for line in password_prompt.split('\n'):
        line = line.strip().strip('\n')
        log.debug(f"Firewall says: {line}")
    if password_prompt[-10:] != 'password: ':
        log.error('Got unexpected response from firewall:')
        log.error(password_prompt)
        raise KROException('Got unexpected response from firewall')
    log.debug(f'Sending response: (value hidden from log)')
    tn.write(f'{authpass}\n'.encode('ascii'))

    # Is Password Accepted?
    password_response = tn.read_until(b"Enter your choice: ", timeout=5).decode('ascii')
    for line in password_response.split('\n'):
        line = line.strip().strip('\n')
        log.debug(f"Firewall says: {line}")
    if re.search('Access denied - wrong user name or password', password_response):
        log.error('Incorrect password entered.')
        return False

    # If Password is Correct, continue with authentication process
    if password_response[-19:] != 'Enter your choice: ':
        log.error('Got unexpected response from firewall:')
        log.error(password_response)
        raise KROException('Got unexpected response from firewall')

    log.debug(f'Sending response: {selection}')
    tn.write(f'{selection}\n'.encode('ascii'))

    result = tn.read_all().decode('ascii')
    for line in result.split('\n'):
        line = line.strip().strip('\n')
        log.debug(f"Firewall says: {line}")

    # Check for standard exits
    if selection == 1:
        if re.search('User authorized for standard services', result):
            log.info('User authorized for standard services')
        else:
            log.error(result)
    elif selection == 2:
        if re.search('User was signed off from all services', result):
            log.info('User was signed off from all services')
        else:
            log.error(result)

    return result


##-------------------------------------------------------------------------
## Define VNC Session Object
##-------------------------------------------------------------------------
class VNCSession(object):
    '''An object to contain information about a VNC session.
    '''
    def __init__(self, name=None, display=None, desktop=None, user=None, pid=None):
        if name is None and display is not None:
            name = desktop.split('-')[2]
        self.name = name
        self.display = display
        self.desktop = desktop
        self.user = user
        self.pid = pid

    def __str__(self):
        return f"  {self.name:12s} {self.display:5s} {self.desktop:s}"


##-------------------------------------------------------------------------
## Define SSH Tunnel Object
##-------------------------------------------------------------------------
class SSHTunnel(object):
    '''An object to contain information about an SSH tunnel.
    '''
    def __init__(self, server, username, ssh_pkey, remote_port, local_port,
                 session_name='unknown', ssh_additional_kex=None):
        self.log = logging.getLogger('KRO')
        self.server = server
        self.username = username
        self.ssh_pkey = ssh_pkey
        self.remote_port = remote_port
        self.local_port = local_port
        self.session_name = session_name
        self.remote_connection = f'{username}@{server}:{remote_port}'
        self.ssh_additional_kex = ssh_additional_kex

        address_and_port = f"{username}@{server}:{remote_port}"
        self.log.info(f"Opening SSH tunnel for {address_and_port} "
                 f"on local port {local_port}.")

        # We now know everything we need to know in order to establish the
        # tunnel. Build the command line options and start the child process.
        # The -N and -T options below are somewhat exotic: they request that
        # the login process not execute any commands and that the server does
        # not allocate a pseudo-terminal for the established connection.

        forwarding = f"{local_port}:localhost:{remote_port}"
        cmd = ['ssh', server, '-l', username, '-L', forwarding, '-N', '-T']
        cmd.append('-oStrictHostKeyChecking=no')
        cmd.append('-oCompression=yes')

        if self.ssh_additional_kex is not None:
            cmd.append('-oKexAlgorithms=' + self.ssh_additional_kex)

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
        # ssh to establish the tunnel. 50 checks with a 0.1 second sleep between
        # checks is effectively a five second timeout.

        checks = 50
        while checks > 0:
            result = is_local_port_in_use(local_port)
            if result == True:
                break
            elif self.proc.poll() is not None:
                raise RuntimeError('ssh command exited unexpectedly')

            checks -= 1
            time.sleep(0.1)

        if checks == 0:
            raise RuntimeError('ssh tunnel failed to open after 5 seconds')


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

    def __init__(self):
        #init vars we need to shutdown app properly
        self.config = None
        self.log = None
        self.sound = None
        self.firewall_pass = None
        self.ssh_tunnels = dict()
        self.vnc_threads = list()
        self.vnc_processes = list()
        self.firewall_requested = False
        self.firewall_opened = False
        self.instrument = None
        self.vncserver = None
        self.ssh_key_valid = False
        self.ssh_additional_kex = '+diffie-hellman-group1-sha1'
        self.exit = False
        self.geometry = list()
        self.tigervnc = None
        self.vncviewer_has_geometry = None

        self.log = logging.getLogger('KRO')

        #default start sessions
        self.default_sessions = [
            'control0',
            'control1',
            'control2',
            'telstatus',
        ]

        #default servers to try at Keck
        servers = ['svncserver2', 'svncserver1', 'kcwi', 'mosfire']
        domain = '.keck.hawaii.edu'
        self.servers_to_try = [f"{server}{domain}" for server in servers]

        #The 'status' session is potentially on a different server and is
        # always on port 1,
        self.STATUS_PORT = ':1'
        self.LOCAL_PORT_START = 5901 # can be overridden by config file

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
        self.log.debug("\n***** PROGRAM STARTED *****\nCommand: "+' '.join(sys.argv))
        self.args = create_parser()

        ##---------------------------------------------------------------------
        ## Log basic system info
        self.log_system_info()
        self.check_version()
        self.get_ping_cmd()
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
            # On test, always cleanup firewall
            self.config['firewall_cleanup'] = True
            self.test_all()
        # Verify Tiger VNC Config
        if self.args.authonly is False:
            if self.test_tigervnc() > 0:
                self.log.error('TigerVNC is not conifgured properly.  See instructions.')
                self.log.error('This can have negative effects on other users.')
                self.log.error('Exiting program.')
                self.exit_app()

        ##---------------------------------------------------------------------
        ## Authenticate Through Firewall (or Disconnect)
        if self.firewall_requested == True:
            self.firewall_opened = self.test_firewall()
        else:
            self.firewall_opened = False

        # Do we need to interact with the firewall?
        need_password = self.config.get('firewall_cleanup', False)
        if self.firewall_requested == True and self.firewall_opened == False:
            need_password = True

        if need_password == True:
            while self.firewall_pass is None:
                firewall_pass = getpass(f"Password for firewall authentication: ")
                firewall_pass = firewall_pass.strip()
                if firewall_pass != '':
                    self.firewall_pass = firewall_pass

        if self.firewall_requested == True and self.firewall_opened == False:
            try:
                self.firewall_opened = self.open_firewall(self.firewall_pass)
            except:
                self.log.error('Unable to authenticate through firewall')
                trace = traceback.format_exc()
                self.log.debug(trace)

            if self.firewall_opened == False:
                self.exit_app('Authentication failure!')


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
            ## Validate ssh key
            self.validate_ssh_key()
            if self.ssh_key_valid == False:
                self.log.error(f"\n\n\tCould not validate SSH key.\n\t"\
                               f"Contact {supportEmail} "\
                               f"for other options to connect remotely.\n")
                self.exit_app()

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
                self.exit_app('No VNC sessions found')

            ##-----------------------------------------------------------------
            ## Open requested sessions
            self.calc_window_geometry()
            for session_name in self.sessions_requested:
                self.start_vnc_session(session_name)

            ##-----------------------------------------------------------------
            ## Open Soundplay
            sound = None
            if self.args.nosound is False and self.config.get('nosound', False) != True:
                self.start_soundplay()

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
            self.log.debug(f'System Info: {os.uname()}')
            hostname = socket.gethostname()
            self.log.debug(f'System hostname: {hostname}')
            #todo: gethostbyname stopped working after I updated mac. need better method
            # ip = socket.gethostbyname(hostname)
            # self.log.debug(f'System IP Address: {ip}')
            python_version_str = sys.version.replace("\n", " ")
            self.log.info(f'Python {python_version_str}')
            self.log.debug(f'yaml {yaml.__version__}')
            self.log.debug(f'requests {requests.__version__}')
            self.log.debug(f'packaging {packaging.__version__}')
            self.log.info(f'Remote Observing Software Version = {__version__}')
        except:
            self.log.error("Unable to log system info.")
            trace = traceback.format_exc()
            self.log.debug(trace)


    def check_version(self):
        '''Compare the version of the local software against that available on
        GitHub.
        '''
        url = ('https://raw.githubusercontent.com/KeckObservatory/'
               'RemoteObserving/master/keck_vnc_launcher.py')
        try:
            import requests
            from packaging import version
            r = requests.get(url)
            findversion = re.search(r"__version__ = '(\d.+)'\n", r.text)
            if findversion is not None:
                remote_version = version.parse(findversion.group(1))
                local_version = version.parse(__version__)
            else:
                self.log.warning(f'Unable to determine software version on GitHub')
                return
            if remote_version == local_version:
                self.log.info(f'Your software is up to date (v{__version__})')
            elif remote_version < local_version:
                self.log.info(f'Your software (v{__version__}) is ahead of the released version')
            else:
                self.log.warning(f'Your local software (v{__version__}) is behind '
                                 f'the currently available version '
                                 f'(v{remote_version})')
        except ModuleNotFoundError as e:
            self.log.warning("Unable to verify remote version")
            self.log.debug(e)
        except requests.ConnectionError as e:
            self.log.warning("Unable to verify remote version")
            self.log.debug(e)
        except Exception as e:
            self.log.warning("Unable to verify remote version")
            self.log.debug(e)


    def get_ping_cmd(self):
        '''Assemble the local ping command.
        '''
        # Figure out local ping command
        try:
            ping = subprocess.check_output(['which', 'ping'])
            ping = ping.decode()
            ping = ping.strip()
            self.ping_cmd = [ping]
        except subprocess.CalledProcessError:
            self.log.error("Ping command not available")
            return None

        os = platform.system()
        os = os.lower()
        # Ping once, wait up to 2 seconds for a response.
        if os == 'linux':
            self.ping_cmd.extend(['-c', '1', '-w', 'wait'])
        elif os == 'darwin':
            self.ping_cmd.extend(['-c', '1', '-W', 'wait000'])
        else:
            # Don't understand how ping works on this platform.
            self.ping_cmd = None
        self.log.debug(f'Got ping command: {self.ping_cmd[:-2]}')


    def ping(self, address, wait=5):
        '''Ping a server to determine if it is accessible.
        '''
        if self.ping_cmd is None:
            self.log.warning('No ping command defined')
            return None
        # Run ping
        ping_cmd = [x.replace('wait', f'{int(wait)}') for x in self.ping_cmd]
        ping_cmd.append(address)
        self.log.debug(' '.join(ping_cmd))
        output = subprocess.run(ping_cmd,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        if output.returncode != 0:
            self.log.debug("Ping command failed")
            self.log.debug(f"STDOUT: {output.stdout.decode()}")
            self.log.debug(f"STDERR: {output.stderr.decode()}")
            return False
        else:
            self.log.debug("Ping command succeeded")
            self.log.debug(f"STDOUT: {output.stdout.decode()}")
            self.log.debug(f"STDERR: {output.stderr.decode()}")
            return True


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
        #check firewall config
        self.firewall_requested = False
        self.firewall_address = self.config.get('firewall_address', None)
        self.firewall_user = self.config.get('firewall_user', None)
        self.firewall_port = self.config.get('firewall_port', None)

        if self.firewall_address is not None and \
           self.firewall_user is not None and \
           self.firewall_port is not None:
            self.firewall_requested = True

        elif self.firewall_address is not None or \
             self.firewall_user is not None or \
             self.firewall_port is not None:
            self.log.warning("Incomplete firewall configuration detected:")
            if self.firewall_address is None:
                self.log.warning("firewall_address not set")
            if self.firewall_user is None:
                self.log.warning("firewall_user not set")
            if self.firewall_port is None:
                self.log.warning("firewall_port not set")


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


    ##-------------------------------------------------------------------------
    ## Open and Close the firewall
    ##-------------------------------------------------------------------------
    def test_firewall(self):
        ''' Return True if the sshuser firewall hole is open; otherwise
        return False. Also return False if the test cannot be performed.
        '''
        self.log.info('Checking whether firewall is open')

        # Use netcat if specified:
        # The netcat test is more rigorous, in that it attempts to contact
        # an ssh daemon that should be available to us after opening the
        # firewall hole. The ping check is a reasonable fallback and was
        # the traditional way the old mainland observing script would confirm
        # the firewall status.
        netcat = self.config.get('netcat', None)
        if netcat is not None:
            cmd = netcat.split()
            for server in self.servers_to_try:
                server_and_port = [server, '22']
                self.log.debug(f'firewall test: {" ".join(cmd+server_and_port)}')
                netcat_result = subprocess.run(cmd+server_and_port, timeout=5,
                                               stdout=subprocess.PIPE,
                                               stderr=subprocess.PIPE)
                up = (netcat_result.returncode == 0)
                if up is True:
                    self.log.info('firewall is open')
                    return True
            self.log.info('firewall is closed')
            return False

        # Use ping if no netcat is specified
        if self.ping_cmd is not None:
            for server in self.servers_to_try:
                up = self.ping(server, wait=2)
                if up is True:
                    self.log.info('firewall is open')
                    return True
            self.log.info('firewall is closed')
            return False
        else:
            # No way to check the firewall status. Assume it is closed,
            # authentication will be required.
            self.log.info('firewall is unknown')
            return None


    def open_firewall(self, authpass):
        '''Simple wrapper to open firewall.
        '''
        do_firewall_command(self.firewall_address, self.firewall_port,
                            self.firewall_user, authpass, 1)


    def close_firewall(self, authpass):
        '''Simple wrapper to close firewall.
        '''
        do_firewall_command(self.firewall_address, self.firewall_port,
                            self.firewall_user, authpass, 2)


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
                    'k1ao':     ['k1obsao'],
                    'k2ao':     ['k2obsao'],
                    'k1inst':   ['k1insttech'],
                    'k2inst':   ['k2insttech'],
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

        telescope = {'mosfire': 1,
                     'hires':   1,
                     'osiris':  1,
                     'lris':    1,
                     'k1ao':    1,
                     'k1inst':  1,
                     'nires':   2,
                     'deimos':  2,
                     'esi':     2,
                     'nirc2':   2,
                     'nirspec': 2,
                     'kcwi':    2,
                     'k2ao':    2,
                     'k2inst':  2,
                    }

        for instrument in accounts.keys():
            if account.lower() in accounts[instrument]:
                return instrument, telescope[instrument]

        return None, None


    ##-------------------------------------------------------------------------
    ## SSH Command
    ##-------------------------------------------------------------------------
    def do_ssh_cmd(self, cmd, server, account, timeout=10):
        '''Utility function for opening ssh client, executing command and
        closing.
        '''
        output = None
        self.log.debug(f'Trying SSH connect to {server} as {account}:')

        command = ['ssh', server, '-l', account, '-T']

        if self.ssh_pkey is not None:
            command.append('-i')
            command.append(self.ssh_pkey)

        if self.ssh_additional_kex is not None:
            command.append('-oKexAlgorithms=' + self.ssh_additional_kex)

        command.append('-oStrictHostKeyChecking=no')
        command.append(cmd)
        self.log.debug('ssh command: ' + ' '.join(command))

        pipe = subprocess.PIPE
        null = subprocess.DEVNULL
        stdout = subprocess.STDOUT

        proc = subprocess.Popen(command, stdin=null, stdout=pipe, stderr=stdout)
        if proc.poll() is not None:
            raise RuntimeError('subprocess failed to execute ssh')

        try:
            stdout,stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.log.error('  Timeout')
            return

        if proc.returncode != 0:
            message = '  command failed with error ' + str(proc.returncode)
            self.log.error(message)

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


        stdout = stdout.decode()
        stdout = stdout.strip()
        self.log.debug(f"Output: '{stdout}'")

        # The first line might be a warning about accepting a ssh host key.
        # Check for that, and get rid of it from the output.

        lines = stdout.split('\n')

        if len(lines) > 1:
            if 'Warning: Permanently added' in lines[0]:
                self.log.debug('Removed warning from command output:')
                self.log.debug(lines[0])
                lines = lines[1:]
                stdout = '\n'.join(lines)

        return stdout


    ##-------------------------------------------------------------------------
    ## Validate ssh key on remote vnc server
    ##-------------------------------------------------------------------------
    def validate_ssh_key(self):
        '''Issue a simple command and check response as a check to see if the
        SSH key is valid.
        '''
        if self.ssh_key_valid == True:
            return

        self.log.info(f"Validating ssh key...")

        self.ssh_key_valid = False
        cmd = 'whoami'
        server = self.servers_to_try[0]
        account = self.kvnc_account

        try:
            data = self.do_ssh_cmd(cmd, server, account)
        except Exception as e:
            self.log.error('  Failed: ' + str(e))
            trace = traceback.format_exc()
            self.log.debug(trace)
            data = None

        if data == self.kvnc_account:
            self.ssh_key_valid = True
            self.log.info("  SSH key OK")
        else:
            self.log.error("  SSH key invalid")


    ##-------------------------------------------------------------------------
    ## Determine VNC Server
    ##-------------------------------------------------------------------------
    def get_vnc_server(self, account, instrument):
        '''Determine the VNC server to connect to given the instrument.
        
        Note that while this nominally cycles through all the servers in the
        servers_to_try list, it is only reliably correct when connecting to a
        solaris machine such as svncserver1 or svncserver2. The kvnc.cfg file
        that those access at Keck is shared and up to date. The kvnc.cfg file
        accessed by the linux instrument machines is deployed via KROOT and may
        be out of date. As of this writing (July 2, 2020), ESI is incorrect on
        those machines, but other instruments return a correct server.
        '''
        self.log.info(f"Determining VNC server for '{account}'...")
        vncserver = None
        for server in self.servers_to_try:
            cmd = f'kvncinfo -server -I {instrument}'

            try:
                data = self.do_ssh_cmd(cmd, server, account)
            except Exception as e:
                self.log.error('  Failed: ' + str(e))
                trace = traceback.format_exc()
                self.log.debug(trace)
                data = None

            if data is not None and ' ' not in data:
                vncserver = data
                self.log.info(f"Got VNC server: '{vncserver}'")
                break

        # Temporary hack for KCWI
        if vncserver == 'vm-kcwivnc':
            vncserver = 'kcwi'

        if vncserver is not None and 'keck.hawaii.edu' not in vncserver:
            vncserver += '.keck.hawaii.edu'

        return vncserver


    ##-------------------------------------------------------------------------
    ## Determine VNC Sessions
    ##-------------------------------------------------------------------------
    def get_vnc_sessions(self, vncserver, instrument, account, instr_account):
        '''Determine the VNC sessions running for the given account.
        '''
        self.log.info(f"Connecting to {account}@{vncserver} to get VNC sessions list")

        sessions = list()
        cmd = f'setenv INSTRUMENT {instrument}; kvncstatus -a'
        try:
            data = self.do_ssh_cmd(cmd, vncserver, account)
        except Exception as e:
            self.log.error('  Failed: ' + str(e))
            trace = traceback.format_exc()
            self.log.debug(trace)
            data = ''

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
        # Add "status" session for either K1 or K2 as appropriate
        sessions.append(VNCSession(name='status', display=self.STATUS_PORT,
                                   desktop='FACSUM & XMET', user=''))

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

        t = SSHTunnel(server, username, ssh_pkey, remote_port, local_port,
                      session_name=session_name,
                      ssh_additional_kex=self.ssh_additional_kex)
        self.ssh_tunnels[local_port] = t
        return local_port


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
                cmd.extend(['setenv', 'DISPLAY', f':{display}.0'])

        cmd.append(vncviewercmd)
        if vncargs is not None:
            vncargs = vncargs.split()
            cmd.extend(vncargs)
        if self.args.viewonly == True:
            cmd.append('-ViewOnly')

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

        #determine vncserver (only different for "status")
        vncserver = self.vncserver
        if session_name == 'status':
            vncserver = f"svncserver{self.tel}.keck.hawaii.edu"

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
                 f"                     MENU",
                 f"-"*(line_length)]

        morelines = [f"  l               List sessions available",
                     f"  [session name]  Open VNC session by name",
                     f"  w               Position VNC windows",
                     f"  s               Soundplayer restart",
                     f"  u               Upload log to Keck",
                     f"  p               Play a local test sound",
                     f"  t               List local ports in use",
                     f"  c [port]        Close ssh tunnel on local port",
                     ]
        if self.args.authonly is False:
            lines.extend(morelines)
        lines.extend([f"  v               Check if software is up to date",
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
            elif cmd == 'w':
                self.position_vnc_windows()
            elif cmd == 'p':
                self.play_test_sound()
            elif cmd == 's':
                self.start_soundplay()
            elif cmd == 'u':
                try:
                    self.upload_log()
                except Exception as e:
                    self.log.error('  Unable to upload logfile: ' + str(e))
                    trace = traceback.format_exc()
                    self.log.debug(trace)
            elif cmd == 'l':
                self.sessions_found = self.get_vnc_sessions(self.vncserver,
                                                            self.instrument,
                                                            self.kvnc_account,
                                                            self.args.account)
                self.print_sessions_found()
            elif cmd == 't':
                self.list_tunnels()
            elif cmd == 'v':
                self.check_version()
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

        aplay = self.config.get('aplay', None)
        if aplay is not None:
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
        self.log.info("Re-reading config file")
        self.get_config()
        self.log.info(f"Positioning VNC windows...")
        self.calc_window_geometry()

        #get all x-window processes
        #NOTE: using wmctrl (does not work for Mac)
        #alternate option: xdotool?
        cmd = ['wmctrl', '-l']
        wmctrl_l = subprocess.run(cmd, stdout=subprocess.PIPE, timeout=5)
        stdout = wmctrl_l.stdout.decode()
        for line in stdout.split('\n'):
            self.log.debug(f'wmctrl line: {line}')
        if wmctrl_l.returncode != 0:
            self.log.debug(f'wmctrl failed')
            for line in stdout.split('\n'):
                self.log.debug(f'wmctrl line: {line}')
            stderr = wmctrl_l.stderr.decode()
            for line in stderr.split('\n'):
                self.log.debug(f'wmctrl line: {line}')
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
                self.log.info(f"Could not find window process for VNC session '{session}'")


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
        destination = account + '@' + self.vncserver + ':' + logfile.name

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

        close_requested = self.config.get('firewall_cleanup', False)
        if close_requested == True:
            try:
                self.close_firewall(self.firewall_pass)
            except:
                self.log.error('Unable to close the firewall hole!')
        else:
            self.log.info('Leaving firewall authentication unchanged.')

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
        print("If you need troubleshooting assistance:")
        print(f"* Email {supportEmail}\n")

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

        self.exit_app()


    ##-------------------------------------------------------------------------
    ## Tests
    ##-------------------------------------------------------------------------
    def test_config_format(self):
        '''Test:
        - The config file has a valid firewall_address specified
        - The config file has a valid firewall_port specified
        - The config file has a valid firewall_user specified
        - The config file has a valid ssh_pkey path specified
        - The config file has a valid vncviewer executable path specified
        '''
        import socket
        failcount = 0
        self.log.info('Checking config file: firewall_address')
        firewall_address = self.config.get('firewall_address', None)
        if firewall_address is None:
            self.log.error(f"No firewall address found")
            failcount += 1
        try:
            socket.inet_aton(firewall_address)
        except OSError:
            self.log.error(f'firewall_address: "{firewall_address}" is invalid')
            failcount += 1

        self.log.info('Checking config file: firewall_port')
        firewall_port = self.config.get('firewall_port', None)
        if isinstance(int(firewall_port), int) is False:
            self.log.error(f'firewall_port: "{firewall_port}" is invalid')
            failcount += 1

        self.log.info('Checking config file: firewall_user')
        firewall_user = self.config.get('firewall_user', None)
        if firewall_user in [None, '']:
            self.log.error(f'firewall_user must be specified if you are outside the WMKO network')
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
            failcount += 1

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

        return failcount


    def test_localhost(self):
        '''The localhost needs to be defined (e.g. 127.0.0.1)
        '''
        failcount = 0
        self.log.info('Checking localhost')
        if self.ping('localhost') is False:
            self.log.error(f"localhost appears not to be configured")
            self.log.error(f"Your /etc/hosts file may need to be updated")
            failcount += 1

        return failcount


    def test_ssh_key_format(self):
        '''The SSH key must be RSA and must not use a passphrase
        '''
        failcount = 0
        self.log.info('Checking SSH private key format')
        with open(self.ssh_pkey, 'r') as f:
            contents = f.read()

        # Check if this is an RSA key
        foundrsa = re.search('BEGIN RSA PRIVATE KEY', contents)
        if not foundrsa:
            self.log.error(f"Your private key does not appear to be an RSA key")
            failcount += 1

        # Check that there is no passphrase
        foundencrypt = re.search('Proc-Type: \d,ENCRYPTED', contents)
        if foundencrypt:
            self.log.error(f"Your private key appears to require a passphrase.  This is not supported.")
            failcount += 1
        
        return failcount


    def test_firewall_authentication(self):
        '''Test:
        - Must authenticate through the firewall successfully.
        '''
        failcount = 0
        self.log.info('Testing firewall authentication')
        self.firewall_opened = False
        if self.firewall_requested == True:
            self.firewall_pass = getpass(f"\nPassword for firewall authentication: ")
            try:
                self.firewall_opened = self.open_firewall(self.firewall_pass)
            except ConnectionRefusedError as e:
                self.log.error(f'Connection Refused')
                self.log.debug(e)
                self.log.error('Unable to communicate with WMKO firewall on the standard port')
                self.log.info('Testing http authentication')
                import requests
                r = requests.get(f'http://{self.firewall_address}:900')
                got_auth_page = re.match('<html><head><title>Authentication Form</title></head>', r.text)
                if got_auth_page is not None:
                    self.log.info('You may be able to authenticate via http. Go to:')
                    self.log.info(f'http://{self.firewall_address}:900')
                    self.log.info('in a browser to authenticate.  Then run this script again.')
                else:
                    self.log.error('The http authentication route is also inaccessible')
            if self.firewall_opened is False:
                self.log.error('Failed to open firewall')
                failcount += 1

        return failcount


    def test_ssh_key(self):
        '''Test:
        - Must succeed in validating the SSH key.
        '''
        failcount = 0
        self.validate_ssh_key()
        if self.ssh_key_valid is False:
            self.log.error('Failed to validate SSH key')
            failcount += 1

        return failcount


    def test_basic_connectivity(self):
        '''Test:
        - Successfully connect to the listed servers at Keck and get a valid
        response from an SSH command.
        '''
        failcount = 0
        servers_and_results = [('svncserver1', 'kaalualu'),
                               ('svncserver2', 'ohaiula'),
                               ('mosfire', 'vm-mosfire'),
                               ('hires', 'vm-hires'),
                               ('lris', 'vm-lris'),
                               ('kcwi', 'vm-kcwi'),
                               ('nirc2', 'vm-nirc2'),
                               ('nires', 'vm-nires'),
                               ('nirspec', 'vm-nirspec')]
        for server, result in servers_and_results:
            self.log.info(f'Testing SSH to {self.kvnc_account}@{server}.keck.hawaii.edu')

            output = self.do_ssh_cmd('hostname', f'{server}.keck.hawaii.edu',
                                    self.kvnc_account, timeout=20)
            if output is None:
                # On timeout, the result returned by do_ssh_cmd is None
                # Just try a second time
                output = self.do_ssh_cmd('hostname', f'{server}.keck.hawaii.edu',
                                        self.kvnc_account, timeout=20)
            self.log.debug(f'Got hostname "{output}" from {server}')
            if output in [None, '']:
                self.log.error(f'Failed to connect to {server}')
                failcount += 1
            else:
                if output.strip() not in [server, result]:
                    self.log.error(f'Got invalid response from {server}')
                    failcount += 1

        return failcount


    def test_all(self):
        '''Run all of the tests.
        '''
        failcount = 0
        failcount += self.test_config_format()
        failcount += self.test_tigervnc()
        failcount += self.test_localhost()
        failcount += self.test_ssh_key_format()
        if self.test_firewall() is None:
            self.log.error('Could not determine if firewall is open')
            failcount += 1
        failcount += self.test_firewall_authentication()
        failcount += self.test_ssh_key()
        failcount += self.test_basic_connectivity()

        if failcount == 0:
            self.log.info('--> All tests PASSED <--')
        else:
            self.log.error(f'--> Found {failcount} failures during tests <--')

        if self.config.get('vncviewer', False) is not True:
            self.play_test_sound()

        self.exit_app()


##-------------------------------------------------------------------------
## Start from command line
##-------------------------------------------------------------------------
if __name__ == '__main__':
    main()

