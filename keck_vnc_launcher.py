#! /usr/bin/env python3

## Import standard modules
import argparse
import atexit
import datetime
import getpass
import logging
import math
import os
import paramiko
import pathlib
import platform
import re
import socket
import subprocess
import sys
import telnetlib
import threading
import time
import traceback
import warnings
import yaml

## Import local modules
import soundplay


__version__ = '1.0.0rc6'

SESSION_NAMES = ('control0', 'control1', 'control2',
                 'analysis0', 'analysis1', 'analysis2',
                 'telanalys', 'telstatus', 'status')


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


class KeckVncLauncher(object):

    def __init__(self):
        #init vars we need to shutdown app properly
        self.config = None
        self.log = None
        self.sound = None
        self.firewall_pass = None
        self.ports_in_use = dict()
        self.vnc_threads = list()
        self.vnc_processes = list()
        self.firewall_requested = False
        self.firewall_opened = False
        self.instrument = None
        self.vncserver = None
        self.ssh_key_valid = False
        self.exit = False

        self.log = logging.getLogger('KRO')


        #default start sessions
        self.default_sessions = [
            'control0',
            'control1',
            'control2',
            'telstatus',
        ]

        #default servers to try at Keck
        self.servers_to_try = ['svncserver2', 'svncserver1', 'kcwi', 'mosfire']

        #NOTE: 'status' session on different server and always on port 1,
        # so assign localport to constant to avoid conflict
        self.STATUS_PORT = ':1'
        self.LOCAL_PORT_START = 5901

        #ssh key constants
        self.SSH_KEY_ACCOUNT = 'kvnc'
        self.SSH_KEY_SERVER = 'svncserver2.keck.hawaii.edu'


    ##-------------------------------------------------------------------------
    ## Start point (main)
    ##-------------------------------------------------------------------------
    def start(self):

        #global suppression of paramiko warnings
        #todo: log these?
        warnings.filterwarnings(action='ignore', module='.*paramiko.*')

        ##---------------------------------------------------------------------
        ## Parse command line args and get config
        ##---------------------------------------------------------------------
        self.log.debug("\n***** PROGRAM STARTED *****\nCommand: "+' '.join(sys.argv))
        self.get_args()
        self.get_config()
        self.check_config()

        ##---------------------------------------------------------------------
        ## Log basic system info
        ##---------------------------------------------------------------------
        self.log_system_info()
        self.check_version()

        ##---------------------------------------------------------------------
        ## Authenticate Through Firewall (or Disconnect)
        ##---------------------------------------------------------------------
        #todo: handle blank password error properly
        self.firewall_opened = False
        if self.firewall_requested == True:
            self.firewall_pass = getpass.getpass(f"Password for firewall authentication: ")
            try:
                self.firewall_opened = self.open_firewall(self.firewall_pass)
            except:
                self.log.error('Unable to authenticate through firewall')
                trace = traceback.format_exc()
                self.log.debug(trace)

            if self.firewall_opened == False:
                self.exit_app('Authentication failure!')

#         if self.args.authonly is True:
#             self.exit_app('Authentication only')


        ##---------------------------------------------------------------------
        ## Determine sessions to open
        ##---------------------------------------------------------------------
        self.sessions_requested = self.get_sessions_requested(self.args)


        ##---------------------------------------------------------------------
        ## Determine instrument
        ##---------------------------------------------------------------------
        self.instrument, self.tel = self.determine_instrument(self.args.account)
        if self.instrument is None:
            self.exit_app(f'Invalid instrument account: "{self.args.account}"')


        ##---------------------------------------------------------------------
        ## Validate ssh key or use alt method?
        ##---------------------------------------------------------------------
        if self.args.nosshkey is False and self.config.get('nosshkey', None) is None:
            self.validate_ssh_key()
            if self.ssh_key_valid == False:
                self.log.error("\n\n\tCould not validate SSH key.\n\t"\
                          "Contact mainland_observing@keck.hawaii.edu "\
                          "for other options to connect remotely.\n")
                self.exit_app()
        else:
            self.vnc_password = getpass.getpass(f"Password for user {self.args.account}: ")


        ##---------------------------------------------------------------------
        ## Determine VNC server
        ##---------------------------------------------------------------------
        if self.ssh_key_valid == True:
            self.vncserver = self.get_vnc_server(self.SSH_KEY_ACCOUNT,
                                                 None,
                                                 self.instrument)
        else:
            self.vncserver = self.get_vnc_server(self.args.account,
                                                 self.vnc_password,
                                                 self.instrument)
        if self.vncserver is None:
            self.exit_app("Could not determine VNC server.")


        ##---------------------------------------------------------------------
        ## Determine VNC Sessions
        ##---------------------------------------------------------------------
        if self.ssh_key_valid == True:
            # self.engv_account = self.get_engv_account(self.instrument)
            self.sessions_found = self.get_vnc_sessions(self.vncserver,
                                                        self.instrument,
                                                        self.SSH_KEY_ACCOUNT,
                                                        None,
                                                        self.args.account)
        else:
            self.sessions_found = self.get_vnc_sessions(self.vncserver,
                                                        self.instrument,
                                                        self.args.account,
                                                        self.vnc_password,
                                                        self.args.account)
        if self.args.authonly is False and\
                (not self.sessions_found or len(self.sessions_found) == 0):
            self.exit_app('No VNC sessions found')


        ##---------------------------------------------------------------------
        ## Open requested sessions
        ##---------------------------------------------------------------------
        self.calc_window_geometry()
        self.ports_in_use = dict()
        self.vnc_threads = list()
        self.vnc_processes = list()
        for session_name in self.sessions_requested:
            self.start_vnc_session(session_name)


        ##---------------------------------------------------------------------
        ## Open Soundplay
        ##---------------------------------------------------------------------
        sound = None
        if self.args.nosound is False and self.config.get('nosound', False) != True:
            self.start_soundplay()


        ##---------------------------------------------------------------------
        ## Wait for quit signal, then all done
        ##---------------------------------------------------------------------
        atexit.register(self.exit_app, msg="App exit")
        self.prompt_menu()
        self.exit_app()
        #todo: Do we need to call exit here explicitly?  App was not exiting on
        # MacOs but does on linux.


    ##-------------------------------------------------------------------------
    ## Start VNC session
    ##-------------------------------------------------------------------------
    def start_vnc_session(self, session_name):

        self.log.info(f"Opening VNCviewer for '{session_name}'")

#         try:
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
        port = int(f"59{display:02d}")

        ## If authenticating, open SSH tunnel for appropriate ports
        if self.firewall_requested == True:

            #determine account and password
            account = self.SSH_KEY_ACCOUNT if self.ssh_key_valid else self.args.account
            password = None if self.ssh_key_valid else self.vnc_password

            # determine if there is already a tunnel for this session
            local_port = None
            for p in self.ports_in_use.keys():
                if session_name == self.ports_in_use[p][1]:
                    local_port = p
                    self.log.info(f"Found existing SSH tunnel on port {port}")
                    break

            #open ssh tunnel
            if local_port is None:
                try:
                    local_port = self.open_ssh_tunnel(vncserver, account,
                                                      password, self.ssh_pkey,
                                                      port, None,
                                                      session_name=session_name)
                except:
                    self.log.error(f"Failed to open SSH tunnel for "
                              f"{account}@{vncserver}:{port}")
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
        #NOTE: This doesn't work for mac so only trying for linux
        geometry = ''
        if 'linux' in platform.system().lower():
            i = len(self.vnc_threads) % len(self.geometry)
            geom = self.geometry[i]
            width = geom[0]
            height = geom[1]
            xpos = geom[2]
            ypos = geom[3]
            # if width is not None and height is not None:
            #     geometry += f'{width}x{height}'
            if xpos is not None and ypos is not None:
                geometry += f'+{xpos}+{ypos}'

        ## Open vncviewer as separate thread
        self.vnc_threads.append(threading.Thread(target=self.launch_vncviewer,
                                       args=(vncserver, local_port, geometry)))
        self.vnc_threads[-1].start()
        time.sleep(0.05)


    ##-------------------------------------------------------------------------
    ## Get command line args
    ##-------------------------------------------------------------------------
    def get_args(self):
        self.args = create_parser()


    ##-------------------------------------------------------------------------
    ## Get Configuration
    ##-------------------------------------------------------------------------
    def get_config(self):

        #define files to try loading in order of pref
        filenames=['local_config.yaml', 'keck_vnc_config.yaml']

        #if config file specified, put that at beginning of list
        filename = self.args.config
        if filename is not None:
            if not pathlib.Path(filename).is_file():
                self.log.error(f'Specified config file "{filename}" does not exist.')
                self.exit_app()
            else:
                filenames.insert(0, filename)

        #find first file that exists
        file = None
        for f in filenames:
            if pathlib.Path(f).is_file():
                file = f
                break
        if file is None:
            self.log.error(f'No config files found in list: {filenames}')
            self.exit_app()

        #load config file and make sure it has the info we need
        self.log.info(f'Using config file: {file}')

        # open file a first time just to log the raw contents
        with open(file) as FO:
            contents = FO.read()
#             lines = contents.split('/n')
        self.log.debug(f"Contents of config file: {contents}")

        # open file a second time to properly read config
        with open(file) as FO:
            config = yaml.load(FO, Loader=yaml.FullLoader)

        cstr = "Parsed Configuration:\n"
        for key, c in config.items():
            cstr += f"\t{key} = " + str(c) + "\n"
        self.log.debug(cstr)

        self.config = config


    ##-------------------------------------------------------------------------
    ## Check Configuration
    ##-------------------------------------------------------------------------
    def check_config(self):

        #check for vncviewer
        #NOTE: Ok if not specified, we will tell them to open vncviewer manually
        #todo: check if valid cmd path?
        self.vncviewerCmd = self.config.get('vncviewer', None)
        if self.vncviewerCmd is None:
            self.log.warning("Config parameter 'vncviewer' undefined.")
            self.log.warning("You will need to open your vnc viewer manually.\n")

        #checks local port start config
        self.local_port = self.LOCAL_PORT_START
        lps = self.config.get('local_port_start', None)
        if lps is not None:
            self.local_port = lps

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

        #check ssh_pkeys servers_to try
        self.ssh_pkey = self.config.get('ssh_pkey', None)
        if self.ssh_pkey is None:
            self.log.warning("No ssh private key file specified in config file.\n")
        else:
            if not pathlib.Path(self.ssh_pkey).exists():
                self.log.warning(f"SSH private key path does not exist: {self.ssh_pkey}")

        #check default_sessions
        ds = self.config.get('default_sessions', None)
        self.log.debug(f'Default sessions from config file: {ds}')
        if self.args.authonly is True:
            self.log.debug(f'authonly is True, so default sessions set to []')
            ds = list()
        if ds is not None:
            self.default_sessions = ds


    ##-------------------------------------------------------------------------
    ## Log basic system info
    ##-------------------------------------------------------------------------
    def log_system_info(self):
        #todo: gethostbyname stopped working after I updated mac. need better method
        try:
            self.log.debug(f'System Info: {os.uname()}')
            hostname = socket.gethostname()
            self.log.debug(f'System hostname: {hostname}')
            # ip = socket.gethostbyname(hostname)
            # self.log.debug(f'System IP Address: {ip}')
            self.log.info(f'Remote Observing Software Version = {__version__}')
        except:
            self.log.error("Unable to log system info.")
            trace = traceback.format_exc()
            self.log.debug(trace)


    ##-------------------------------------------------------------------------
    ## Get sessions to open
    ##-------------------------------------------------------------------------
    def get_sessions_requested(self, args):

        #get sessions to open
        sessions = list()
        for session in SESSION_NAMES:
            try:
                requested = getattr(args, session)
            except AttributeError:
                continue

            if requested == True:
                sessions.append (session)

        # create default sessions list if none provided
        if len(sessions) == 0:
            sessions = self.default_sessions

        self.log.debug(f'Sessions to open: {sessions}')
        return sessions


    ##-------------------------------------------------------------------------
    ## Print sessions found for instrument
    ##-------------------------------------------------------------------------
    def print_sessions_found(self):

        print(f"\nSessions found for account '{self.args.account}':")
        for s in self.sessions_found:
            print(s)


    ##-------------------------------------------------------------------------
    ## List Open Tunnels
    ##-------------------------------------------------------------------------
    def list_tunnels(self):

        if len(self.ports_in_use) == 0:
            print(f"No SSH tunnels opened by this program")
        else:
            print(f"\nSSH tunnels:")
            print(f"  Local Port | Desktop   | Remote Connection")
            for p in self.ports_in_use.keys():
                desktop = self.ports_in_use[p][1]
                remote_connection = self.ports_in_use[p][0]
                print(f"  {p:10d} | {desktop:9s} | {remote_connection:s}")


    ##-------------------------------------------------------------------------
    ## Launch xterm
    ##-------------------------------------------------------------------------
    def launch_xterm(self, command, pw, title):
        cmd = ['xterm', '-hold', '-title', title, '-e', f'"{command}"']
        xterm = subprocess.call(cmd)


    ##-------------------------------------------------------------------------
    ## Open ssh tunnel
    ##-------------------------------------------------------------------------
    def open_ssh_tunnel(self, server, username, password, ssh_pkey, remote_port,
                        local_port=None, session_name='unknown'):

        # If the local port is not specified attempt to find one dynamically.

        if local_port is None:
            for i in range(0,100):
                if self.is_local_port_in_use(self.local_port):
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


        address_and_port = f"{username}@{server}:{remote_port}"
        self.log.info(f"Opening SSH tunnel for {address_and_port} "
                 f"on local port {local_port}.")


        # We now know everything we need to know in order to establish the
        # tunnel. Build the command line options and start the child process.
        # The -N and -T options below are somewhat exotic: they request that
        # the login process not execute any commands and that the server does
        # not allocate a pseudo-terminal for the established connection.

        forwarding = f"{local_port}:localhost:{remote_port}"
        command = ['ssh', '-l', username, '-L', forwarding, '-N', '-T', server]

        if ssh_pkey is not None:
            command.append('-i')
            command.append(ssh_pkey)

        self.log.debug('ssh command: ' + ' '.join (command))
        process = subprocess.Popen(command)


        # Having started the process let's make sure it's actually running.
        # First try polling,  then confirm the requested local port is in use.
        # It's a fatal error if either check fails.

        if process.poll() is not None:
            raise RuntimeError('subprocess failed to execute ssh')

        # A delay is built-in here as it takes some finite amount of time for
        # ssh to establish the tunnel. 50 checks with a 0.1 second sleep between
        # checks is effectively a five second timeout.

        checks = 50
        while checks > 0:
            result = self.is_local_port_in_use(local_port)
            if result == True:
                break
            else:
                checks -= 1
                time.sleep(0.1)

        if checks == 0:
            raise RuntimeError('ssh tunnel failed to open after 5 seconds')

        in_use = [address_and_port, session_name, process]
        self.ports_in_use[local_port] = in_use
        return local_port



    ##-------------------------------------------------------------------------
    ##-------------------------------------------------------------------------
    def is_local_port_in_use(self, port):
        cmd = f'lsof -i -P -n | grep LISTEN | grep ":{port} (LISTEN)" | grep -v grep'
        self.log.debug(f'Checking for port {port} in use: ' + cmd)
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        data = proc.communicate()[0]
        data = data.decode("utf-8").strip()

        if len(data) == 0:
            return False
        else:
            self.log.debug(f"Port {port} is in use.")
            return True


    ##-------------------------------------------------------------------------
    ## Launch vncviewer
    ##-------------------------------------------------------------------------
    def launch_vncviewer(self, vncserver, port, geometry=None):

        vncviewercmd = self.config.get('vncviewer', 'vncviewer')
        vncprefix = self.config.get('vncprefix', '')
        vncargs = self.config.get('vncargs', None)

        cmd = [vncviewercmd]
        if vncargs is not None:
            vncargs = vncargs.split()
            cmd = cmd + vncargs
        if self.args.viewonly is not None:
            cmd.append('-ViewOnly')
        #todo: make this config on/off so it doesn't break things
        if geometry is not None and geometry != '':
            cmd.append(f'-geometry={geometry}')
        cmd.append(f'{vncprefix}{vncserver}:{port:4d}')

        self.log.debug(f"VNC viewer command: {cmd}")
        # proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
        #                         stderr=subprocess.PIPE)
        proc = subprocess.Popen(cmd)

        #append to proc list so we can terminate on app exit
        self.vnc_processes.append(proc)

        #capture all output and log
        #todo: figure out how to do this realtime as stream instead of only when proc terminates
        # out, err = proc.communicate()
        # out = out.decode()
        # err = err.decode()
        # self.log.debug('vnc comm output: ' + out)
        # if err: self.log.debug('vnc comm err: ' + err)


    ##-------------------------------------------------------------------------
    ## Start soundplay
    ##-------------------------------------------------------------------------
    def start_soundplay(self):

        try:
            #check for existing first and shutdown
            if self.sound is not None:
                self.sound.terminate()

            #config vars
            sound_port = 9798
            aplay = self.config.get('aplay', None)
            soundplayer = self.config.get('soundplayer', None)
            vncserver = self.vncserver

            #Do we need ssh tunnel for this?
            if self.firewall_requested == True:

                account = self.SSH_KEY_ACCOUNT if self.ssh_key_valid else self.args.account
                password = None if self.ssh_key_valid else self.vnc_password
                try:
                    sound_port = self.open_ssh_tunnel(self.vncserver, account,
                                                      password, self.ssh_pkey,
                                                      sound_port, None)
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
            #todo: should we start this as a thread?
            # sound = sound = threading.Thread(target=launch_soundplay, args=(vncserver, 9798, instrument,))
            # soundThread.start()
        except:
            self.log.error('Unable to start soundplay.  See log for details.')
            trace = traceback.format_exc()
            self.log.debug(trace)


    def play_test_sound(self):
        self.log.warning('Playing of a test sound is not yet implemented')


    ##-------------------------------------------------------------------------
    ## Open the firewall hole for ssh traffic
    ##-------------------------------------------------------------------------
    def open_firewall(self, authpass):

        #todo: shorten timeout for mistyped password

        self.log.info(f'Authenticating through firewall as:')
        self.log.info(f' {self.firewall_user}@{self.firewall_address}:{self.firewall_port}')

        tn = telnetlib.Telnet(self.firewall_address, int(self.firewall_port))
        tn.read_until(b"User: ", timeout=5)
        tn.write(f'{self.firewall_user}\n'.encode('ascii'))
        tn.read_until(b"password: ", timeout=5)
        tn.write(f'{authpass}\n'.encode('ascii'))
        tn.read_until(b"Enter your choice: ", timeout=5)
        tn.write('1\n'.encode('ascii'))
        result = tn.read_all().decode('ascii')

        if re.search('User authorized for standard services', result):
            self.log.info('User authorized for standard services')
            return True
        else:
            self.log.error(result)
            return False


    ##-------------------------------------------------------------------------
    ## Close the firewall hole for ssh traffic
    ##-------------------------------------------------------------------------
    def close_firewall(self, authpass):

        if self.firewall_opened == False:
            return

        self.log.info('Signing off of firewall authentication')
        tn = telnetlib.Telnet(self.firewall_address, int(self.firewall_port))
        tn.read_until(b"User: ", timeout=5)
        tn.write(f'{self.firewall_user}\n'.encode('ascii'))
        tn.read_until(b"password: ", timeout=5)
        tn.write(f'{authpass}\n'.encode('ascii'))
        tn.read_until(b"Enter your choice: ", timeout=5)
        tn.write('2\n'.encode('ascii'))
        result = tn.read_all().decode('ascii')

        if re.search('User was signed off from all services', result):
            self.log.info('User was signed off from all services')
        else:
            self.log.error(result)


    ##-------------------------------------------------------------------------
    ## Determine Instrument
    ##-------------------------------------------------------------------------
    def determine_instrument(self, account):
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
                     'nires':   2,
                     'deimos':  2,
                     'esi':     2,
                     'nirc2':   2,
                     'nirspec': 2,
                     'kcwi':    2,
                    }

        for instrument in accounts.keys():
            if account.lower() in accounts[instrument]:
                return instrument, telescope[instrument]

        return None, None


    ##-------------------------------------------------------------------------
    ## Utility function for opening ssh client, executing command and closing
    ##-------------------------------------------------------------------------
    def do_ssh_cmd(self, cmd, server, account, password):
        try:
            output = None
            self.log.debug(f'Trying SSH connect to {server} as {account}:')

            client = paramiko.SSHClient()
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.WarningPolicy())
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                server,
                port = 22,
                timeout = 6,
                key_filename=self.ssh_pkey,
                username = account,
                password = password)
            self.log.info('  Connected')
        except TimeoutError:
            self.log.error('  Timeout')
        except Exception as e:
            self.log.error('  Failed: ' + str(e))
            trace = traceback.format_exc()
            self.log.debug(trace)
        else:
            self.log.debug(f'Command: {cmd}')
            stdin, stdout, stderr = client.exec_command(cmd)
            output = stdout.read()
            output = output.decode().strip('\n')
            self.log.debug(f"Output: '{output}'")
        finally:
            client.close()
            return output


    ##-------------------------------------------------------------------------
    ## Validate ssh key on remote vnc server
    ##-------------------------------------------------------------------------
    def validate_ssh_key(self):
        self.log.info(f"Validating ssh key...")

        self.ssh_key_valid = False
        cmd = 'whoami'
        data = self.do_ssh_cmd(cmd, self.SSH_KEY_SERVER, self.SSH_KEY_ACCOUNT,
                               None)

        if data == self.SSH_KEY_ACCOUNT:
            self.ssh_key_valid = True

        if self.ssh_key_valid == True:
            self.log.info("  SSH key OK")
        else:
            self.log.error("  SSH key invalid")


    ##-------------------------------------------------------------------------
    ## Get engv account for instrument
    ##-------------------------------------------------------------------------
    def get_engv_account(self, instrument):
        self.log.info(f"Getting engv account for instrument {instrument} ...")

        cmd = f'setenv INSTRUMENT {instrument}; kvncinfo -engineering'
        data = self.do_ssh_cmd(cmd, self.SSH_KEY_SERVER, self.SSH_KEY_ACCOUNT,
                               None)

        engv = None
        if data and ' ' not in data:
            engv = data

        if engv is not None:
            self.log.debug("engv account is: '{}'")
        else:
            self.log.error("Could not get engv account info.")

        return engv


    ##-------------------------------------------------------------------------
    ## Determine VNC Server
    ##-------------------------------------------------------------------------
    def get_vnc_server(self, account, password, instrument):
        self.log.info(f"Determining VNC server for '{account}'...")
        vncserver = None
        for server in self.servers_to_try:
            server += ".keck.hawaii.edu"
            cmd = f'kvncinfo -server -I {instrument}'
            data = self.do_ssh_cmd(cmd, server, account, password)
            if data is not None and ' ' not in data:
                vncserver = data
                self.log.info(f"Got VNC server: '{vncserver}'")
                break

        # todo: Temporary hack for KCWI
        if vncserver == 'vm-kcwivnc':
            vncserver = 'kcwi'

        if vncserver is not None and 'keck.hawaii.edu' not in vncserver:
            vncserver += '.keck.hawaii.edu'

        return vncserver


    ##-------------------------------------------------------------------------
    ## Determine VNC Sessions
    ##-------------------------------------------------------------------------
    def get_vnc_sessions(self, vncserver, instrument, account, password,
                         instr_account):
        self.log.info(f"Connecting to {account}@{vncserver} to get VNC sessions list")

        sessions = list()
        cmd = f'setenv INSTRUMENT {instrument}; kvncstatus -a'
        data = self.do_ssh_cmd(cmd, vncserver, account, password)
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
    ## Close ssh threads
    ##-------------------------------------------------------------------------
    def close_ssh_thread(self, p):
        try:
            remote_connection, desktop, process = self.ports_in_use.pop(p, None)
        except KeyError:
            return

        self.log.info(f" Closing SSH tunnel for port {p:d}, {desktop:s} "
                 f"on {remote_connection:s}")
        process.kill()


    def close_ssh_threads(self):
        for p in list(self.ports_in_use.keys()):
            self.close_ssh_thread(p)


    ##-------------------------------------------------------------------------
    ## Calculate vnc windows size and position
    ##-------------------------------------------------------------------------
    def calc_window_geometry(self):

        self.log.debug(f"Calculating VNC window geometry...")

        #get screen dimensions
        #alternate command: xrandr |grep \* | awk '{print $1}'
        cmd = "xdpyinfo | grep dimensions | awk '{print $2}' | awk -Fx '{print $1, $2}'"
        p1 = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        out = p1.communicate()[0].decode('utf-8')
        screen_width, screen_height = [int(x) for x in out.split()]
        self.log.debug(f"Screen size: {screen_width}x{screen_height}")

        #get num rows and cols
        #todo: assumming 2x2 always for now; make smarter
        num_win = len(self.sessions_requested)
        cols = 2
        rows = 2

        #window coord and size config overrides
        window_positions = self.config.get('window_positions', None)
        window_size = self.config.get('window_size', None)

        #get window width height
        if window_size is None:
            ww = round(screen_width / cols)
            wh = round(screen_height / rows)
        else:
            ww = window_size[0]
            wh = window_size[1]

        #get x/y coords (assume two rows)
        self.geometry = list()
        for row in range(0, rows):
            for col in range(0, cols):
                x = round(col * screen_width/cols)
                y = round(row * screen_height/rows)
                if window_positions is not None:
                    index = len(self.geometry) % len(window_positions)
                    x = window_positions[index][0]
                    y = window_positions[index][1]
                self.geometry.append([ww, wh, x, y])

        self.log.debug('geometry: ' + str(self.geometry))


    ##-------------------------------------------------------------------------
    ## Position vncviewers
    ##-------------------------------------------------------------------------
    def position_vnc_windows(self):

        self.log.info(f"Positioning VNC windows...")

        #get all x-window processes
        #NOTE: using wmctrl (does not work for Mac)
        #alternate option: xdotool?
        xlines = list()
        cmd = ['wmctrl', '-l']
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        while True:
            line = proc.stdout.readline()
            if line is None or line == '':
                break
            line = line.rstrip().decode('utf-8')
            self.log.debug(f'wmctrl line: {line}')
            xlines.append(line)

        #reposition each vnc session window
        for i, session in enumerate(self.sessions_requested):
            self.log.debug(f'Search xlines for "{session}"')
            win_id = None
            for line in xlines:
                if session not in line:
                    continue
                parts = line.split()
                win_id = parts[0]

            if win_id is not None:
                index = i % len(self.geometry)
                geom = self.geometry[index]
                ww = geom[0]
                wh = geom[1]
                wx = geom[2]
                wy = geom[3]
                # cmd = ['wmctrl', '-i', '-r', win_id, '-e', f'0,{wx},{wy},{ww},{wh}']
                cmd = ['wmctrl', '-i', '-r', win_id, '-e',
                       f'0,{wx},{wy},-1,-1']
                self.log.debug(f"Positioning '{session}' with command: " + ' '.join(cmd))
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
            else:
                self.log.info(f"Could not find window process for VNC session '{session}'")


    ##-------------------------------------------------------------------------
    ## Prompt command line menu and wait for quit signal
    ##-------------------------------------------------------------------------
    def prompt_menu(self):

        line_length = 52
        lines = [f"-"*(line_length-2),
                 f"          Keck Remote Observing (v{__version__})",
                 f"                        MENU",
                 f"-"*(line_length-2),
                 f"  l               List sessions available",
                 f"  [session name]  Open VNC session by name",
                 f"  w               Position VNC windows",
                 f"  s               Soundplayer restart",
                 f"  u               Upload log to Keck",
#                  f"|  p               Play a local test sound",
                 f"  t               List local ports in use",
                 f"  c [port]        Close ssh tunnel on local port",
                 f"  v               Check if software is up to date",
                 f"  q               Quit (or Control-C)",
                 f"-"*(line_length-2),
                 ]
        menu = "\n"
        for newline in lines:
            menu += '|' + newline + ' '*(line_length-len(newline)-1) + '|\n'
        menu += "> "

        quit = None
        while quit is None:
            cmd = input(menu).lower()
            cmatch = re.match(r'c (\d+)', cmd)
            if cmd == '':
                pass
            elif cmd == 'q':
                self.log.info(f'Recieved command "{cmd}"')
                quit = True
            elif cmd == 'w':
                self.log.info(f'Recieved command "{cmd}"')
                try:
                    self.position_vnc_windows()
                except:
                    self.log.error("Failed to reposition windows.  See log for details.")
                    trace = traceback.format_exc()
                    self.log.debug(trace)
            elif cmd == 'p':
                self.log.info(f'Recieved command "{cmd}"')
                self.play_test_sound()
            elif cmd == 's':
                self.log.info(f'Recieved command "{cmd}"')
                self.start_soundplay()
            elif cmd == 'u':
                self.log.info(f'Recieved command "{cmd}"')
                self.upload_log()
            elif cmd == 'l':
                self.log.info(f'Recieved command "{cmd}"')
                self.print_sessions_found()
            elif cmd == 't':
                self.log.info(f'Recieved command "{cmd}"')
                self.list_tunnels()
            elif cmd == 'v':
                self.log.info(f'Recieved command "{cmd}"')
                self.check_version()
            elif cmatch is not None:
                self.log.info(f'Recieved command "{cmd}"')
                self.close_ssh_thread(int(cmatch.group(1)))
            #elif cmd == 'v': self.validate_ssh_key()
            #elif cmd == 'x': self.kill_vnc_processes()
            elif cmd in [s.name for s in self.sessions_found]:
                self.log.info(f'Recieved command "{cmd}"')
                self.start_vnc_session(cmd)
            else:
                self.log.info(f'Recieved command "{cmd}"')
                self.log.error(f'Unrecognized command: "{cmd}"')


    ##-------------------------------------------------------------------------
    ## Check for latest version number on GitHub
    ##-------------------------------------------------------------------------
    def check_version(self):
        url = ('https://raw.githubusercontent.com/KeckObservatory/'
               'RemoteObserving/master/keck_vnc_launcher.py')
        try:
            import requests
            from packaging import version
            r = requests.get(url)
            findversion = re.search("__version__ = '(\d.+)'\n", r.text)
            if findversion is not None:
                remote_version = version.parse(findversion.group(1))
                local_version = version.parse(__version__)
            else:
                self.log.warning(f'Unable to determine software version on GitHub')
                return
            if remote_version == local_version:
                self.log.info(f'Your software is up to date (v{__version__})')
            elif remote_version > local_version:
                self.log.info(f'Your software (v{__version__}) is ahead of the released version')
            else:
                self.log.warning(f'Your local software (v{__version__}) is behind '
                                 f'the currently available version '
                                 f'(v{remote_version})')
        except:
            self.log.warning("Unable to verify remote version")

    ##-------------------------------------------------------------------------
    ## Upload log file to Keck
    ##-------------------------------------------------------------------------
    def upload_log(self):
        try:
            user = self.SSH_KEY_ACCOUNT if self.ssh_key_valid else self.args.account
            pw = None if self.ssh_key_valid else self.vnc_password

            client = paramiko.SSHClient()
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.WarningPolicy())
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                self.vncserver,
                port = 22,
                timeout = 6,
                key_filename=self.ssh_pkey,
                username = user,
                password = pw)
            sftp = client.open_sftp()
            self.log.info('  Connected SFTP')

            logfile_handlers = [lh for lh in self.log.handlers if
                                isinstance(lh, logging.FileHandler)]
            logfile = pathlib.Path(logfile_handlers.pop(0).baseFilename)
            destination = logfile.name
            sftp.put(logfile, destination)
            self.log.info(f'  Uploaded {logfile.name}')
            self.log.info(f'  to {self.args.account}@{self.vncserver}:{destination}')
        except TimeoutError:
            self.log.error('  Timed out trying to upload log file')
        except Exception as e:
            self.log.error('  Unable to upload logfile: ' + str(e))
            trace = traceback.format_exc()
            self.log.debug(trace)


    ##-------------------------------------------------------------------------
    ## Terminate all vnc processes
    ##-------------------------------------------------------------------------
    def kill_vnc_processes(self, msg=None):

        self.log.info('Terminating all VNC sessions.')
        try:
            #NOTE: poll() value of None means it still exists.
            while self.vnc_processes:
                proc = self.vnc_processes.pop()
                self.log.debug('terminating VNC process: ' + str(proc.args))
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

        #hack for preventing this function from being called twice
        #todo: need to figure out how to use atexit with threads properly
        if self.exit == True:
            return

        self.exit = True
        #todo: Fix app exit so certain clean ups don't cause errors (ie thread not started, etc
        if msg is not None:
            self.log.info(msg)

        #terminate soundplayer
        if self.sound is not None:
            self.sound.terminate()

        # Close down ssh tunnels and firewall authentication
        self.close_ssh_threads()

        try:
            self.close_firewall(self.firewall_pass)
        except:
            self.log.error('Unable to close firewall authentication!')

        #close vnc sessions
        self.kill_vnc_processes()

        self.log.info("EXITING APP\n")
        sys.exit(1)


    ##-------------------------------------------------------------------------
    ## Handle fatal error
    ##-------------------------------------------------------------------------
    def handle_fatal_error(self, error):

        #helpful user error message
        supportEmail = 'mainland_observing@keck.hawaii.edu'
        print("\n****** PROGRAM ERROR ******\n")
        print("Error message: " + str(error) + "\n")
        print("If you need troubleshooting assistance:")
        print(f"* Email {supportEmail}\n")
        #todo: call number, website?

        #Log error if we have a log object (otherwise dump error to stdout)
        #and call exit_app function
        msg = traceback.format_exc()

        if self.log is None:
            print(msg)
        else:
            logfile = self.log.handlers[0].baseFilename
            print(f"* Attach log file at: {logfile}\n")
            self.log.debug(f"\n\n!!!!! PROGRAM ERROR:\n{msg}\n")

        self.exit_app()


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
                   f"mainland_observing@keck.hawaii.edu")
    parser = argparse.ArgumentParser(description=description)

    ## add flags
    parser.add_argument("--authonly", dest="authonly",
        default=False, action="store_true",
        help="Authenticate through firewall, but do not start VNC sessions.")
    parser.add_argument("--nosound", dest="nosound",
        default=False, action="store_true",
        help="Skip start of soundplay application.")
    parser.add_argument("--viewonly", dest="viewonly",
        default=False, action="store_true",
        help="Open VNC sessions in View Only mode (only for TigerVnC viewer)")
    parser.add_argument("--nosshkey", dest="nosshkey",
        default=False, action="store_true",
        help=argparse.SUPPRESS)
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
    return parser.parse_args()

##-------------------------------------------------------------------------
## Create logger
##-------------------------------------------------------------------------
def create_logger():

    try:
        ## Create logger object
        log = logging.getLogger('KRO')
        log.setLevel(logging.DEBUG)

        #create log file and log dir if not exist
        ymd = datetime.datetime.utcnow().date().strftime('%Y%m%d')
        pathlib.Path('logs/').mkdir(parents=True, exist_ok=True)

        #file handler (full debug logging)
        logFile = f'logs/keck-remote-log-utc-{ymd}.txt'
        logFileHandler = logging.FileHandler(logFile)
        logFileHandler.setLevel(logging.DEBUG)
        logFormat = logging.Formatter('%(asctime)s UT - %(levelname)s: %(message)s')
        logFormat.converter = time.gmtime
        logFileHandler.setFormatter(logFormat)
        log.addHandler(logFileHandler)

        #stream/console handler (info+ only)
        logConsoleHandler = logging.StreamHandler()
        logConsoleHandler.setLevel(logging.INFO)
        logFormat = logging.Formatter(' %(levelname)8s: %(message)s')
        logFormat.converter = time.gmtime
        logConsoleHandler.setFormatter(logFormat)

        log.addHandler(logConsoleHandler)

    except Exception as error:
        print(str(error))
        print(f"ERROR: Unable to create logger at {logFile}")
        print("Make sure you have write access to this directory.\n")
        log.info("EXITING APP\n")
        sys.exit(1)


##-------------------------------------------------------------------------
## Start from command line
##-------------------------------------------------------------------------
if __name__ == '__main__':

    #catch all exceptions so we can exit gracefully
    try:
        create_logger()
        kvl = KeckVncLauncher()
        kvl.start()
    except Exception as error:
        kvl.handle_fatal_error(error)


