
#!/usr/env/python

## Import General Tools
import os
import sys
import re
import socket
import argparse
import logging
import time
import yaml
from getpass import getpass
import paramiko
from time import sleep
from threading import Thread
from telnetlib import Telnet
from astropy.table import Table, Column
from soundplay import soundplay
import atexit
from datetime import datetime
import traceback
import pathlib
import math
import subprocess
import warnings
import sshtunnel
import platform

__version__ = '0.9'

class KeckVncLauncher(object):

    def __init__(self):
        #init vars we need to shutdown app properly
        self.config = None
        self.sound = None
        self.firewall_pass = None
#         self.ssh_threads = None
        self.ports_in_use = None
        self.vnc_processes = None
        self.do_authenticate = False
        self.is_authenticated = False
        self.instrument = None
        self.vncserver = None
        self.is_ssh_key_valid = False
        self.exit = False


        #session name consts
        self.SESSION_NAMES = [
            'control0',
            'control1',
            'control2',
            'analysis0',
            'analysis1',
            'analysis2',
            'telanalys',
            'telstatus',
            'status'
        ]

        #default start sessions
        self.DEFAULT_SESSIONS = [
            'control0',
            'control1',
            'control2',
            'telstatus',
        ]

        #NOTE: 'status' session on different server and always on port 1, 
        # so assign localport to constant to avoid conflict
        self.STATUS_PORT       = ':1'
        self.LOCAL_PORT_START  = 5901

        #ssh key constants
        self.SSH_KEY_ACCOUNT = 'kvnc'
        self.SSH_KEY_SERVER  = 'svncserver2.keck.hawaii.edu'


    ##-------------------------------------------------------------------------
    ## Start point (main)
    ##-------------------------------------------------------------------------
    def start(self):
    
        #global suppression of paramiko warnings
        #todo: log these?
        warnings.filterwarnings(action='ignore', module='.*paramiko.*')


        ##---------------------------------------------------------------------
        ## Log basic system info
        ##---------------------------------------------------------------------
        log.debug("\n***** PROGRAM STARTED *****\nCommand: "+' '.join(sys.argv))
        self.log_system_info()


        ##---------------------------------------------------------------------
        ## Parse command line args and get config
        ##---------------------------------------------------------------------
        self.get_args()
        self.get_config()
        self.check_config()

        ##---------------------------------------------------------------------
        ## Authenticate Through Firewall (or Disconnect)
        ##---------------------------------------------------------------------
        #todo: handle blank password error properly
        self.is_authenticated = False
        if self.do_authenticate:
            self.firewall_pass = getpass(f"Password for firewall authentication: ")
            self.is_authenticated = self.authenticate(self.firewall_pass)
            if not self.is_authenticated:
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
        if not self.instrument: 
            self.exit_app(f'Invalid instrument account: "{self.args.account}"')


        ##---------------------------------------------------------------------
        ## Validate ssh key or use alt method?
        ##---------------------------------------------------------------------
        if self.args.nosshkey is False and self.config.get('nosshkey', None) is None:
            self.validate_ssh_key()
            if not self.is_ssh_key_valid:
                log.error("\n\n\tCould not validate SSH key.\n\t"\
                          "Contact mainland_observing@keck.hawaii.edu "\
                          "for other options to connect remotely.\n")
                self.exit_app()
        else:
            self.vnc_password = getpass(f"Password for user {self.args.account}: ")


        ##---------------------------------------------------------------------
        ## Determine VNC server
        ##---------------------------------------------------------------------
        if self.is_ssh_key_valid:
            self.vncserver = self.get_vnc_server(self.SSH_KEY_ACCOUNT,
                                                 None,
                                                 self.instrument)
        else:
            self.vncserver = self.get_vnc_server(self.args.account,
                                                 self.vnc_password,
                                                 self.instrument)
        if not self.vncserver:
            self.exit_app("Could not determine VNC server.")


        ##---------------------------------------------------------------------
        ## Determine VNC Sessions
        ##---------------------------------------------------------------------
        if self.is_ssh_key_valid:
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
        if not self.sessions_found or len(self.sessions_found) == 0:
            self.exit_app('No VNC sessions found')


        ##---------------------------------------------------------------------
        ## Open requested sessions
        ##---------------------------------------------------------------------
        self.calc_window_geometry()
#         self.ssh_threads  = []
        self.ports_in_use = {}
        self.vnc_threads  = []
        self.vnc_processes = []
        for session_name in self.sessions_requested:
            self.start_vnc_session(session_name)


        ##---------------------------------------------------------------------
        ## Open Soundplay
        ## TODO: Does this work if we are authenticating or do we need an ssh tunnel?
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

        log.info(f"Opening VNCviewer for '{session_name}'")

        try:
            #get session data by name
            session = None
            for tmp in self.sessions_found:
                if tmp['name'] == session_name:
                    session = tmp
            if not session:
                log.error(f"No server VNC session found for '{session_name}'.")
                self.print_sessions_found()
                return

            #determine vncserver (only different for "status")
            vncserver = self.vncserver
            if session_name == 'status':
                vncserver = f"svncserver{self.tel}.keck.hawaii.edu"

            #get remote port
            display   = int(session['Display'][1:])
            port      = int(f"59{display:02d}")

            ## If authenticating, open SSH tunnel for appropriate ports
            if self.do_authenticate:

                #determine account and password         
                account  = self.SSH_KEY_ACCOUNT if self.is_ssh_key_valid else self.args.account
                password = None if self.is_ssh_key_valid else self.vnc_password

                #open ssh tunnel
                port = self.open_ssh_tunnel(vncserver, account, password,
                                            self.ssh_pkey, port, None,
                                            session_name=session_name)
                if not port:
                    return
                else:
                    vncserver = 'localhost'

            #If vncviewer is not defined, then prompt them to open manually and
            # return now
            if self.config['vncviewer'] in [None, 'None', 'none']:
                log.info(f"\nNo VNC viewer application specified")
                log.info(f"Open your VNC viewer manually\n")
                return

            #determine geometry
            #NOTE: This doesn't work for mac so only trying for linux
            geometry = ''
            if 'linux' in platform.system().lower():
                i = len(self.vnc_threads) % len(self.geometry)
                geom = self.geometry[i]
                width  = geom[0]
                height = geom[1]
                xpos   = geom[2]
                ypos   = geom[3]
                # if width != None and height != None:
                #     geometry += f'{width}x{height}'
                if xpos != None and ypos != None:
                    geometry += f'+{xpos}+{ypos}'

            ## Open vncviewer as separate thread
            self.vnc_threads.append(Thread(target=self.launch_vncviewer,
                                           args=(vncserver, port, geometry)))
            self.vnc_threads[-1].start()
            sleep(0.05)

        except Exception as error:
            log.error("Unable to start vnc session.  See log for details.")
            log.debug(str(error))


    ##-------------------------------------------------------------------------
    ## Get command line args
    ##-------------------------------------------------------------------------
    def get_args(self):

        ## create a parser object for understanding command-line arguments
        parser = argparse.ArgumentParser(description="Keck VNC Launcher")

        ## add flags
        parser.add_argument("--authonly", dest="authonly",
            default=False, action="store_true",
            help="Authenticate through firewall, but do not start VNC sessions.")
        parser.add_argument("--nosound", dest="nosound",
            default=False, action="store_true",
            help="Skip start of soundplay application.")
        parser.add_argument("--viewonly", dest="viewonly",
            default=False, action="store_true",
            help="Open VNC sessions in View Only mode")
        parser.add_argument("--nosshkey", dest="nosshkey",
            default=False, action="store_true",
            help=argparse.SUPPRESS)
        for name in self.SESSION_NAMES:
            parser.add_argument(f"--{name}", 
                dest=name, 
                default=False, 
                action="store_true", 
                help=f"Open {name}")

        ## add arguments
        parser.add_argument("account", type=str, help="The user account.")

        ## add options
        parser.add_argument("-c", "--config", dest="config", type=str,
            help="Path to local configuration file.")

        #parse
        self.args = parser.parse_args()
        

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
                log.error(f'Specified config file "{filename}" does not exist.')
                self.exit_app()
            else:
                filenames.insert(0, filename)

        #find first file that exists
        file = None
        for f in filenames:
            if pathlib.Path(f).is_file():
                file = f
                break
        if not file:
            log.error(f'No config files found in list: {filenames}')
            self.exit_app()

        #load config file and make sure it has the info we need
        log.info(f'Using config file: {file}')

        # open file a first time just to log the raw contents
        with open(file) as FO:
            contents = FO.read()
#             lines = contents.split('/n')
        log.debug(f"Contents of config file: {contents}")

        # open file a second time to properly read config
        with open(file) as FO:
            config = yaml.safe_load(FO)

        cstr = "Parsed Configuration:\n"
        for key, c in config.items():
            cstr += f"\t{key} = " + str(c) + "\n"
        log.debug(cstr)

        self.config = config


    ##-------------------------------------------------------------------------
    ## Check Configuration
    ##-------------------------------------------------------------------------
    def check_config(self):

        #checks servers_to try
        self.servers_to_try = self.config.get('servers_to_try', None)
        if not self.servers_to_try:
            log.error("Config parameter 'servers_to_try' undefined.\n")
            self.exit_app()

        #check for vncviewer
        #NOTE: Ok if not specified, we will tell them to open vncviewer manually
        #todo: check if valid cmd path?
        self.vncviewerCmd = self.config.get('vncviewer', None)
        if not self.vncviewerCmd:
            log.warning("Config parameter 'vncviewer' undefined.")
            log.warning("You will need to open your vnc viewer manually.\n")

        #checks local port start config
        self.local_port = self.LOCAL_PORT_START
        lps = self.config.get('local_port_start', None)
        if lps: self.local_port = lps

        #check firewall config
        self.do_authenticate = False
        self.firewall_address = self.config.get('firewall_address', None)
        self.firewall_user    = self.config.get('firewall_user',    None)
        self.firewall_port    = self.config.get('firewall_port',    None)
        if self.firewall_address or self.firewall_user or self.firewall_port:
            if self.firewall_address and self.firewall_user and self.firewall_port:
                self.do_authenticate = True
            else:
                log.warning("Partial firewall configuration detected in config file:")
                if not self.firewall_address: log.warning("firewall_address not set")
                if not self.firewall_user: log.warning("firewall_user not set")
                if not self.firewall_port: log.warning("firewall_port not set")

        #check ssh_pkeys servers_to try
        self.ssh_pkey = self.config.get('ssh_pkey', None)
        if not self.ssh_pkey:
            log.warning("No ssh private key file specified in config file.\n")
        else:
            if not pathlib.Path(self.ssh_pkey).exists():
                log.warning(f"SSH private key path does not exist: {self.ssh_pkey}")

        #check default_sessions
        ds = self.config.get('default_sessions', None)
        log.debug(f'Default sessions from config file: {ds}')
        if self.args.authonly is True:
            log.debug(f'authonly is True, so default sessions set to []')
            ds = []
        if ds is not None: self.DEFAULT_SESSIONS = ds


    ##-------------------------------------------------------------------------
    ## Log basic system info
    ##-------------------------------------------------------------------------
    def log_system_info(self):
        #todo: gethostbyname stopped working after I updated mac. need better method
        try:
            log.debug(f'System Info: {os.uname()}')
            hostname = socket.gethostname()
            log.debug(f'System hostname: {hostname}')
            # ip = socket.gethostbyname(hostname)
            # log.debug(f'System IP Address: {ip}')
            log.info(f'Remote Observing Software Version = {__version__}')
        except Exception as error:
            log.error("Unable to log system info.")
            log.debug(str(error))


    ##-------------------------------------------------------------------------
    ## Get sessions to open
    ##-------------------------------------------------------------------------
    def get_sessions_requested(self, args):

        #get sessions to open
        #todo: use const SESSION_NAMES here
        sessions = []
        if args.control0  is True: sessions.append('control0')
        if args.control1  is True: sessions.append('control1')
        if args.control2  is True: sessions.append('control2')
        if args.telstatus is True: sessions.append('telstatus')
        if args.analysis0 is True: sessions.append('analysis0')
        if args.analysis1 is True: sessions.append('analysis1')
        if args.analysis2 is True: sessions.append('analysis2')
        if args.telanalys is True: sessions.append('telanalys')
        if args.status    is True: sessions.append('status')

        # create default sessions list if none provided
        if len(sessions) == 0:
            sessions = self.DEFAULT_SESSIONS

        log.debug(f'Sessions to open: {sessions}')
        return sessions


    ##-------------------------------------------------------------------------
    ## Print sessions found for instrument
    ##-------------------------------------------------------------------------
    def print_sessions_found(self):

        print(f"\nSessions found for account '{self.args.account}':")
        for s in self.sessions_found:
            print(f"  {s['name']:12s} {s['Display']:5s} {s['Desktop']:s}")


    ##-------------------------------------------------------------------------
    ## List Open Tunnels
    ##-------------------------------------------------------------------------
    def list_tunnels(self):

        if len(self.ports_in_use) == 0:
            print(f"No local ports opened for SSH tunnels")
        else:
            print(f"\nLocal ports used for SSH tunnels:")
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

        #get next local port if need be
        #NOTE: Try up to 100 ports beyond
        if not local_port:
            for i in range(0,100):
                if self.is_local_port_in_use(self.local_port): 
                    self.local_port += 1
                    continue
                else:
                    local_port = self.local_port
                    self.local_port += 1
                    break

        #if we can't find an open port, error and return
        if not local_port:
            log.error(f"Could not find an open local port for SSH tunnel to {username}@{server}:{remote_port}")
            self.local_port = self.LOCAL_PORT_START
            return False

        #log
        address_and_port = f"{username}@{server}:{remote_port}"
        log.info(f"Opening SSH tunnel for {address_and_port} "
                 f"on local port {local_port}.")

        #try to open ssh tunnel
        try:
            thread = sshtunnel.SSHTunnelForwarder(
                server,
                ssh_username=username,
                ssh_password=password,
                ssh_pkey=ssh_pkey,
                remote_bind_address=('127.0.0.1', remote_port),
                local_bind_address=('0.0.0.0', local_port),
            )
            thread.start()

            #if success, keep track of ssh threads and ports in use
#             self.ssh_threads.append(thread)
            self.ports_in_use[local_port] = [address_and_port, session_name, thread]
            return local_port

        except Exception as e:
            log.error(f"Failed to open SSH tunnel for "
                      f"{username}@{server}:{remote_port} "
                      f"on local port {local_port}.")
            log.debug(str(e))
            return False


    ##-------------------------------------------------------------------------
    ##-------------------------------------------------------------------------
    def is_local_port_in_use(self, port):
        cmd = f'lsof -i -P -n | grep LISTEN | grep ":{port} (LISTEN)" | grep -v grep'
        log.debug(f'Checking for port {port} in use: ' + cmd)
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        data = proc.communicate()[0]
        data = data.decode("utf-8").strip()
        lines = data.split('\n') if data else []
        if lines:
            log.debug(f"Port {port} is in use.")
            return True
        else: 
            return False


    ##-------------------------------------------------------------------------
    ## Launch vncviewer
    ##-------------------------------------------------------------------------
    def launch_vncviewer(self, vncserver, port, geometry=None):

        vncviewercmd   = self.config.get('vncviewer', 'vncviewer')
        vncprefix      = self.config.get('vncprefix', '')
        vncargs        = self.config.get('vncargs', None)

        cmd = [vncviewercmd]
        if vncargs:  
            vncargs = vncargs.split()           
            cmd = cmd + vncargs
        if self.args.viewonly:  cmd.append('-ViewOnly')
        #todo: make this config on/off so it doesn't break things 
        if geometry:            cmd.append(f'-geometry={geometry}')
        cmd.append(f'{vncprefix}{vncserver}:{port:4d}')

        log.debug(f"VNC viewer command: {cmd}")
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
        # log.debug('vnc comm output: ' + out)
        # if err: log.debug('vnc comm err: ' + err)


    ##-------------------------------------------------------------------------
    ## Start soundplay
    ##-------------------------------------------------------------------------
    def start_soundplay(self):

        try:
            #check for existing first and shutdown
            if self.sound:
                self.sound.terminate()

            #config vars
            sound_port  = 9798
            aplay       = self.config.get('aplay', None)
            soundplayer = self.config.get('soundplayer', None)

            #Do we need ssh tunnel for this?
            if self.do_authenticate:

                account  = self.SSH_KEY_ACCOUNT if self.is_ssh_key_valid else self.args.account
                password = None if self.is_ssh_key_valid else self.vnc_password
                sound_port = self.open_ssh_tunnel(self.vncserver, account,
                                                  password, self.ssh_pkey,
                                                  sound_port, None)
                if not sound_port:
                    return
                else:
                    vncserver = 'localhost'

            self.sound = soundplay()
            self.sound.connect(self.instrument, self.vncserver, sound_port,
                               aplay=aplay, player=soundplayer)
            #todo: should we start this as a thread?  
            # sound = sound = Thread(target=launch_soundplay, args=(vncserver, 9798, instrument,))
            # soundThread.start()
        except Exception as error:
            log.error('Unable to start soundplay.  See log for details.')
            log.info(str(error))


    ##-------------------------------------------------------------------------
    ## Authenticate
    ##-------------------------------------------------------------------------
    def authenticate(self, authpass):

        #todo: shorten timeout for mistyped password

        log.info(f'Authenticating through firewall as:')
        log.info(f' {self.firewall_user}@{self.firewall_address}:{self.firewall_port}')

        try:
            with Telnet(self.firewall_address, int(self.firewall_port)) as tn:
                tn.read_until(b"User: ", timeout=5)
                tn.write(f'{self.firewall_user}\n'.encode('ascii'))
                tn.read_until(b"password: ", timeout=5)
                tn.write(f'{authpass}\n'.encode('ascii'))
                tn.read_until(b"Enter your choice: ", timeout=5)
                tn.write('1\n'.encode('ascii'))
                result = tn.read_all().decode('ascii')
                if re.search('User authorized for standard services', result):
                    log.info('User authorized for standard services')
                    return True
                else:
                    log.error(result)
                    return False
        except Exception as error:
            log.error('Unable to authenticate through firewall')
            log.info(str(error))
            return False


    ##-------------------------------------------------------------------------
    ## Close Authentication
    ##-------------------------------------------------------------------------
    def close_authentication(self, authpass):

        if not self.is_authenticated:
            return False

        log.info('Signing off of firewall authentication')
        try:
            with Telnet(self.firewall_address, int(self.firewall_port)) as tn:
                tn.read_until(b"User: ", timeout=5)
                tn.write(f'{self.firewall_user}\n'.encode('ascii'))
                tn.read_until(b"password: ", timeout=5)
                tn.write(f'{authpass}\n'.encode('ascii'))
                tn.read_until(b"Enter your choice: ", timeout=5)
                tn.write('2\n'.encode('ascii'))
                result = tn.read_all().decode('ascii')
                if re.search('User was signed off from all services', result):
                    log.info('User was signed off from all services')
                    return True
                else:
                    log.error(result)
                    return False
        except:
            log.error('Unable to close firewall authentication!')
            return False


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
        accounts['osiris'].append('osiriseng')
        accounts['lris'].append('lriseng')
        accounts['nires'].append('nireseng')
        accounts['deimos'].append('dmoseng')
        accounts['esi'].append('esieng')
        accounts['nirc2'].append('nirceng')
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
            log.debug(f'Trying SSH connect to {server} as {account}:')

            client = paramiko.SSHClient()
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.WarningPolicy())
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                server, 
                port     = 22, 
                timeout  = 6, 
                key_filename=self.ssh_pkey,
                username = account, 
                password = password)
            log.info('  Connected')
        except TimeoutError:
            log.error('  Timeout')
        except Exception as e:
            log.error('  Failed: ' + str(e))
        else:
            log.debug(f'Command: {cmd}')
            stdin, stdout, stderr = client.exec_command(cmd)
            output = stdout.read()
            output = output.decode().strip('\n')
            log.debug(f"Output: '{output}'")
        finally:
            client.close()
            return output


    ##-------------------------------------------------------------------------
    ## Validate ssh key on remote vnc server
    ##-------------------------------------------------------------------------
    def validate_ssh_key(self):
        log.info(f"Validating ssh key...")

        self.is_ssh_key_valid = False
        cmd = 'whoami'
        data = self.do_ssh_cmd(cmd, self.SSH_KEY_SERVER, self.SSH_KEY_ACCOUNT,
                               None)

        if data == self.SSH_KEY_ACCOUNT:
            self.is_ssh_key_valid = True

        if self.is_ssh_key_valid: log.info("  SSH key OK")
        else                    : log.info("  SSH key invalid")


    ##-------------------------------------------------------------------------
    ## Get engv account for instrument
    ##-------------------------------------------------------------------------
    def get_engv_account(self, instrument):
        log.info(f"Getting engv account for instrument {instrument} ...")

        cmd = f'setenv INSTRUMENT {instrument}; kvncinfo -engineering'
        data = self.do_ssh_cmd(cmd, self.SSH_KEY_SERVER, self.SSH_KEY_ACCOUNT,
                               None)

        engv = None
        if data and ' ' not in data:
            engv = data

        if engv: log.debug("engv account is: '{}'")
        else   : log.error("Could not get engv account info.")

        return engv


    ##-------------------------------------------------------------------------
    ## Determine VNC Server
    ##-------------------------------------------------------------------------
    def get_vnc_server(self, account, password, instrument):
        log.info(f"Determining VNC server for '{account}'...")
        vncserver = None
        for server in self.servers_to_try:
            server += ".keck.hawaii.edu"
            cmd = f'kvncinfo -server -I {instrument}'
            data = self.do_ssh_cmd(cmd, server, account, password) 
            if data and ' ' not in data:
                vncserver = data
                log.info(f"Got VNC server: '{vncserver}'")
                break

        # todo: Temporary hack for KCWI
        if vncserver == 'vm-kcwivnc':
            vncserver = 'kcwi'

        if vncserver:
            vncserver += '.keck.hawaii.edu'

        return vncserver


    ##-------------------------------------------------------------------------
    ## Determine VNC Sessions
    ##-------------------------------------------------------------------------
    def get_vnc_sessions(self, vncserver, instrument, account, password,
                         instr_account):
        log.info(f"Connecting to {account}@{vncserver} to get VNC sessions list")

        sessions = []
        cmd = f'setenv INSTRUMENT {instrument}; kvncstatus -a'
        data = self.do_ssh_cmd(cmd, vncserver, account, password)
        if data:
            allsessions = Table.read(data.split('\n'), format='ascii')
            sessions = allsessions[allsessions['User'] == instr_account]
            log.debug(f'  Got {len(sessions)} sessions')
            names = [x['Desktop'].split('-')[2] for x in sessions]
            sessions.add_column(Column(data=names, name=('name')))

            #add default row for 'status' session at display port 1
            if len(sessions) > 0:
                sessions.add_row([self.STATUS_PORT, 'FACSUM & XMET', '', 0,
                                  'status'])

        sessions.sort('Desktop')
        log.debug("\n" + str(sessions))
        return sessions


    ##-------------------------------------------------------------------------
    ## Close ssh threads
    ##-------------------------------------------------------------------------
    def close_ssh_thread(self, p):
        if p in self.ports_in_use.keys():
            desktop = self.ports_in_use[p][1]
            remote_connection = self.ports_in_use[p][0]
            log.info(f" Closing SSH tunnel for port {p:d}, {desktop:s} "
                     f"on {remote_connection:s}")
            thread = self.ports_in_use[p][2]
            thread.stop()


    def close_ssh_threads(self):
        if len(self.ports_in_use) > 0:
            for p in self.ports_in_use.keys():
                self.close_ssh_thread(p)
#         if self.ssh_threads:
#             for thread in self.ssh_threads:
#                 log.info(f'Closing SSH forwarding for {thread.local_bind_port}')
#                 thread.stop()


    ##-------------------------------------------------------------------------
    ## Calculate vnc windows size and position
    ##-------------------------------------------------------------------------
    def calc_window_geometry(self):

        log.debug(f"Calculating VNC window geometry...")

        #get screen dimensions
        #alternate command: xrandr |grep \* | awk '{print $1}'
        cmd = "xdpyinfo | grep dimensions | awk '{print $2}' | awk -Fx '{print $1, $2}'"
        p1 = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        out = p1.communicate()[0].decode('utf-8')
        screen_width, screen_height = [int(x) for x in out.split()]
        log.debug(f"Screen size: {screen_width}x{screen_height}")

        #get num rows and cols 
        #todo: assumming 2x2 always for now; make smarter
        num_win = len(self.sessions_requested)
        cols = 2
        rows = 2

        #window coord and size config overrides
        window_positions = self.config.get('window_positions', None)
        window_size = self.config.get('window_size', None)

        #get window width height
        if window_size:
            ww = window_size[0]
            wh = window_size[1]
        else:
            ww = round(screen_width / cols)
            wh = round(screen_height / rows)

        #get x/y coords (assume two rows)
        self.geometry = []
        for row in range(0, rows):
            for col in range(0, cols):
                x = round(col * screen_width/cols)
                y = round(row * screen_height/rows)
                if window_positions:
                    index = len(self.geometry) % len(window_positions)
                    x = window_positions[index][0]
                    y = window_positions[index][1]
                self.geometry.append([ww, wh, x, y])

        log.debug('geometry: ' + str(self.geometry))


    ##-------------------------------------------------------------------------
    ## Position vncviewers
    ##-------------------------------------------------------------------------
    def position_vnc_windows(self):

        log.info(f"Positioning VNC windows...")

        try:
            #get all x-window processes
            #NOTE: using wmctrl (does not work for Mac)
            #alternate option: xdotool?
            xlines = []
            cmd = ['wmctrl', '-l']
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
            while True:
                line = proc.stdout.readline()
                if not line: break
                line = line.rstrip().decode('utf-8')
                log.debug(f'wmctrl line: {line}')
                xlines.append(line)

            #reposition each vnc session window
            for i, session in enumerate(self.sessions_requested):
                log.debug(f'Search xlines for "{session}"')
                win_id = None
                for line in xlines:
                    if session not in line: continue
                    parts = line.split()
                    win_id = parts[0]

                if win_id:
                    index = i % len(self.geometry)
                    geom = self.geometry[index]
                    ww = geom[0]
                    wh = geom[1]
                    wx = geom[2]
                    wy = geom[3]
                    # cmd = ['wmctrl', '-i', '-r', win_id, '-e', f'0,{wx},{wy},{ww},{wh}']
                    cmd = ['wmctrl', '-i', '-r', win_id, '-e',
                           f'0,{wx},{wy},-1,-1']
                    log.debug(f"Positioning '{session}' with command: " + ' '.join(cmd))
                    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
                else:
                    log.info(f"Could not find window process for VNC session '{session}'")
        except Exception as error:
            log.error("Failed to reposition windows.  See log for details.")
            log.debug(str(error))


    ##-------------------------------------------------------------------------
    ## Prompt command line menu and wait for quit signal
    ##-------------------------------------------------------------------------
    def prompt_menu(self):

        menu = "\n"
        menu += "---------------------------------------------------\n"
        menu += "|                    MENU                         |\n"
        menu += "---------------------------------------------------\n"
        menu += "|  l               List sessions available        |\n"
        menu += "|  [session name]  Open VNC session by name       |\n"
        menu += "|  w               Position VNC windows           |\n"
        menu += "|  s               Soundplayer restart            |\n"
#         menu += "|  p               Play a local test sound        |\n"
        menu += "|  t               List local ports in use        |\n"
        menu += "|  c [port]        Close ssh tunnel on local port |\n"
        menu += "|  q               Quit (or Control-C)            |\n"
        menu += "---------------------------------------------------\n"
        menu += "> "

        quit = None
        while quit is None:
            cmd = input(menu).lower()
            cmatch = re.match('c (\d+)', cmd)
            if   cmd == 'q': quit = True
            elif cmd == 'w': self.position_vnc_windows()
            elif cmd == 'p': self.play_test_sound()
            elif cmd == 's': self.start_soundplay()
            elif cmd == 'l': self.print_sessions_found()
            elif cmd == 't': self.list_tunnels()
            elif cmatch is not None: self.close_ssh_thread(int(cmatch.group(1)))
            #elif cmd == 'v': self.validate_ssh_key()
            #elif cmd == 'x': self.kill_vnc_processes()
            elif cmd in self.sessions_found['name']:
                self.start_vnc_session(cmd)
            else:
                log.error(f'Unrecognized command: {cmd}')


    ##-------------------------------------------------------------------------
    ## Terminate all vnc processes
    ##-------------------------------------------------------------------------
    def kill_vnc_processes(self, msg=None):

        log.info('Terminating all VNC sessions.')
        try:
            #NOTE: poll() value of None means it still exists.
            while self.vnc_processes:
                proc = self.vnc_processes.pop()
                log.debug('terminating VNC process: ' + str(proc.args))
                if proc.poll() == None:
                    proc.terminate()

        except Exception as error:
            log.error("Failed to terminate VNC sessions.  See log for details.")
            log.debug(str(error))


    ##-------------------------------------------------------------------------
    ## Common app exit point
    ##-------------------------------------------------------------------------
    def exit_app(self, msg=None):

        #hack for preventing this function from being called twice
        #todo: need to figure out how to use atexit with threads properly
        if self.exit: return

        #todo: Fix app exit so certain clean ups don't cause errors (ie thread not started, etc
        if msg != None: log.info(msg)

        #terminate soundplayer
        if self.sound: 
            self.sound.terminate()

        # Close down ssh tunnels and firewall authentication
        if self.do_authenticate is True:
            self.close_ssh_threads()
            self.close_authentication(self.firewall_pass)

        #close vnc sessions
        self.kill_vnc_processes()

        self.exit = True
        log.info("EXITING APP\n")        
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
        if log:
            logfile = log.handlers[0].baseFilename
            print(f"* Attach log file at: {logfile}\n")
            log.debug(f"\n\n!!!!! PROGRAM ERROR:\n{msg}\n")
        else:
            print(msg)

        self.exit_app()


##-------------------------------------------------------------------------
## Create logger
##-------------------------------------------------------------------------
def create_logger():

    try:
        ## Create logger object
        log = logging.getLogger('KRO')
        log.setLevel(logging.DEBUG)

        #create log file and log dir if not exist
        ymd = datetime.utcnow().date().strftime('%Y%m%d')
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

    print("\nStarting Keck VNC Launcher...\n")

    #catch all exceptions so we can exit gracefully
    try:        
        create_logger()
        log = logging.getLogger('KRO')
        kvl = KeckVncLauncher()
        kvl.start()
    except Exception as error:
        kvl.handle_fatal_error(error)


