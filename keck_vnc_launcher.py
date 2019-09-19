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


class KeckVncLauncher(object):

    def __init__(self):

        #init vars we need to shutdown app properly
        self.config = None
        self.sound = None
        self.firewall_pass = None
        self.ssh_threads = None
        self.ports_in_use = None
        self.do_authenticate = False
        self.is_authenticated = False
        self.instrument = None
        self.vncserver = None
        self.is_ssh_key_valid = False


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


        ##-------------------------------------------------------------------------
        ## Log basic system info
        ##-------------------------------------------------------------------------
        log.debug("\n***** PROGRAM STARTED *****\nCommand: "+' '.join(sys.argv))
        self.log_system_info()


        ##-------------------------------------------------------------------------
        ## Parse command line args and get config
        ##-------------------------------------------------------------------------
        self.get_args()
        self.get_config()
        self.check_config()


        ##-------------------------------------------------------------------------
        ## Authenticate Through Firewall (or Disconnect)
        ##-------------------------------------------------------------------------
        #todo: handle blank password error properly
        self.is_authenticated = False
        if self.do_authenticate:
            self.firewall_pass = getpass(f"Password for firewall authentication: ")
            self.is_authenticated = self.authenticate(self.firewall_pass)
            if not self.is_authenticated:
                self.exit_app('Authentication failure!')

        if self.args.authonly is True:
            self.exit_app('Authentication only')


        ##-------------------------------------------------------------------------
        ## Determine sessions to open
        ##-------------------------------------------------------------------------
        self.sessions_requested = self.get_sessions_requested(self.args)


        ##-------------------------------------------------------------------------
        ## Determine instrument
        ##-------------------------------------------------------------------------
        self.instrument, self.tel = self.determine_instrument(self.args.account)
        if not self.instrument: 
            self.exit_app(f'Invalid instrument account name: "{self.args.account}"')


        ##-------------------------------------------------------------------------
        ## Validate ssh key
        ##-------------------------------------------------------------------------
        if self.args.nosshkey is False:
            self.validate_ssh_key()
        if not self.is_ssh_key_valid:
            self.vnc_password = getpass(f"Password for user {self.args.account}: ")


        ##-------------------------------------------------------------------------
        ## Determine VNC server
        ##-------------------------------------------------------------------------
        if self.is_ssh_key_valid:
            self.vncserver = self.get_vnc_server(self.SSH_KEY_ACCOUNT, None, self.instrument)
        else:
            self.vncserver = self.get_vnc_server(self.args.account, self.vnc_password, self.instrument)
        if not self.vncserver:
            self.exit_app("Could not determine VNC server.")


        ##-------------------------------------------------------------------------
        ## Determine VNC Sessions
        ##-------------------------------------------------------------------------
        if self.is_ssh_key_valid:
            # self.engv_account = self.get_engv_account(self.instrument)
            self.sessions_found = self.get_vnc_sessions(self.vncserver, self.instrument, self.SSH_KEY_ACCOUNT, None, self.args.account)
        else:
            self.sessions_found = self.get_vnc_sessions(self.vncserver, self.instrument, self.args.account, self.vnc_password, self.args.account)
        if not self.sessions_found or len(self.sessions_found) == 0:
            self.exit_app('No VNC sessions found')


        ##-------------------------------------------------------------------------
        ## Open requested sessions
        ##-------------------------------------------------------------------------
        self.ssh_threads  = []
        self.ports_in_use = []
        self.vnc_threads  = []
        for session_name in self.sessions_requested:
            self.start_vnc_session(session_name)


        ##-------------------------------------------------------------------------
        ## Open Soundplay
        ## TODO: Does this work if we are authenticating or do we need an ssh tunnel?
        ##-------------------------------------------------------------------------
        sound = None
        if self.args.nosound is False:
            self.start_soundplay()


        ##-------------------------------------------------------------------------
        ## Wait for quit signal, then all done
        ##-------------------------------------------------------------------------
        atexit.register(self.exit_app, msg="Forced app exit")
        self.prompt_menu()
        self.exit_app(msg="Normal app exit")


    ##-------------------------------------------------------------------------
    ## Start VNC session
    ##-------------------------------------------------------------------------
    def start_vnc_session(self, session_name):

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
        if session_name == 'status': vncserver = f"svncserver{self.tel}.keck.hawaii.edu"

        #get remote port
        display   = int(session['Display'][1:])
        port      = int(f"59{display:02d}")

        #get next local port
        local_port = self.local_port
        self.local_port += 1

        ## If authenticating, open SSH tunnel for appropriate ports
        if self.do_authenticate:

            if self.is_ssh_key_valid:
                account = self.SSH_KEY_ACCOUNT
                password = None
            else:
                account=self.args.account
                password=self.vnc_password

            #get next local port
            local_port = self.local_port
            self.local_port += 1
            self.ports_in_use.append(local_port)

            log.info(f"Opening SSH tunnel for '{session_name}' on server '{vncserver} as {account}':")
            log.info(f"  remote port = {port}, local port = {local_port}")
            server = sshtunnel.SSHTunnelForwarder(
                vncserver,
                ssh_username=account,
                ssh_password=password,
                ssh_pkey=self.ssh_pkey,
                remote_bind_address=('127.0.0.1', port),
                local_bind_address=('0.0.0.0', local_port)
            )
            self.ssh_threads.append(server)
            try:
                self.ssh_threads[-1].start()
            except sshtunnel.HandlerSSHTunnelForwarderError as e:
                log.error('Failed to open ssh tunnel')
                log.debug(e)


        #If vncviewer is not defined, then prompt them to open manually and return now
        if self.config['vncviewer'] in [None, 'None', 'none']:
            log.info(f"\nNo VNC viewer application specified")
            log.info(f"Open your VNC viewer manually\n")
            return

        ## Open vncviewers
        if self.do_authenticate is True: 
            vncserver = 'localhost'
            port = local_port
        log.info(f"Opening VNCviewer for '{session_name}'")
        self.vnc_threads.append(Thread(target=self.launch_vncviewer, args=(vncserver, port)))
        self.vnc_threads[-1].start()
        sleep(0.05)


    ##-------------------------------------------------------------------------
    ## Get command line args
    ##-------------------------------------------------------------------------
    def get_args(self):

        ## create a parser object for understanding command-line arguments
        parser = argparse.ArgumentParser(description="Keck VNC Launcher")

        ## add flags
        parser.add_argument("--authonly", dest="authonly",
            default=False, action="store_true",
            help="Authenticate through firewall only?")
        parser.add_argument("--nosound", dest="nosound",
            default=False, action="store_true",
            help="Skip start of soundplay application?")
        parser.add_argument("--nosshkey", dest="nosshkey",
            default=False, action="store_true",
            help="Do not attempt to use ssk key connection method.")
        for name in self.SESSION_NAMES:
            parser.add_argument(f"--{name}", 
                dest=name, 
                default=False, 
                action="store_true", 
                help=f"Open {name}?")

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
                log.error(f'Specified config file "{filename}"" does not exist.')
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
        with open(file) as FO:
            config = yaml.safe_load(FO)

        cstr = "CONFIGS:\n"
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
                if not self.firewall_user:    log.warning("firewall_user not set")
                if not self.firewall_port:    log.warning("firewall_port not set")

        #check ssh_pkeys servers_to try
        self.ssh_pkey = self.config.get('ssh_pkey', None)
        if not self.ssh_pkey:
            log.warning("No ssh private key file specified in config file.\n")
        else:
            if not pathlib.Path(self.ssh_pkey).exists():
                log.warning(f"SSH private key path does not exist: {self.ssh_pkey}\n")


    ##-------------------------------------------------------------------------
    ## Log basic system info
    ##-------------------------------------------------------------------------
    def log_system_info(self):
        #todo: gethostbyname stopped working after I updated mac.  need better method
        try:
            log.debug(f'System Info: {os.uname()}')
            hostname = socket.gethostname()
            log.debug(f'System hostname: {hostname}')
            # ip = socket.gethostbyname(hostname)
            # log.debug(f'System IP Address: {ip}')
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
            sessions.append('control0')
            sessions.append('control1')
            sessions.append('control2')
            sessions.append('telstatus')

        return sessions


    ##-------------------------------------------------------------------------
    ## Print sessions found for instrument
    ##-------------------------------------------------------------------------
    def print_sessions_found(self):

        print (f"\nSessions found for account '{self.args.account}':")
        for session in self.sessions_found:
            print (f"\t{session['name']}")


    ##-------------------------------------------------------------------------
    ## Launch xterm
    ##-------------------------------------------------------------------------
    def launch_xterm(self, command, pw, title):
        cmd = ['xterm', '-hold', '-title', title, '-e', f'"{command}"']
        xterm = subprocess.call(cmd)


    ##-------------------------------------------------------------------------
    ## Open ssh tunnel
    ##-------------------------------------------------------------------------
    def open_ssh_tunnel(self, server, username, password, remote_port, local_port):
        server = sshtunnel.SSHTunnelForwarder(
            server,
            ssh_username=username,
            ssh_password=password,
            remote_bind_address=('127.0.0.1', remote_port),
            local_bind_address=('0.0.0.0', local_port),
        )
        server.start()


    ##-------------------------------------------------------------------------
    ## Launch vncviewer
    ##-------------------------------------------------------------------------
    def launch_vncviewer(self, vncserver, port):

        vncviewercmd   = self.config.get('vncviewer', 'vncviewer')
        vncprefix      = self.config.get('vncprefix', '')
        vncargs        = self.config.get('vncargs', None)

        cmd = [vncviewercmd]
        if vncargs: cmd.append(vncargs)
        cmd.append(f'{vncprefix}{vncserver}:{port:4d}')

        log.debug(f"VNC viewer command: {cmd}")
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)

        #todo: read output and do window move when we get message the window has been opened
        # while True:
        #     line = proc.stdout.readline()
        #     print ('procline: ', line)
        #     line = line.rstrip().decode('utf-8')



    ##-------------------------------------------------------------------------
    ## Start soundplay
    ##-------------------------------------------------------------------------
    def start_soundplay(self):

        #check for existing first and shutdown
        if self.sound:
            self.sound.terminate()

        #todo: Do we need ssh tunnel for this?
        sound_port  = 9798
        aplay       = self.config.get('aplay', None)
        soundplayer = self.config.get('soundplayer', None)
        self.sound = soundplay()
        self.sound.connect(self.instrument, self.vncserver, sound_port, aplay=aplay, player=soundplayer)
        #todo: should we start this as a thread?
        # sound = sound = Thread(target=launch_soundplay, args=(vncserver, 9798, instrument,))
        # soundThread.start()


    ##-------------------------------------------------------------------------
    ## Authenticate
    ##-------------------------------------------------------------------------
    def authenticate(self, authpass):

        #todo: shorten timeout for mistyped password

        log.info(f'Authenticating through firewall as:')
        log.info(f'  {self.firewall_user}@{self.firewall_address}:{self.firewall_port}')

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
            log.debug('  Connected')
        except TimeoutError:
            log.debug('  Timeout')
        except Exception as e:
            log.debug('  Failed: ' + str(e))
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
        data = self.do_ssh_cmd(cmd, self.SSH_KEY_SERVER, self.SSH_KEY_ACCOUNT, None)

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
        data = self.do_ssh_cmd(cmd, self.SSH_KEY_SERVER, self.SSH_KEY_ACCOUNT, None)

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
    def get_vnc_sessions(self, vncserver, instrument, account, password, instr_account):
        log.info(f"Connecting to '{vncserver}' as {account} to get VNC sessions list...")

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
                sessions.add_row([self.STATUS_PORT, 'status', '', 0, 'status'])

        log.debug("\n" + str(sessions))
        return sessions


    ##-------------------------------------------------------------------------
    ## Close ssh threads
    ##-------------------------------------------------------------------------
    def close_ssh_threads(self):
        if self.ssh_threads:
            for thread in self.ssh_threads:
                log.info(f'Closing SSH forwarding for {thread.local_bind_port}')
                thread.stop()


    ##-------------------------------------------------------------------------
    ## Position vncviewers
    ##-------------------------------------------------------------------------
    def position_vnc_windows(self):

        log.info(f"Positioning VNC windows...")

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

        #get window width height
        ww = round(screen_width / cols)
        wh = round(screen_height / rows)

        #get x/y coords (assume two rows)
        coords = []
        for row in range(0, rows):
            for col in range(0, cols):
                x = round(col * screen_width/cols)
                y = round(row * screen_height/rows)
                coords.append([x,y])

        #window coord and size config overrides
        window_size = self.config.get('window_size', None)
        if window_size:
            ww = window_size[0]
            wh = window_size[1]
        window_positions = self.config.get('window_positions', None)
        if window_positions:
            coords = window_positions

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
                index = i % len(coords)
                wx = coords[index][0]
                wy = coords[index][1]
                cmd = ['wmctrl', '-i', '-r', win_id, '-e', f'0,{wx},{wy},{ww},{wh}']
                log.debug(f"Positioning '{session}' with command: " + ' '.join(cmd))
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
            else:
                log.info(f"Could not find window process for VNC session '{session}'")


    ##-------------------------------------------------------------------------
    ## Prompt command line menu and wait for quit signal
    ##-------------------------------------------------------------------------
    def prompt_menu(self):

        menu = "\n"
        menu += "--------------------------------------------------\n"
        menu += "|                    MENU                        |\n"
        menu += "--------------------------------------------------\n"
        menu += "|  p               Position VNC windows          |\n"
        menu += "|  s               Soundplayer restart           |\n"
        menu += "|  l               List sessions available       |\n"
        menu += "|  [session name]  Open VNC session by name      |\n"
        menu += "|  q               Quit (or Control-C)           |\n"
        menu += "--------------------------------------------------\n"
        menu += "> "

        quit = None
        while quit is None:
            cmd = input(menu).lower()
            if   cmd == 'q':  quit = True
            elif cmd == 'p':  self.position_vnc_windows()
            elif cmd == 's':  self.start_soundplay()
            elif cmd == 'l':  self.print_sessions_found()
            elif cmd == 'v':  self.validate_ssh_key()
            elif cmd in self.SESSION_NAMES:
                self.start_vnc_session(cmd)
            else:
                log.error(f'Unrecognized command: {cmd}')


    ##-------------------------------------------------------------------------
    ## Common app exit point
    ##-------------------------------------------------------------------------
    def exit_app(self, msg=None):

        #todo: Fix app exit so certain clean ups don't cause errors (ie thread not started, etc
        if msg != None: log.info(msg)

        #terminate soundplayer
        if self.sound: 
            self.sound.terminate()

        # Close down ssh tunnels and firewall authentication
        if self.do_authenticate is True:
            self.close_ssh_threads()
            self.close_authentication(self.firewall_pass)

        log.info("EXITING APP\n")
        
        sys.exit(1)


    ##-------------------------------------------------------------------------
    ## Handle fatal error
    ##-------------------------------------------------------------------------
    def handle_fatal_error(self, error):

        #helpful user error message
        supportEmail = 'mainland_observing@keck.hawaii.edu'
        print ("\n****** PROGRAM ERROR ******\n")
        print ("Error message: " + str(error) + "\n")
        print ("If you need troubleshooting assistance:")
        print (f"* Email {supportEmail}\n")
        #todo: call number, website?

        #Log error if we have a log object (otherwise dump error to stdout) 
        #and call exit_app function
        msg = traceback.format_exc()
        if log:
            logfile = log.handlers[0].baseFilename
            print (f"* Attach log file at: {logfile}\n")
            log.debug(f"\n\n!!!!! PROGRAM ERROR:\n{msg}\n")
        else:
            print (msg)

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
        print (str(error))
        print (f"ERROR: Unable to create logger at {logFile}")
        print ("Make sure you have write access to this directory.\n")
        log.info("EXITING APP\n")        
        sys.exit(1)


##-------------------------------------------------------------------------
## Start from command line
##-------------------------------------------------------------------------
if __name__ == '__main__':

    print ("\nStarting Keck VNC Launcher...\n")

    #catch all exceptions so we can exit gracefully
    try:        
        create_logger()
        log = logging.getLogger('KRO')
        kvl = KeckVncLauncher()
        kvl.start()
    except Exception as error:
        kvl.handle_fatal_error(error)


