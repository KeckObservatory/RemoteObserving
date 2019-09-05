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


class KeckVncLauncher(object):

    def __init__(self):

        #init vars we need to shutdown app properly
        self.config = None
        self.sound = None
        self.firewall_pass = None
        self.ssh_threads = None
        self.ports_used = None
        self.do_authenticate = False
        self.is_authenticated = False
        self.instrument = None
        self.vncserver = None

        #session name consts
        self.session_names = [
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


    ##-------------------------------------------------------------------------
    ## Start point (main)
    ##-------------------------------------------------------------------------
    def start(self):


        ##-------------------------------------------------------------------------
        ## Create logger and log basic system info
        ##-------------------------------------------------------------------------
        self.create_logger()
        self.log.debug("\n***** PROGRAM STARTED *****\nCommand: "+' '.join(sys.argv))
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
        self.instrument, tel = self.determine_instrument(self.args.account)
        if not self.instrument: 
            self.exit_app(f'Invalid instrument account name: "{self.args.account}"')


        ##-------------------------------------------------------------------------
        ## Determine VNC server
        ##-------------------------------------------------------------------------
        vnc_password = getpass(f"Password for user {self.args.account}: ")
        self.vncserver = self.determine_vnc_server(self.args.account, vnc_password)


        ##-------------------------------------------------------------------------
        ## Determine VNC Sessions
        ##-------------------------------------------------------------------------
        self.sessions_found = self.determine_vnc_sessions(self.args.account, vnc_password, self.vncserver)
        if len(self.sessions_found) == 0:
            self.exit_app('No VNC sessions found')
        self.log.debug("\n" + str(self.sessions_found))


        ##-------------------------------------------------------------------------
        ## Open SSH Tunnel for Appropriate Ports
        ##-------------------------------------------------------------------------
        self.ssh_threads = []
        ports_used = []
        if self.do_authenticate:
            for session in self.sessions_found:
                if session['name'] in self.sessions_requested:
                    display = int(session['Display'][1:])
                    port = int(f"59{display:02d}")
                    if 'local_ports' in self.config.keys(): 
                        localport = self.config['local_ports'].pop(0)
                    else: 
                        localport = port
                    ports_used.append(localport)
                    self.log.info(f"Opening SSH tunnel for {session['name']}")
                    self.log.info(f"  remote port = {port}, local port = {localport}")
                    server = sshtunnel.SSHTunnelForwarder(
                        self.vncserver,
                        ssh_username=self.args.account,
                        ssh_password=vnc_password,
                        remote_bind_address=('127.0.0.1', port),
                        local_bind_address=('0.0.0.0', localport),
                    )
                    self.ssh_threads.append(server)
                    try:
                        self.ssh_threads[-1].start()
                    except sshtunnel.HandlerSSHTunnelForwarderError as e:
                        self.log.error('Failed to open tunnel')
                        self.log.error(e)
            if self.args.status is True:
                if 'local_ports' in self.config.keys():
                    statusport = self.config['local_ports'].pop(0)
                else:
                    statusport = [p for p in range(5901,5910,1) if p not in ports_used][0]
                self.log.info(f"Opening SSH tunnel for k{tel}status")
                self.log.info(f"  remote port = {port}, local port = {statusport}")
                server = sshtunnel.SSHTunnelForwarder(
                    f"svncserver{tel}.keck.hawaii.edu",
                    ssh_username=self.args.account,
                    ssh_password=vnc_password,
                    remote_bind_address=('127.0.0.1', 5901),
                    local_bind_address=('0.0.0.0', statusport),
                )
                self.ssh_threads.append(server)
                try:
                    self.ssh_threads[-1].start()
                except sshtunnel.HandlerSSHTunnelForwarderError as e:
                    self.log.error('Failed to open tunnel')
                    self.log.error(e)
        elif self.args.status is True:
            if 'local_ports' in self.config.keys():
                statusport = self.config['local_ports'].pop(0)
            else:
                statusport = [p for p in range(5901,5910,1) if p not in ports_used][0]


        ##-------------------------------------------------------------------------
        ## Open vncviewers
        ##-------------------------------------------------------------------------
        #todo: should we not loop thru sessions_requested instead?
        vnc_threads = []
        if self.do_authenticate is True:
            self.vncserver = 'localhost'
            statusvncserver = 'localhost'
        else:
            statusvncserver = f"svncserver{tel}.keck.hawaii.edu"

        if self.config['vncviewer'] in [None, 'None', 'none']:
            self.log.info(f"\nNo VNC viewer application specified")
            self.log.info(f"Open your VNC viewer manually\n")
        else:
            for session in self.sessions_found:
                if session['name'] in self.sessions_requested:
                    self.log.info(f"Opening VNCviewer for {session['name']}")
                    display = int(session['Display'][1:])
                    if ports_used != []: port = ports_used.pop(0)
                    else               : port = int(f"59{display:02d}")
                    vnc_threads.append(Thread(target=self.launch_vncviewer, 
                                              args=(self.vncserver, port)))
                    vnc_threads[-1].start()
                    sleep(0.05)
            if self.args.status is True:
                self.log.info(f"Opening VNCviewer for k{tel}status on {statusport}")
                vnc_threads.append(Thread(target=self.launch_vncviewer, 
                                          args=(statusvncserver, statusport)))
                vnc_threads[-1].start()


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
    ## Create logger
    ##-------------------------------------------------------------------------
    def create_logger(self):

        try:
            ## Create logger object
            self.log = logging.getLogger('GetVNCs')
            self.log.setLevel(logging.DEBUG)

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
            self.log.addHandler(logFileHandler)

            #stream/console handler (info+ only)
            logConsoleHandler = logging.StreamHandler()
            logConsoleHandler.setLevel(logging.INFO)
            logFormat = logging.Formatter(' %(levelname)8s: %(message)s')
            logFormat.converter = time.gmtime
            logConsoleHandler.setFormatter(logFormat)
            
            self.log.addHandler(logConsoleHandler)

        except Exception as error:
            print (str(error))
            print (f"ERROR: Unable to create logger at {logFile}")
            print ("Make sure you have write access to this directory.\n")
            self.exit_app()


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
        for name in self.session_names:
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
                self.log.error(f'Specified config file "{filename}"" does not exist.')
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
            self.log.error(f'No config files found in list: {filenames}')
            self.exit_app()

        #load config file and make sure it has the info we need
        self.log.info(f'Using config file: {file}')
        with open(file) as FO:
            config = yaml.safe_load(FO)

        self.config = config


    ##-------------------------------------------------------------------------
    ## Check Configuration
    ##-------------------------------------------------------------------------
    def check_config(self):

        #checks servers_to try
        self.servers_to_try = self.config.get('servers_to_try', None)
        if not self.servers_to_try:
            self.log.error("Config parameter 'servers_to_try' undefined.\n")
            self.exit_app()

        #check for vncviewer
        #NOTE: Ok if not specified, we will tell them to open vncviewer manually
        #todo: check if valid cmd path?
        self.vncviewerCmd = self.config.get('vncviewer', None)
        if not self.vncviewerCmd:
            self.log.warning("Config parameter 'vncviewer' undefined.")
            self.log.warning("You will need to open your vnc viewer manually.\n")

        #checks local ports config
        if 'local_ports' in self.config.keys():
            if type(self.config['local_ports']) is not list:
                self.log.error("Config parameter 'local_ports' must be a list of integers.")
                self.log.error("Or, remove 'local_ports' from config to use default ports.\n")
                self.exit_app()
            else:
                nlp = len(self.config['local_ports'])
                if nlp < 9:
                    self.log.warning(f"Only {nlp} local ports specified.")
                    self.log.warning(f"Program may crash if trying to open >{nlp} sessions.\n")

        #check firewall config
        self.do_authenticate = False
        self.firewall_address = self.config.get('firewall_address', None)
        self.firewall_user    = self.config.get('firewall_user',    None)
        self.firewall_port    = self.config.get('firewall_port',    None)
        if self.firewall_address or self.firewall_user or self.firewall_port:
            if self.firewall_address and self.firewall_user and self.firewall_port:
                self.do_authenticate = True
                import sshtunnel
            else:
                self.log.warning("Partial firewall configuration detected in config file:")
                if not self.firewall_address: self.log.warning("firewall_address not set")
                if not self.firewall_user:    self.log.warning("firewall_user not set")
                if not self.firewall_port:    self.log.warning("firewall_port not set")


    ##-------------------------------------------------------------------------
    ## Log basic system info
    ##-------------------------------------------------------------------------
    def log_system_info(self):
        #todo: gethostbyname stopped working after I updated mac.  need better method
        try:
            self.log.debug(f'System Info: {os.uname()}')
            hostname = socket.gethostname()
            self.log.debug(f'System hostname: {hostname}')
            # ip = socket.gethostbyname(hostname)
            # self.log.debug(f'System IP Address: {ip}')
        except Exception as error:
            self.log.error("Unable to log system info.")
            self.log.debug(str(error))


    ##-------------------------------------------------------------------------
    ## Get sessions to open
    ##-------------------------------------------------------------------------
    def get_sessions_requested(self, args):

        #get sessions to open
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
        vncviewercmd = self.config.get('vncviewer', 'vncviewer')
        vncprefix    = self.config.get('vncprefix', '')
        vncargs      = self.config.get('vncargs', None)
        cmd = [vncviewercmd]
        if vncargs: 
            cmd.append(vncargs)
        cmd.append(f'{vncprefix}{vncserver}:{port:4d}')
        self.log.info(f"  Launching VNC viewer for {cmd[-1]}")
        print ('test: launch: ', cmd)
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        # while True:
        #     line = proc.stdout.readline()
        #     print ('procline: ', line)
        #     line = line.rstrip().decode('utf-8')

        #todo: read output and do window move when we get message the window has been opened
        print ('test: launch complete: ', type(proc))


    ##-------------------------------------------------------------------------
    ## Start soundplay
    ##-------------------------------------------------------------------------
    def start_soundplay(self):

        #todo: check for existing first and shutdown
        if self.sound:
            self.sound.terminate()

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

        self.log.info(f'Authenticating through firewall as:')
        self.log.info(f'  {self.firewall_user}@{self.firewall_address}:{self.firewall_port}')

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
                    self.log.info('User authorized for standard services')
                    return True
                else:
                    self.log.error(result)
                    return False
        except Exception as error:
            self.log.error('Unable to authenticate through firewall')
            self.log.info(str(error))
            return False


    ##-------------------------------------------------------------------------
    ## Close Authentication
    ##-------------------------------------------------------------------------
    def close_authentication(self, authpass):

        if not self.is_authenticated:
            return False

        self.log.info('Signing off of firewall authentication')
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
                    self.log.info('User was signed off from all services')
                    return True
                else:
                    self.log.error(result)
                    return False
        except:
            self.log.error('Unable to close firewall authentication!')
            return False


    ##-------------------------------------------------------------------------
    ## Determine Instrument
    ##-------------------------------------------------------------------------
    def determine_instrument(self, accountname):
        accounts = {'mosfire':  [f'mosfire{i}' for i in range(1,10)],
                    'hires':    [f'hires{i}'   for i in range(1,10)],
                    'osiris':   [f'osiris{i}'  for i in range(1,10)],
                    'lris':     [f'lris{i}'    for i in range(1,10)],
                    'nires':    [f'nires{i}'   for i in range(1,10)],
                    'deimos':   [f'deimos{i}'  for i in range(1,10)],
                    'esi':      [f'esi{i}'     for i in range(1,10)],
                    'nirc2':    [f'nirc{i}'    for i in range(1,10)],
                    'nirspec':  [f'nirspec{i}' for i in range(1,10)],
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
        accounts['nirspec'].append('nirspeceng')
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
            if accountname.lower() in accounts[instrument]:
                return instrument, telescope[instrument]

        return None, None


    ##-------------------------------------------------------------------------
    ## Determine VNC Server
    ##-------------------------------------------------------------------------
    def determine_vnc_server(self, accountname, password):
        self.log.info(f"Determining VNC server for {accountname}")
        vncserver = None
        for s in self.servers_to_try:
            try:
                self.log.info(f'Trying {s}:')
                client = paramiko.SSHClient()
                client.load_system_host_keys()
                client.set_missing_host_key_policy(paramiko.WarningPolicy())
                client.connect(f"{s}.keck.hawaii.edu", port=22, timeout=6,
                               username=accountname, password=password)
                self.log.info('  Connected')
            except TimeoutError:
                self.log.info('  Timeout')
            except:
                self.log.info('  Failed')
            else:
                stdin, stdout, stderr = client.exec_command('kvncinfo -server')
                rawoutput = stdout.read()
                vncserver = rawoutput.decode().strip('\n')
                self.log.debug(f"  kvncinfo -server returned: '{vncserver}'")
            finally:
                client.close()
                if vncserver is not None and vncserver != '':
                    self.log.info(f"Got VNC server: '{vncserver}'")
                    break

        #exit if none
        if vncserver == None:
            self.exit_app("Could not determine VNC server.")

        # todo: Temporary hack for KCWI
        if vncserver == 'vm-kcwivnc':
            vncserver = 'kcwi'

        return f"{vncserver}.keck.hawaii.edu"


    ##-------------------------------------------------------------------------
    ## Determine VNC Sessions
    ##-------------------------------------------------------------------------
    def determine_vnc_sessions(self, accountname, password, vncserver):
        self.log.info(f"Connecting to {vncserver} to get VNC sessions list")
        try:
            client = paramiko.SSHClient()
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.WarningPolicy())
            client.connect(vncserver, port=22, timeout=6, 
                           username=accountname, password=password)
            self.log.info('  Connected')
        except TimeoutError:
            self.log.info('  Timeout')
        except:
            self.log.error('  Failed')
            raise
        else:
            stdin, stdout, stderr = client.exec_command('kvncstatus')
            rawoutput = stdout.read()
            output = rawoutput.decode().strip('\n')
            allsessions = Table.read(output.split('\n'), format='ascii')
            self.log.debug(f'  Got {len(allsessions)} sessions for all users')
            if len(allsessions) == 0:
                self.log.warning(f'Found 0 sessions on {vncserver}')
                client.close()
                sessions = []
            else:
                sessions = allsessions[allsessions['User'] == accountname]
                self.log.info(f'  Got {len(sessions)} sessions')
                names = [x['Desktop'].split('-')[2] for x in sessions]
                sessions.add_column(Column(data=names, name=('name')))
        finally:
            client.close()
            return sessions


    ##-------------------------------------------------------------------------
    ## Close ssh threads
    ##-------------------------------------------------------------------------
    def close_ssh_threads(self):
        if self.ssh_threads:
            for thread in self.ssh_threads:
                self.log.info(f'Closing SSH forwarding for {thread.local_bind_port}')
                thread.stop()


    ##-------------------------------------------------------------------------
    ## Position vncviewers
    ##-------------------------------------------------------------------------
    def position_vnc_windows(self):

        self.log.info(f"Positioning VNC windows...")

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
            self.log.debug(f'wmctrl line: {line}')
            xlines.append(line)

        #reposition each vnc session window
        for i, session in enumerate(self.sessions_requested):
            self.log.debug(f'Search xlines for "{session}"')
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
                self.log.debug(f"Positioning '{session}' with command: " + ' '.join(cmd))
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
            else:
                self.log.info(f"Could not find window process for VNC session '{session}'")


    ##-------------------------------------------------------------------------
    ## Prompt command line menu and wait for quit signal
    ##-------------------------------------------------------------------------
    def prompt_menu(self):

        #todo: add options to open/reopen controls
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
            elif cmd in self.session_names:
                self.start_vnc_session(cmd)
            else:
                self.log.error(f'Unrecognized command: {cmd}')


    ##-------------------------------------------------------------------------
    ## Common app exit point
    ##-------------------------------------------------------------------------
    def exit_app(self, msg=None):

        if msg != None: self.log.info(msg)

        #terminate soundplayer
        if self.sound: 
            self.sound.terminate()

        # Close down ssh tunnels and firewall authentication
        if self.do_authenticate is True:
            self.close_ssh_threads()
            self.close_authentication(self.firewall_pass)

        self.log.info("EXITING APP\n")
        
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
        if self.log:
            logfile = self.log.handlers[0].baseFilename
            print (f"* Attach log file at: {logfile}\n")
            self.log.debug(f"\n\n!!!!! PROGRAM ERROR:\n{msg}\n")
        else:
            print (msg)

        self.exit_app()


##-------------------------------------------------------------------------
## Start from command line
##-------------------------------------------------------------------------
if __name__ == '__main__':

    print ("\nStarting Keck VNC Launcher:\n")

    #catch all exceptions so we can exit gracefully
    try:        
        kvl = KeckVncLauncher()
        kvl.start()
    except Exception as error:
        kvl.handle_fatal_error(error)


