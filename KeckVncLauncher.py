#!/usr/env/python

## Import General Tools
import os
import sys
import re
import socket
import argparse
import logging
import yaml
from getpass import getpass
import paramiko
from time import sleep
from threading import Thread
from telnetlib import Telnet
from subprocess import Popen, call
from astropy.table import Table, Column
from soundplay import soundplay
import atexit
from datetime import datetime
import platform
import traceback


class KeckVncLauncher(object):

    def __init__(self):

        #init things we need to shutdown app properly
        self.config = None
        self.sound = None
        self.firewall_pass = None
        self.ssh_threads = None
        self.ports_used = None
        self.is_authenticated = False


    ##-------------------------------------------------------------------------
    ## Start point
    ##-------------------------------------------------------------------------
    def start(self):


        ##-------------------------------------------------------------------------
        ## Create logger and log basic system info
        ##-------------------------------------------------------------------------
        self.create_logger()
        self.log.debug("\n***** PROGRAM STARTED *****\nCommand: ", ' '.join(sys.argv))
        self.log_system_info()


        ##-------------------------------------------------------------------------
        ## Parse command line args and get config
        ##-------------------------------------------------------------------------
        self.args = self.get_args()
        self.config = self.get_config()


        ##-------------------------------------------------------------------------
        ## Authenticate Through Firewall (or Disconnect)
        ##-------------------------------------------------------------------------
        if 'firewall_address' in self.config.keys() and\
           'firewall_user'    in self.config.keys() and\
           'firewall_port'    in self.config.keys():
            self.config['authenticate'] = True
            import sshtunnel
        else:
            self.config['authenticate'] = False

        self.is_authenticated = False
        if self.config['authenticate'] is True:
            self.firewall_pass = getpass(f"Password for firewall authentication: ")
            self.is_authenticated = self.authenticate(self.firewall_pass)
            if not self.is_authenticated:
                self.exit_app('Authentication failure!')

        if self.args.authonly is True:
            if self.config['authenticate'] is True:
                self.prompt_quit_signal()
            self.exit_app('Authentication only')


        ##-------------------------------------------------------------------------
        ## Determine sessions to open
        ##-------------------------------------------------------------------------
        sessions_to_open = self.get_sessions_to_open(self.args)


        ##-------------------------------------------------------------------------
        ## Determine instrument
        ##-------------------------------------------------------------------------
        instrument, tel = self.determine_instrument(self.args.account)
        if not instrument: 
            self.exit_app(f'Account name "{self.args.account}" not a valid instrument account name.')


        ##-------------------------------------------------------------------------
        ## Determine VNC server
        ##-------------------------------------------------------------------------
        vnc_password = getpass(f"Password for user {self.args.account}: ")
        vncserver = self.determine_vnc_server(self.args.account, vnc_password)


        ##-------------------------------------------------------------------------
        ## Determine VNC Sessions
        ##-------------------------------------------------------------------------
        sessions = self.determine_vnc_sessions(self.args.account, vnc_password, vncserver)
        if len(sessions) == 0:
            if self.config['authenticate'] is True:
                self.close_authentication(self.firewall_pass)
            self.exit_app('No VNC sessions found')
        self.log.debug("\n" + str(sessions))


        ##-------------------------------------------------------------------------
        ## Open SSH Tunnel for Appropriate Ports
        ##-------------------------------------------------------------------------
        self.ssh_threads = []
        ports_used = []
        if self.config['authenticate'] is True:
            for session in sessions:
                if session['name'] in sessions_to_open:
                    display = int(session['Display'][1:])
                    port = int(f"59{display:02d}")
                    if 'local_ports' in self.config.keys(): localport = self.config['local_ports'].pop(0)
                    else                                  : localport = port
                    ports_used.append(localport)
                    self.log.info(f"Opening SSH tunnel for {session['name']}")
                    self.log.info(f"  remote port = {port}, local port = {localport}")
                    server = sshtunnel.SSHTunnelForwarder(
                        vncserver,
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
        vnc_threads = []
        if self.config['authenticate'] is True:
            vncserver = 'localhost'
            statusvncserver = 'localhost'
        else:
            statusvncserver = f"svncserver{tel}.keck.hawaii.edu"
        if self.config['vncviewer'] in [None, 'None', 'none']:
            self.log.info(f"No VNC viewer application specified")
            self.log.info(f"Open your VNC viewer manually")
        else:
            for session in sessions:
                if session['name'] in sessions_to_open:
                    self.log.info(f"Opening VNCviewer for {session['name']}")
                    display = int(session['Display'][1:])
                    if ports_used != []: port = ports_used.pop(0)
                    else               : port = int(f"59{display:02d}")
                    vnc_threads.append(Thread(target=self.launch_vncviewer, args=(vncserver, port)))
                    vnc_threads[-1].start()
                    sleep(0.05)
            if self.args.status is True:
                self.log.info(f"Opening VNCviewer for k{tel}status on {statusport}")
                vnc_threads.append(Thread(target=self.launch_vncviewer, args=(statusvncserver, statusport)))
                vnc_threads[-1].start()


        ##-------------------------------------------------------------------------
        ## Open Soundplay
        ##-------------------------------------------------------------------------
        sound = None
        if self.args.nosound is False:
            aplay       = self.config['aplay']       if 'aplay'       in self.config.keys() else None
            soundplayer = self.config['soundplayer'] if 'soundplayer' in self.config.keys() else None
            sound = soundplay()
            sound.connect(instrument, vncserver, 9798, aplay=aplay, player=soundplayer)
            #todo: should we start this as a thread?
            # sound = sound = Thread(target=launch_soundplay, args=(vncserver, 9798, instrument,))
            # soundThread.start()


        ##-------------------------------------------------------------------------
        ## Wait for quit signal
        ##-------------------------------------------------------------------------
        atexit.register(self.exit_app, msg="Forced app exit")
        self.prompt_quit_signal()

       
        #all done
        self.exit_app(msg="Normal app exit")


    ##-------------------------------------------------------------------------
    ## Create logger
    ##-------------------------------------------------------------------------
    def create_logger(self):

        ## Create logger object
        self.log = logging.getLogger('GetVNCs')
        self.log.setLevel(logging.DEBUG)

        #create log file and log dir if not exist
        ymd = datetime.today().strftime('%Y%m%d')
        logFile = f'logs/keck-remote-log-{ymd}.txt'
        if not os.path.exists(os.path.dirname(logFile)):
            os.makedirs(os.path.dirname(logFile))

        #file handler (full debug logging)
        logFileHandler = logging.FileHandler(logFile)
        logFileHandler.setLevel(logging.DEBUG)
        logFormat = logging.Formatter('%(asctime)s - %(levelname)s: %(message)s')
        logFileHandler.setFormatter(logFormat)
        self.log.addHandler(logFileHandler)

        #stream/console handler (info+ only)
        logConsoleHandler = logging.StreamHandler()
        logConsoleHandler.setLevel(logging.INFO)
        logFormat = logging.Formatter(' %(levelname)8s: %(message)s')
        logConsoleHandler.setFormatter(logFormat)
        self.log.addHandler(logConsoleHandler)


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
        parser.add_argument("--control0", dest="control0",
            default=False, action="store_true",
            help="Open control0?")
        parser.add_argument("--control1", dest="control1",
            default=False, action="store_true",
            help="Open control1?")
        parser.add_argument("--control2", dest="control2",
            default=False, action="store_true",
            help="Open control2?")
        parser.add_argument("--telstatus", dest="telstatus",
            default=False, action="store_true",
            help="Open telstatus?")
        parser.add_argument("--analysis0", dest="analysis0",
            default=False, action="store_true",
            help="Open analysis0?")
        parser.add_argument("--analysis1", dest="analysis1",
            default=False, action="store_true",
            help="Open analysis1?")
        parser.add_argument("--analysis2", dest="analysis2",
            default=False, action="store_true",
            help="Open analysis2?")
        parser.add_argument("--telanalysis", "--telanalys", dest="telanalys",
            default=False, action="store_true",
            help="Open telanalys?")
        parser.add_argument("--status", dest="status",
            default=False, action="store_true",
            help="Open status for telescope?")
        parser.add_argument("--nosound", dest="nosound",
            default=False, action="store_true",
            help="Skip start of soundplay application?")

        ## add arguments
        parser.add_argument("account", type=str,
            help="The user account.")

        ## add options
        parser.add_argument("-c", "--config", dest="config", type=str,
            help="Path to local configuration file.")

        #parse
        args = parser.parse_args()
        return args


    ##-------------------------------------------------------------------------
    ## Get Configuration
    ##-------------------------------------------------------------------------
    def get_config(self):

        #define files to try loading in order of pref
        filenames=['local_config.yaml', 'keck_vnc_config.yaml']

        #if config file specified, put that at beginning of list
        filename = self.args.config
        if filename is not None:
            if not os.path.exists(filename):
                self.log.error(f'Specified config file "{filename}"" does not exist.')
                app_exit()
            else:
                filenames.insert(0, filename)

        #find first file that exists
        file = None
        for f in filenames:
            if os.path.exists(f):
                file = f
                break
        if not file:
            self.log.error(f'No config files found.')
            app_exit()

        #load config file and make sure it has the info we need
        self.log.info(f'Using config file: {file}')
        with open(file) as FO:
            config = yaml.safe_load(FO)

        #checks that fail
        assert 'servers_to_try' in config.keys()
        assert 'vncviewer' in config.keys()

        #checks that warn
        if 'local_ports' in config.keys():
            assert type(config['local_ports']) is list
            nlp = len(config['local_ports'])
            if nlp < 9:
                self.log.warning(f"Only {nlp} local ports specified.")
                self.log.warning(f"Program may crash if trying to open >{nlp} sessions")

        return config


    ##-------------------------------------------------------------------------
    ## Log basic system info
    ##-------------------------------------------------------------------------
    def log_system_info(self):
        self.log.debug(f'System Info: {os.uname()}')
        hostname = socket.gethostname()
        self.log.debug(f'System hostname: {hostname}')
        self.log.debug(f'System IP Address: {socket.gethostbyname(hostname)}')


    ##-------------------------------------------------------------------------
    ## Get sessions to open
    ##-------------------------------------------------------------------------
    def get_sessions_to_open(self, args):

        #get sessions to open
        sessions_to_open = []
        if args.control0  is True: sessions_to_open.append('control0')
        if args.control1  is True: sessions_to_open.append('control1')
        if args.control2  is True: sessions_to_open.append('control2')
        if args.telstatus is True: sessions_to_open.append('telstatus')
        if args.analysis0 is True: sessions_to_open.append('analysis0')
        if args.analysis1 is True: sessions_to_open.append('analysis1')
        if args.analysis2 is True: sessions_to_open.append('analysis2')
        if args.telanalys is True: sessions_to_open.append('telanalys')
        if args.status    is True: sessions_to_open.append('status')

        # create default sessions list if none provided
        if len(sessions_to_open) == 0:
            sessions_to_open.append('control0')
            sessions_to_open.append('control1')
            sessions_to_open.append('control2')
            sessions_to_open.append('telstatus')

        return sessions_to_open


    ##-------------------------------------------------------------------------
    ## Launch xterm
    ##-------------------------------------------------------------------------
    def launch_xterm(self, command, pw, title):
        cmd = ['xterm', '-hold', '-title', title, '-e', f'"{command}"']
        xterm = call(cmd)


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
        vncviewer = call(cmd)


    ##-------------------------------------------------------------------------
    ## Authenticate
    ##-------------------------------------------------------------------------
    def authenticate(self, authpass):

        assert 'firewall_user'    in self.config.keys()
        assert 'firewall_address' in self.config.keys()
        assert 'firewall_port'    in self.config.keys()
        firewall_user    = self.config.get('firewall_user')
        firewall_address = self.config.get('firewall_address')
        firewall_port    = self.config.get('firewall_port')
        self.log.info(f'Authenticating through firewall as {firewall_user}@{firewall_address}:{firewall_port}')

        try:
            with Telnet(firewall_address, int(firewall_port)) as tn:
                tn.read_until(b"User: ", timeout=5)
                tn.write(f'{firewall_user}\n'.encode('ascii'))
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

        assert 'firewall_user'    in self.config.keys()
        assert 'firewall_address' in self.config.keys()
        assert 'firewall_port'    in self.config.keys()
        firewall_user    = self.config.get('firewall_user')
        firewall_address = self.config.get('firewall_address')
        firewall_port    = self.config.get('firewall_port')

        try:
            with Telnet(firewall_address, int(firewall_port)) as tn:
                tn.read_until(b"User: ", timeout=5)
                tn.write(f'{firewall_user}\n'.encode('ascii'))
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
        servers_to_try = self.config.get('servers_to_try')
        vncserver = None
        for s in servers_to_try:
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
    ## Prompt and wait for quit signal
    ##-------------------------------------------------------------------------
    def prompt_quit_signal(self, ):

        sleep(1)
        quit = input('Hit q to close down any SSH tunnels and firewall auth: ')
        foundq = re.match('^[qQ].*', quit)
        while foundq is None:
            sleep(1)
            quit = input('Hit q to close down any SSH tunnels and firewall auth: ')
            foundq = re.match('^[qQ].*', quit)


    ##-------------------------------------------------------------------------
    ## Common app exit point
    ##-------------------------------------------------------------------------
    def exit_app(self, msg=None):

        if msg != None: self.log.info(msg)

        if self.sound: 
            self.sound.terminate()

        # Close down ssh tunnels and firewall authentication
        if self.config['authenticate'] is True:
            self.close_ssh_threads()
            self.close_authentication(self.firewall_pass)

        self.log.info("EXITING APP\n")
        
        sys.exit(1)


    ##-------------------------------------------------------------------------
    ## Handle fatal error
    ##-------------------------------------------------------------------------
    @staticmethod
    def handle_fatal_error(error, kvl=None):

        #helpful user error message
        supportEmail = 'mainland_observing@keck.hawaii.edu'
        print ("\n****** PROGRAM ERROR ******\n")
        print ("Error message: " + str(error) + "\n")
        print ("If you need troubleshooting assistance:")
        print (f"* Email {supportEmail}")
        #todo: call number, website?

        #if we got as far as to have an instance of object, then log and call exit_app function
        if kvl:            
            msg = traceback.format_exc()
            if kvl.log:
                logfile = log.handlers[0].baseFilename
                print (f"* Attach log file at: {logfile}\n")
                kvl.log.debug(f"\n\n!!!!! PROGRAM ERROR:\n{msg}\n")
            else:
                print (msg)

            kvl.exit_app()


##-------------------------------------------------------------------------
## Start from command line
##-------------------------------------------------------------------------
if __name__ == '__main__':

    print ("\nStarting Keck VNC Launcher:\n")

    #catch all exceptions so we can exit gracefully
    kvl = None
    try:        
        kvl = KeckVncLauncher()
        kvl.start()
    except Exception as error:
        KeckVncLauncher.handle_fatal_error(error, kvl)


