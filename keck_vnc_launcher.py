#! /usr/bin/env python3

## Import standard modules
import os
import argparse
import atexit
from datetime import datetime
from getpass import getpass
import logging
import math
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


__version__ = '1.1.2'
supportEmail = 'remote-observing@keck.hawaii.edu'

SESSION_NAMES = ('control0', 'control1', 'control2',
                 'analysis0', 'analysis1', 'analysis2',
                 'telanalys', 'telstatus', 'status')

class KROException(Exception):
    pass


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
        self.ssh_additional_kex = '+diffie-hellman-group1-sha1'
        self.exit = False
        self.geometry = list()
        self.get_ping_cmd()

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
        self.kvnc_account = 'kvnc'
        self.initial_server = 'svncserver2.keck.hawaii.edu'


    ##-------------------------------------------------------------------------
    ## Start point (main)
    ##-------------------------------------------------------------------------
    def start(self):

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
        ## Run tests
        ##---------------------------------------------------------------------
        if self.args.test is True:
            self.test_all()
        # Verify Tiger VNC Config
        if self.args.authonly is False:
            self.test_tigervnc()

        ##---------------------------------------------------------------------
        ## Authenticate Through Firewall (or Disconnect)
        ##---------------------------------------------------------------------

        if self.firewall_requested == True:
            self.firewall_opened = self.test_firewall()
        else:
            self.firewall_opened = False

        # Only prompt for the firewall password if it is required for opening
        # or closing the firewall hole.

        need_password = False
        close_requested = self.config.get('firewall_cleanup', False)
        if close_requested == True:
            need_password = True

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
            ## Validate ssh key
            ##---------------------------------------------------------------------
            self.validate_ssh_key()
            if self.ssh_key_valid == False:
                self.log.error(f"\n\n\tCould not validate SSH key.\n\t"\
                               f"Contact {supportEmail} "\
                               f"for other options to connect remotely.\n")
                self.exit_app()


            ##---------------------------------------------------------------------
            ## Determine VNC server
            ##---------------------------------------------------------------------
            self.vncserver = self.get_vnc_server(self.kvnc_account,
                                                 self.instrument)

            if self.vncserver is None:
                self.exit_app("Could not determine VNC server.")


            ##---------------------------------------------------------------------
            ## Determine VNC Sessions
            ##---------------------------------------------------------------------
            self.sessions_found = self.get_vnc_sessions(self.vncserver,
                                                        self.instrument,
                                                        self.kvnc_account,
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

            account = self.kvnc_account

            # determine if there is already a tunnel for this session
            local_port = None
            for p in self.ports_in_use.keys():
                if session_name == self.ports_in_use[p][1]:
                    local_port = p
                    vncserver = 'localhost'
                    self.log.info(f"Found existing SSH tunnel on port {port}")
                    break

            #open ssh tunnel
            if local_port is None:
                try:
                    local_port = self.open_ssh_tunnel(vncserver, account,
                                                      self.ssh_pkey,
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
        args = (vncserver, local_port, geometry)
        vnc_thread = Thread(target=self.launch_vncviewer, args=args)
        vnc_thread.start()
        self.vnc_threads.append(vnc_thread)
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
            if not Path(self.ssh_pkey).exists():
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
    ## Open ssh tunnel
    ##-------------------------------------------------------------------------
    def open_ssh_tunnel(self, server, username, ssh_pkey, remote_port,
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
        command = ['ssh', server, '-l', username, '-L', forwarding, '-N', '-T']
        command.append('-oStrictHostKeyChecking=no')
        command.append('-oCompression=yes')

        if self.ssh_additional_kex is not None:
            command.append('-oKexAlgorithms=' + self.ssh_additional_kex)

        if ssh_pkey is not None:
            command.append('-i')
            command.append(ssh_pkey)

        self.log.debug('ssh command: ' + ' '.join (command))
        null = subprocess.DEVNULL
        proc = subprocess.Popen(command, stdin=null, stdout=null, stderr=null)


        # Having started the process let's make sure it's actually running.
        # First try polling,  then confirm the requested local port is in use.
        # It's a fatal error if either check fails.

        if proc.poll() is not None:
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

        in_use = [address_and_port, session_name, proc]
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
        if self.args.viewonly == True:
            cmd.append('-ViewOnly')
        #todo: make this config on/off so it doesn't break things
        if geometry is not None and geometry != '':
            cmd.append(f'-geometry={geometry}')
        cmd.append(f'{vncprefix}{vncserver}:{port:4d}')

        self.log.debug(f"VNC viewer command: {cmd}")
        null = subprocess.DEVNULL
        proc = subprocess.Popen(cmd, stdin=null, stdout=null, stderr=null)

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
            #todo: should we start this as a thread?
            # sound = sound = Thread(target=launch_soundplay, args=(vncserver, 9798, instrument,))
            # soundThread.start()
        except:
            self.log.error('Unable to start soundplay.  See log for details.')
            trace = traceback.format_exc()
            self.log.debug(trace)


    def play_test_sound(self):
        if self.config.get('nosound', False) is True:
            self.log.warning('Sounds are not enabled on this install.  See config file.')
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
        self.log.debug('Calling: ' + ' '.join (command))
        test_sound_STDOUT = subprocess.check_output(command)
        for line in test_sound_STDOUT.decode().split('\n'):
            self.log.debug(f'  {line}')
        self.log.info('  You should have heard a sound through your local system')


    ##-------------------------------------------------------------------------
    ## Open the firewall hole for ssh traffic
    ##-------------------------------------------------------------------------
    def open_firewall(self, authpass):

        #todo: shorten timeout for mistyped password

        self.log.info(f'Authenticating through firewall as:')
        self.log.info(f' {self.firewall_user}@{self.firewall_address}:{self.firewall_port}')

        tn = Telnet(self.firewall_address, int(self.firewall_port))

        # Find Username Prompt
        user_prompt = tn.read_until(b"User: ", timeout=5).decode('ascii')
        for line in user_prompt.split('\n'):
            line = line.strip().strip('\n')
            self.log.debug(f"Firewall says: {line}")
        if user_prompt[-6:] != 'User: ':
            self.log.error('Got unexpected response from firewall:')
            self.log.error(user_prompt)
            raise KROException('Got unexpected response from firewall')
        tn.write(f'{self.firewall_user}\n'.encode('ascii'))

        # Find Username Prompt
        password_prompt = tn.read_until(b"password: ", timeout=5).decode('ascii')
        for line in password_prompt.split('\n'):
            line = line.strip().strip('\n')
            self.log.debug(f"Firewall says: {line}")
        if password_prompt[-10:] != 'password: ':
            self.log.error('Got unexpected response from firewall:')
            self.log.error(password_prompt)
            raise KROException('Got unexpected response from firewall')
        tn.write(f'{authpass}\n'.encode('ascii'))

        # Is Password Accepted?
        password_response = tn.read_until(b"Enter your choice: ", timeout=5).decode('ascii')
        for line in password_response.split('\n'):
            line = line.strip().strip('\n')
            self.log.debug(f"Firewall says: {line}")
        if re.search('Access denied - wrong user name or password', password_response):
            self.log.error('Incorrect password entered.')
            return False

        # If Password is Correct, continue with authentication process
        if password_response[-19:] != 'Enter your choice: ':
            self.log.error('Got unexpected response from firewall:')
            self.log.error(password_response)
            raise KROException('Got unexpected response from firewall')
        tn.write('1\n'.encode('ascii'))

        result = tn.read_all().decode('ascii')
        for line in result.split('\n'):
            line = line.strip().strip('\n')
            self.log.debug(f"Firewall says: {line}")
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

        self.log.info('Closing firewall hole')
        tn = Telnet(self.firewall_address, int(self.firewall_port))
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
    ## Check to see whether the firewall hole is already open.
    ##-------------------------------------------------------------------------
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
        # Ping once, wait up to five seconds for a response.
        if os == 'linux':
            self.ping_cmd.extend(['-c', '1', '-w', '5'])
        elif os == 'darwin':
            self.ping_cmd.extend(['-c', '1', '-W', '5000'])
        else:
            # Don't understand how ping works on this platform.
            self.ping_cmd = None


    def ping(self, address):
        '''Wrap logic around the ping command.
        '''
        if self.ping_cmd is None:
            return False
        # Run ping
        output = subprocess.run(self.ping_cmd + [address],
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


    def test_firewall(self):
        ''' Return True if the sshuser firewall hole is open; otherwise
            return False. Also return False if the test cannot be performed.
        '''

        try:
            netcat = subprocess.check_output(['which', 'ncat'])
        except subprocess.CalledProcessError:
            netcat = None

        # The netcat test is more rigorous, in that it attempts to contact
        # an ssh daemon that should be available to us after opening the
        # firewall hole. The ping check is a reasonable fallback and was
        # the traditional way the old mainland observing script would confirm
        # the firewall status.

        if netcat is not None:
            netcat = netcat.decode()
            netcat = netcat.strip()
            command = [netcat, 'sshserver1.keck.hawaii.edu', '22', '-w', '2']

            self.log.debug('firewall test: ' + ' '.join (command))
            null = subprocess.DEVNULL
            proc = subprocess.Popen(command, stdin=null, stdout=null, stderr=null)
            return_code = proc.wait()
            if return_code == 0:
                self.log.debug('firewall is open')
                return True
            else:
                self.log.debug('firewall is closed')
                return False

        elif self.ping_cmd is not None:
            if self.ping('128.171.95.100') is True:
                self.log.debug('firewall is open')
                return True
            else:
                self.log.debug('firewall is closed')
                return False

        else:
            # No way to check the firewall status. Assume it is closed,
            # authentication will be required.
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
    ## Utility function for opening ssh client, executing command and closing
    ##-------------------------------------------------------------------------
    def do_ssh_cmd(self, cmd, server, account, timeout=10):
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
        self.log.debug('ssh command: ' + ' '.join (command))

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
        if self.ssh_key_valid == True:
            return

        self.log.info(f"Validating ssh key...")

        self.ssh_key_valid = False
        cmd = 'whoami'
        server = self.initial_server
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
    ## Get engv account for instrument
    ##-------------------------------------------------------------------------
    def get_engv_account(self, instrument):
        self.log.info(f"Getting engv account for instrument {instrument} ...")

        cmd = f'setenv INSTRUMENT {instrument}; kvncinfo -engineering'
        server = self.initial_server
        account = self.kvnc_account
        try:
            data = self.do_ssh_cmd(cmd, server, account)
        except Exception as e:
            self.log.error('  Failed: ' + str(e))
            trace = traceback.format_exc()
            self.log.debug(trace)
            data = None

        engv = None
        if data is not None and ' ' not in data:
            engv = data

        if engv is not None:
            self.log.debug("engv account is: '{}'")
        else:
            self.log.error("Could not get engv account info.")

        return engv


    ##-------------------------------------------------------------------------
    ## Determine VNC Server
    ##-------------------------------------------------------------------------
    def get_vnc_server(self, account, instrument):
        self.log.info(f"Determining VNC server for '{account}'...")
        vncserver = None
        for server in self.servers_to_try:
            server += ".keck.hawaii.edu"
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

        # todo: Temporary hack for KCWI
        if vncserver == 'vm-kcwivnc':
            vncserver = 'kcwi'

        if vncserver is not None and 'keck.hawaii.edu' not in vncserver:
            vncserver += '.keck.hawaii.edu'

        return vncserver


    ##-------------------------------------------------------------------------
    ## Determine VNC Sessions
    ##-------------------------------------------------------------------------
    def get_vnc_sessions(self, vncserver, instrument, account, instr_account):
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
        self.geometry = list()
        cmd = "xdpyinfo | grep dimensions | awk '{print $2}' | awk -Fx '{print $1, $2}'"
        p1 = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        out = p1.communicate()[0].decode('utf-8')
        if not out:
            self.log.debug('Could not calc window geometry')
            return
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

        line_length = 50
        lines = [f"-"*(line_length),
                 f"          Keck Remote Observing (v{__version__})",
                 f"                        MENU",
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
            boxed.append ('|' + line.ljust(line_length) + '|')

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
                try:
                    self.position_vnc_windows()
                except:
                    self.log.error("Failed to reposition windows.  See log for details.")
                    trace = traceback.format_exc()
                    self.log.debug(trace)
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
    ## Check for latest version number on GitHub
    ##-------------------------------------------------------------------------
    def check_version(self):
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

    ##-------------------------------------------------------------------------
    ## Upload log file to Keck
    ##-------------------------------------------------------------------------
    def upload_log(self):

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

        self.log.debug('scp command: ' + ' '.join (command))

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

        #helpful user error message
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
            logfiles = [h.baseFilename for h in self.log.handlers if isinstance(h, logging.FileHandler)]
            if len(logfiles) > 0:
                print(f"* Attach log file at: {logfiles[0]}\n")
            self.log.debug(f"\n\n!!!!! PROGRAM ERROR:\n{msg}\n")

        self.exit_app()

    ##-------------------------------------------------------------------------
    ## Tests
    ##-------------------------------------------------------------------------
    def test_config_format(self):
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
        failcount = 0
        vncviewercmd = self.config.get('vncviewer', 'vncviewer')
        cmd = [vncviewercmd, '--help']
        self.log.debug(f'Checking VNC viewer: {" ".join(cmd)}')
        result = subprocess.run(cmd, capture_output=True)
        output = result.stdout.decode() + '\n' + result.stderr.decode()
        if re.search(r'TigerVNC', output):
            self.log.info(f'Checking TigerVNC defaults')
        else:
            self.log.debug(f'We are NOT using TigerVNC')
            return failcount

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
        failcount = 0
        self.log.info('Testing firewall authentication')
        self.firewall_opened = False
        if self.firewall_requested == True:
            self.firewall_pass = getpass(f"\nPassword for firewall authentication: ")
            self.firewall_opened = self.open_firewall(self.firewall_pass)
            if self.firewall_opened is False:
                self.log.error('Failed to open firewall')
                failcount += 1

        return failcount


    def test_ssh_key(self):
        failcount = 0
        self.validate_ssh_key()
        if self.ssh_key_valid is False:
            self.log.error('Failed to validate SSH key')
            failcount += 1

        return failcount


    def test_basic_connectivity(self):
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
        failcount = 0
        failcount += self.test_config_format()
        failcount += self.test_tigervnc()
        failcount += self.test_localhost()
        failcount += self.test_ssh_key_format()
        failcount += self.test_firewall_authentication()
        failcount += self.test_ssh_key()
        failcount += self.test_basic_connectivity()

        if failcount == 0:
            self.log.info('--> All tests PASSED <--')
        else:
            self.log.error(f'--> Found {failcount} failures during tests <--')

        self.play_test_sound()

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


