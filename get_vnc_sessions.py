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

from datetime import datetime
import platform
import traceback



##-------------------------------------------------------------------------
## Create logger
##-------------------------------------------------------------------------
def create_logger():

    ## Create logger object
    log = logging.getLogger('GetVNCs')
    log.setLevel(logging.DEBUG)

    #create log file and log dir if not exist
    logFile = get_logfile_path()
    if not os.path.exists(os.path.dirname(logFile)):
        os.makedirs(os.path.dirname(logFile))

    #file handler (full debug logging)
    logFileHandler = logging.FileHandler(logFile)
    logFileHandler.setLevel(logging.DEBUG)
    logFormat = logging.Formatter('%(asctime)s - %(levelname)s: %(message)s')
    logFileHandler.setFormatter(logFormat)
    log.addHandler(logFileHandler)

    #stream/console handler (info+ only)
    logConsoleHandler = logging.StreamHandler()
    logConsoleHandler.setLevel(logging.INFO)
    logFormat = logging.Formatter(' %(levelname)8s: %(message)s')
    logConsoleHandler.setFormatter(logFormat)
    log.addHandler(logConsoleHandler)

    return log

def get_logfile_path():
    ymd = datetime.today().strftime('%Y%m%d')
    return f'logs/keck-remote-log-{ymd}.txt'


##-------------------------------------------------------------------------
## Get args
##-------------------------------------------------------------------------
def get_args():

    ## create a parser object for understanding command-line arguments
    parser = argparse.ArgumentParser(description="Get VNC sessions.")

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

    ## add arguments
    parser.add_argument("account", type=str,
        help="The user account.")

    ## add options
    parser.add_argument("-c", "--config", dest="config", type=str,
        help="Path to local configuration file.")

    #parse
    args = parser.parse_args()
    log.debug("\n\n\t***** PROGRAM STARTED *****\n\tArguments: " + ' '.join(sys.argv[1:]) + "\n")

    return args


##-------------------------------------------------------------------------
## Get Configuration
##-------------------------------------------------------------------------
def get_config(filename=None, filenames=['local_config.yaml', 'keck_vnc_config.yaml']):

    #if config file specified, put that at beginning of list
    if filename is not None:
        if not os.path.exists(filename):
            log.error(f'Specified config file "{filename}"" does not exist!')
            sys.exit(1)
        else:
            filenames.insert(0, filename)

    #find first file that exists
    file = None
    for f in filenames:
        if os.path.exists(f):
            file = f
            break
    if not file:
        log.error(f'No config files found.')
        sys.exit(1)

    #load config file and make sure it has the info we need
    log.info(f'Using config file {file}')
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
            log.warning(f"Only {nlp} local ports specified.")
            log.warning(f"Program may crash if trying to open >{nlp} sessions")

    return config


##-------------------------------------------------------------------------
## Log basic system info
##-------------------------------------------------------------------------
def log_system_info():
    log.debug(f'System Info: {os.uname()}')
    hostname = socket.gethostname()
    log.debug(f'System hostname: {hostname}')
    log.debug(f'System IP Address: {socket.gethostbyname(hostname)}')


##-------------------------------------------------------------------------
## Get sessions to open
##-------------------------------------------------------------------------
def get_sessions_to_open(args):

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
def launch_xterm(command, pw, title):
    cmd = ['xterm', '-hold', '-title', title, '-e', f'"{command}"']
    xterm = call(cmd)


##-------------------------------------------------------------------------
## Open ssh tunnel
##-------------------------------------------------------------------------
def open_ssh_tunnel(server, username, password, remote_port, local_port):
    server = sshtunnel.SSHTunnelForwarder(server,
                                ssh_username=username,
                                ssh_password=password,
                                remote_bind_address=('127.0.0.1', remote_port),
                                local_bind_address=('0.0.0.0', local_port),
                                )
    server.start()


##-------------------------------------------------------------------------
## Launch vncviewer
##-------------------------------------------------------------------------
def launch_vncviewer(vncserver, port, config=None, pw=None):
    vncviewercmd = config.get('vncviewer', 'vncviewer')
    vncprefix = config.get('vncprefix', '')
    vncargs = config.get('vncargs', None)
    cmd = [vncviewercmd]
    if vncargs is not None:
        cmd.append(vncargs)
    cmd.append(f'{vncprefix}{vncserver}:{port:4d}')
    log.info(f"  Launching VNC viewer for {cmd[-1]}")
    vncviewer = call(cmd)


##-------------------------------------------------------------------------
## Authenticate
##-------------------------------------------------------------------------
def authenticate(authpass,  config=None):
    log.info('Authenticating through firewall')

    assert 'firewall_user' in config.keys()
    assert 'firewall_address' in config.keys()
    assert 'firewall_port' in config.keys()
    firewall_user = config.get('firewall_user')
    firewall_address = config.get('firewall_address')
    firewall_port = config.get('firewall_port')
    log.debug(f'Firewall auth: user={firewall_user}, address={firewall_address}, port={firewall_port}')

    with Telnet(firewall_address, int(firewall_port)) as tn:
        tn.read_until(b"User: ", timeout=5)
        tn.write(f'{firewall_user}\n'.encode('ascii'))
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
            return None


##-------------------------------------------------------------------------
## Close Authentication
##-------------------------------------------------------------------------
def close_authentication(authpass, config):
    log.info('Signing off of firewall authentication')

    assert 'firewall_user' in config.keys()
    assert 'firewall_address' in config.keys()
    assert 'firewall_port' in config.keys()
    firewall_user = config.get('firewall_user')
    firewall_address = config.get('firewall_address')
    firewall_port = config.get('firewall_port')

    with Telnet(firewall_address, int(firewall_port)) as tn:
        tn.read_until(b"User: ", timeout=5)
        tn.write(f'{firewall_user}\n'.encode('ascii'))
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
            return None


##-------------------------------------------------------------------------
## Determine Instrument
##-------------------------------------------------------------------------
def determine_instrument(accountname):
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
def determine_VNCserver(accountname, password, config):
    servers_to_try = config.get('servers_to_try')
    vncserver = None
    for s in servers_to_try:
        try:
            log.info(f'Trying {s}:')
            client = paramiko.SSHClient()
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.WarningPolicy())
            client.connect(f"{s}.keck.hawaii.edu", port=22, timeout=6,
                           username=accountname, password=password)
            log.info('  Connected')
        except TimeoutError:
            log.info('  Timeout')
        except:
            log.info('  Failed')
        else:
            stdin, stdout, stderr = client.exec_command('kvncinfo -server')
            rawoutput = stdout.read()
            vncserver = rawoutput.decode().strip('\n')
            log.debug(f"  kvncinfo -server returned: '{vncserver}'")
        finally:
            client.close()
            if vncserver is not None and vncserver != '':
                log.info(f"Got VNC server: '{vncserver}'")
                break

    # todo: Temporary hack for KCWI
    if vncserver == 'vm-kcwivnc':
        vncserver = 'kcwi'

    return f"{vncserver}.keck.hawaii.edu"


##-------------------------------------------------------------------------
## Determine VNC Sessions
##-------------------------------------------------------------------------
def determine_VNC_sessions(accountname, password, vncserver):
    log.info(f"Connecting to {vncserver} to get VNC sessions list")
    try:
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.WarningPolicy())
        client.connect(vncserver, port=22, timeout=6,
                       username=accountname, password=password)
        log.info('  Connected')
    except TimeoutError:
        log.info('  Timeout')
    except:
        log.error('  Failed')
        raise
    else:
        stdin, stdout, stderr = client.exec_command('kvncstatus')
        rawoutput = stdout.read()
        output = rawoutput.decode().strip('\n')
        allsessions = Table.read(output.split('\n'), format='ascii')
        log.debug(f'  Got {len(allsessions)} sessions for all users')
        if len(allsessions) == 0:
            log.warning(f'Found 0 sessions on {vncserver}')
            client.close()
            sessions = []
        else:
            sessions = allsessions[allsessions['User'] == accountname]
            log.info(f'  Got {len(sessions)} sessions')
            names = [x['Desktop'].split('-')[2] for x in sessions]
            sessions.add_column(Column(data=names, name=('name')))
    finally:
        client.close()
        return sessions


##-------------------------------------------------------------------------
## Main Program
##-------------------------------------------------------------------------
def main(args, config):

    ##-------------------------------------------------------------------------
    ## Authenticate Through Firewall (or Disconnect)
    ##-------------------------------------------------------------------------
    if 'firewall_address' in config.keys() and\
       'firewall_user' in config.keys() and\
       'firewall_port' in config.keys():
        config['authenticate'] = True
        import sshtunnel
    else:
        config['authenticate'] = False

    if config['authenticate'] is True:
        authpass = getpass(f"Password for firewall authentication: ")
        authenticate(authpass, config)

    if args.authonly is True:
        ## Wait for quit signal
        if config['authenticate'] is True:
            sleep(1)
            quit = input('Hit q to close down any SSH tunnels and firewall auth: ')
            foundq = re.match('^[qQ].*', quit)
            while foundq is None:
                sleep(1)
                quit = input('Hit q to close down any SSH tunnels and firewall auth: ')
                foundq = re.match('^[qQ].*', quit)
        ## Close down ssh tunnels and firewall authentication
        if config['authenticate'] is True:
            close_authentication(authpass, config)
        return


    ##-------------------------------------------------------------------------
    ## Determine sessions to open
    ##-------------------------------------------------------------------------
    sessions_to_open = get_sessions_to_open(args)


    ##-------------------------------------------------------------------------
    ## Determine instrument
    ##-------------------------------------------------------------------------
    instrument, tel = determine_instrument(args.account)
    if not instrument: 
        log.error(f'Account name "{args.account}" not a valid instrument account name!')
        return


    ##-------------------------------------------------------------------------
    ## Determine VNC server
    ##-------------------------------------------------------------------------
    password = getpass(f"Password for user {args.account}: ")
    vncserver = determine_VNCserver(args.account, password, config)


    ##-------------------------------------------------------------------------
    ## Determine VNC Sessions
    ##-------------------------------------------------------------------------
    sessions = determine_VNC_sessions(args.account, password, vncserver)
    if len(sessions) == 0:
        log.info('No VNC sessions found')
        if config['authenticate'] is True:
            close_authentication(authpass, config)
        return
    log.info("\n" + str(sessions))


    ##-------------------------------------------------------------------------
    ## Open SSH Tunnel for Appropriate Ports
    ##-------------------------------------------------------------------------
    ports_in_use = []
    if config['authenticate'] is True:
        ssh_threads = []
        for session in sessions:
            if session['name'] in sessions_to_open:
                display = int(session['Display'][1:])
                port = int(f"59{display:02d}")
                if 'local_ports' in config.keys():
                    localport = config['local_ports'].pop(0)
                else:
                    localport = port
                ports_in_use.append(localport)
                log.info(f"Opening SSH tunnel for {session['name']}")
                log.info(f"  remote port = {port}, local port = {localport}")
                server = sshtunnel.SSHTunnelForwarder(vncserver,
                                  ssh_username=args.account,
                                  ssh_password=password,
                                  remote_bind_address=('127.0.0.1', port),
                                  local_bind_address=('0.0.0.0', localport),
                                  )
                ssh_threads.append(server)
                try:
                    ssh_threads[-1].start()
                except sshtunnel.HandlerSSHTunnelForwarderError as e:
                    log.error('Failed to open tunnel')
                    log.error(e)
        if args.status is True:
            if 'local_ports' in config.keys():
                statusport = config['local_ports'].pop(0)
            else:
                statusport = [p for p in range(5901,5910,1)
                              if p not in ports_in_use][0]
            log.info(f"Opening SSH tunnel for k{tel}status")
            log.info(f"  remote port = {port}, local port = {statusport}")
            server = sshtunnel.SSHTunnelForwarder(f"svncserver{tel}.keck.hawaii.edu",
                              ssh_username=args.account,
                              ssh_password=password,
                              remote_bind_address=('127.0.0.1', 5901),
                              local_bind_address=('0.0.0.0', statusport),
                              )
            ssh_threads.append(server)
            try:
                ssh_threads[-1].start()
            except sshtunnel.HandlerSSHTunnelForwarderError as e:
                log.error('Failed to open tunnel')
                log.error(e)
    elif args.status is True:
        if 'local_ports' in config.keys():
            statusport = config['local_ports'].pop(0)
        else:
            statusport = [p for p in range(5901,5910,1)
                          if p not in ports_in_use][0]


    ##-------------------------------------------------------------------------
    ## Open vncviewers
    ##-------------------------------------------------------------------------
    vnc_threads = []
    if config['authenticate'] is True:
        vncserver = 'localhost'
        statusvncserver = 'localhost'
    else:
        statusvncserver = f"svncserver{tel}.keck.hawaii.edu"
    if config['vncviewer'] in [None, 'None', 'none']:
        log.info(f"No VNC viewer application specified")
        log.info(f"Open your VNC viewer manually")
    else:
        for session in sessions:
            if session['name'] in sessions_to_open:
                log.info(f"Opening VNCviewer for {session['name']}")
                display = int(session['Display'][1:])
                if ports_in_use != []:
                    port = ports_in_use.pop(0)
                else:
                    port = int(f"59{display:02d}")

                vnc_threads.append(Thread(target=launch_vncviewer,
                                          args=(vncserver, port, config)))
                vnc_threads[-1].start()
                sleep(0.05)
        if args.status is True:
            log.info(f"Opening VNCviewer for k{tel}status on {statusport}")
            vnc_threads.append(Thread(target=launch_vncviewer,
                                      args=(statusvncserver, statusport, config)))
            vnc_threads[-1].start()


    ##-------------------------------------------------------------------------
    ## Wait for quit signal
    ##-------------------------------------------------------------------------
    if config['authenticate'] is True:
        sleep(1)
        quit = input('Hit q to close down any SSH tunnels and firewall auth: ')
        foundq = re.match('^[qQ].*', quit)
        while foundq is None:
            sleep(1)
            quit = input('Hit q to close down any SSH tunnels and firewall auth: ')
            foundq = re.match('^[qQ].*', quit)
    
    ##-------------------------------------------------------------------------
    ## Close down ssh tunnels and firewall authentication
    ##-------------------------------------------------------------------------
    if config['authenticate'] is True:
        for thread in ssh_threads:
            log.info(f'Closing SSH forwarding for {thread.local_bind_port}')
            thread.stop()
        close_authentication(authpass, config)


##-------------------------------------------------------------------------
## Handle fatal error
##-------------------------------------------------------------------------
def handle_fatal_error(error):
        supportEmail = 'mainland_observing@keck.hawaii.edu'
        logFile = os.path.dirname(os.path.realpath(__file__)) + '/' + get_logfile_path()

        print ("\n****** PROGRAM ERROR ******\n")
        print ("Error message: " + str(error) + "\n")
        print ("If you need troubleshooting assistance:")
        print (f"* Email {supportEmail} and attach log file.")
        print (f"* Log file location: {logFile}\n")
        #todo: call number, website?

        msg = traceback.format_exc()
        if log: log.debug(f"\n\n!!!!! PROGRAM ERROR:\n{msg}\n")

        sys.exit(1)


##-------------------------------------------------------------------------
## __main__
##-------------------------------------------------------------------------
if __name__ == '__main__':

    print ("\nStarting get_vnc_sessions:\n")

    #catch all exceptions so we can exit gracefully
    try:        
        #create logger (file and stdout)
        log = create_logger()

        #parse command line args
        args = get_args()

        #get yaml config
        config = get_config(filename=args.config)

        #log basic system info
        log_system_info()

        # run main connection code
        main(args, config)

    except Exception as error:
        handle_fatal_error(error)





