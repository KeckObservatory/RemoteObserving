import os
import sys
import subprocess
import atexit
import time
import argparse
import logging
import platform

log = logging.getLogger('KRO')


class soundplay(object):

    def __init__(self):

        #class vars
        self.proc = None


    def connect(self, instrument, server=None, port=9798, aplay='aplay', player=None):
        '''
        Connect to sound server
        '''

        log.info(f'Starting soundplayer: server={server}, instrument={instrument}')
        try:
            #massage inputs
            instrument = instrument.lower()
            port = str(port)
            if server is None:
                server = self.getVncServer(instrument)
            serverport = f'{server}:{port}'

            # TODO: It should be OK for aplay to be None here.
            if aplay is None:
                aplay = 'aplay'

            soundplayPath = full_path(player)

            #check existing soundplay process
            procs = self.check_existing_process(server, port, instrument)
            if procs and len(procs) > 0:
                log.info(f"SOUNDPLAY PROCESS ALREADY EXISTS FOR: {serverport} {instrument}")
                log.debug(procs)
                return False

            #create command and open process and hold on to handle so we can terminate later
            cmd = [soundplayPath, '-s', serverport, '-T', instrument]

            if aplay is not None:
                cmd.append('-px')
                cmd.append(aplay)

            log.debug('Soundplay cmd: ' + str(cmd))
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except Exception as error:
            log.error("Could not start soundplayer")
            log.error(error)
            return False

        return True


    def check_existing_process(self, server, port, instrument):
        '''
        Use system ps command to look for processes connected to same server/port/instr combo
        '''
        #todo: fix this to use proper cmd array and shell=False
        cmd = f'ps -elf | grep soundplay | grep "{server}:{port}" | grep {instrument} | grep -v grep'
        log.debug('Checking for existing soundplay process: ' + cmd)
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        data = proc.communicate()[0]
        data = data.decode("utf-8").strip()
        lines = data.split('\n') if data else []
        return lines


    def getVncServer(self, instrument):
        '''
        #todo: move this common function to shared module.  It can look for ssh key.  If not found, then it can prompt for password.
        '''
        raise Exception("Not implemented yet. Must provide server name explicitly.")


    def terminate(self):
        if self.proc:
            log.info('Terminating soundplay process...')
            self.proc.terminate()



##-------------------------------------------------------------------------
## Get the full path to the soundplay executable
##-------------------------------------------------------------------------

def full_path(player=None):

    remobs_base = os.path.dirname(os.path.abspath(__file__))
    soundplayers = os.path.join(remobs_base, 'soundplayer')

    if player is None:
        system = platform.system()
        system = system.lower()
        arch = platform.machine()
        arch = arch.lower()

        specific = '.'.join(('soundplay', system, arch))
        sound_path = os.path.join(soundplayers, specific)

        if os.path.exists(sound_path):
            pass
        else:
            sound_path = os.path.join(soundplayers, 'soundplay')

    else:
        if os.path.exists(player):
            sound_path = player
        else:
            sound_path = os.path.join(soundplayers, player)

        if os.path.exists(sound_path):
            pass
        else:
            raise ValueError('invalid soundplay binary name: ' + player)

    return sound_path



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
##  main
##-------------------------------------------------------------------------
if __name__ == "__main__":
    '''
    Run in command line mode
    '''

    #create logger
    create_logger()
    log = logging.getLogger('KRO')

    # arg parser
    parser = argparse.ArgumentParser(description="Start Keck event sounds player.")
    parser.add_argument("instrument",   type=str,                                           help="Instrument to get event sounds for.")
    parser.add_argument("--server",     type=str,   dest="server",  default=None,           help="IP name or address of sound server to connect to. Will query for value if not given.")
    parser.add_argument("--port",       type=int,   dest="port",    default=9798,           help="Server port where soundplayer should connect. Default is standard.")
    parser.add_argument("--player",     type=str,   dest="player",  default='soundplay',    help="Keck soundplay executable filename to use in soundplayer folder.")
    parser.add_argument("--aplay",      type=str,   dest="aplay",   default='aplay',        help="Full path to local system command-line sound player.")
    args = parser.parse_args()


    #define exit handler in case program is killed by user
    def exit_handler(soundplay=None):
        if soundplay: soundplay.terminate()


    #start soundplay
    sp = soundplay()
    ok = sp.connect(args.instrument, server=args.server, port=args.port, aplay=args.aplay, player=args.player)
    if not ok:
        sys.exit(1)

    #wait for interrupt to exit cleanly
    try:
        atexit.register(exit_handler, sp)
        print ('Hit control-C to terminate program and close soundplay connection.')
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        if sp: sp.terminate()
