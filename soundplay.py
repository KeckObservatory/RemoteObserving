import os
import sys
import subprocess
import atexit
import time
import argparse
import logging

log = logging.getLogger('KRO')


class soundplay(object):

    def __init__(self):
        
        #class vars
        self.proc = None


    def connect(self, instrument, server=None, port=9798, aplay='aplay', player='soundplay'):
        '''
        Connect to sound server
        '''

        log.info(f'Starting soundplayer: server={server}, instrument={instrument}')
        try:
            #massage inputs
            instrument = instrument.lower()
            port = str(port)
            if server == None: server = self.getVncServer(instrument)
            serverport = f'{server}:{port}'
            if aplay  == None: aplay  = 'aplay'
            if player == None: player = 'soundplay'

            #check existing soundplay process
            procs = self.check_existing_process(server, port, instrument)
            if procs and len(procs) > 0:
                log.info(f"SOUNDPLAY PROCESS ALREADY EXISTS FOR: {serverport} {instrument}")
                log.debug(procs)
                return False

            #path to soundplay is relative to this script
            #todo: auto-detect based on OS, etc?
            soundplayPath  = os.path.dirname(os.path.abspath(__file__)) + "/soundplayer/" + player

            #create command and open process and hold on to handle so we can terminate later
            cmd = [soundplayPath, '-s', serverport, '-T', instrument, '-px', aplay]
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
            log.info('\nTerminating soundplay process...\n')
            self.proc.terminate()



##-------------------------------------------------------------------------
## Create logger
##-------------------------------------------------------------------------
def create_logger():

    try:
        ## Create logger object
        log = logging.getLogger('KRO')
        log.setLevel(logging.DEBUG)

        #stream/console handler (info+ only)
        logConsoleHandler = logging.StreamHandler()
        logFormat = logging.Formatter(' %(levelname)8s: %(message)s')
        logFormat.converter = time.gmtime
        logConsoleHandler.setFormatter(logFormat)
        
        log.addHandler(logConsoleHandler)

    except Exception as error:
        print (f"ERROR: Unable to create logger")
        print (str(error))


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
