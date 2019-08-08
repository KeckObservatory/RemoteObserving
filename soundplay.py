import os
import sys
import subprocess
import atexit
from time import sleep
import argparse


class soundplay(object):

    def __init__(self):
        
        #class vars
        self.proc = None


    def connect(self, instrument, server=None, port=9798, aplay='aplay', player='soundplay'):
        '''
        Connect to sound server
        '''

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
            print ("SOUNDPLAY PROCESS ALREADY EXISTS FOR: ", server+':'+port, instrument)
            print (procs)
            return False

        #path to soundplay is relative to this script
        #todo: auto-detect based on OS, etc?
        soundplayPath  = os.path.dirname(os.path.abspath(__file__)) + "/soundplayer/" + player

        #create command and open process and hold on to handle so we can terminate later
        cmd = [soundplayPath, '-s', serverport, '-T', instrument, '-px', aplay]
        print ('Connecting to sound server: ', ' '.join(cmd))
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


    def check_existing_process(self, server, port, instrument):
        '''
        Use system ps command to look for processes connected to same server/port/instr combo
        '''
        cmd = f'ps -elf | grep soundplay | grep "{server}:{port}" | grep {instrument} | grep -v grep'
        print ('Checking for existing soundplay process: ', cmd)
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        data = proc.communicate()[0]
        data = data.decode("utf-8").strip()
        lines = data.split('\n') if data else []
        return lines


    def getVncServer(self, instrument):
        #todo: move this common function to shared module.  It can look for ssh key.  If not found, then it can prompt for password.
        raise Exception("Not implemented yet. Must provide server name explicitly.")


    def terminate(self):
        if self.proc:
            print ('\nTerminating soundplay process...\n')
            self.proc.terminate()




##-------------------------------------------------------------------------
##  main
##-------------------------------------------------------------------------
if __name__ == "__main__":
    '''
    Run in command line mode
    '''

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


    #start soundplay and wait for kill signal to terminate
    try:
        sp = soundplay()
        sp.connect(args.instrument, server=args.server, port=args.port, aplay=args.aplay, player=args.player)
        atexit.register(exit_handler, sp)
        print ('Hit control-C to terminate program and close soundplay connection.')
        while True:
            sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        if sp: sp.terminate()
