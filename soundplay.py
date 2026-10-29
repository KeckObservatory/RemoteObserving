import os
import sys
import subprocess
import atexit
import time
import argparse
import logging
import platform
from pathlib import Path

log = logging.getLogger('KRO')
log.setLevel(logging.DEBUG)


class soundplay(object):

    def __init__(self):

        #class vars
        self.proc = None


    def connect(self, instrument, server, port=9798, aplay='aplay'):
        '''
        Connect to sound server
        '''

        log.info(f'Starting soundplayer: server={server}, instrument={instrument}')
        try:
            #massage inputs
            instrument = instrument.lower()
            port = str(port)
            serverport = f'{server}:{port}'

            if aplay is None:
                aplay = 'aplay'

            #check existing soundplay process
            procs = self.check_existing_process(server, port, instrument)
            if procs and len(procs) > 0:
                log.info(f"SOUNDPLAY PROCESS ALREADY EXISTS FOR: {serverport} {instrument}")
                log.debug(procs)
                return False

            #create command and open process and hold on to handle so we can terminate later
            cmd = [Path(sys.executable), Path(__file__).parent / 'soundplayer.py', '-s', serverport, '-T', instrument]

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


    def terminate(self):
        if self.proc:
            log.info('Terminating soundplay process...')
            self.proc.terminate()
