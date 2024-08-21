import argparse
import pdb
import os
import sys
import socketio
import signal
import logging
import logging.config
import configparser
import time
import threading
from collections import deque

import socketio.exceptions

CONFIG_PATH = 'config.live.ini'
logging.config.fileConfig(CONFIG_PATH)
logger = logging.getLogger(__name__)
logger.info('starting odap_cli')
config = configparser.ConfigParser()
config.read(CONFIG_PATH)
defaultDir = os.getcwd()

parser = argparse.ArgumentParser(description="Setup websocket host")
parser.add_argument('--directory', type=str, required=False, default=defaultDir,
                    help='directory to save files. directory must exist.')
parser.add_argument('--lev0', type=bool, required=False, default=True,
                    help='receive lev0 messesages')
parser.add_argument('--lev1', type=bool, required=False, default=True,
                    help='receive lev1 messesages')
parser.add_argument('--streamFile', type=bool, required=False, default=False,
                    help='stream files to directory')
parser.add_argument('--ofname', type=bool, required=False, default=True,
                    help='If true, files are named by ofname, else koaid.')
parser.add_argument('--requestExistingFiles', type=bool, required=False, default=False,
                    help='Request existing files from the server.')
parser.add_argument('--instruments', type=str, required=False, default=None,
                    help='instrument to receive data from. If None, receive all instruments.')

def log_exit(name=None):
    def inner(func):
        def wrapper(*args, **kwargs):
            nme = name if name else args[0]
            logger.info(f'entering {nme}')
            result = func(*args, **kwargs)
            logger.info(f'exiting {nme}')
            return result 
        return wrapper 
    return inner 

def signal_handler(sig, frame):
    logger.info("exiting threads")
    threadExit.set()
    soc.disconnect()

def sigint_handler(sig, frame):
    signal_handler(sig, frame)
    sys.exit()

# Exit on these signals
signal.signal(signal.SIGINT, sigint_handler)
signal.signal(signal.SIGTERM, signal_handler)


args = parser.parse_args()
directory = args.directory
instrumentsStr = args.instruments
instrumentsStr = instrumentsStr.upper() if instrumentsStr else None
instruments = instrumentsStr.replace(' ', '').split(',') if instrumentsStr else [] 

logger.info(f'args: {args}')

assert os.path.exists(directory), f"directory {directory} does not exist"

levs = {
    'lev0': args.lev0,
    'lev1': args.lev1,
}
streamFile = args.streamFile
fnkey = 'ofname' if args.ofname else 'koaid'
requestExistingFiles = args.requestExistingFiles

hash = config['userinfo']['hash']
workers = config['queue']['workers']
url = config['socketio']['url']
socketio_path = config['socketio']['socketio_path']
reconnection_attempts = int(config['socketio']['reconnection_attempts'])
reconnection_delay = int(config['socketio']['reconnection_delay'])
socLogger = logger if bool(int(config['socketio']['soc_logger'])) else False

soc = socketio.Client(reconnection_attempts=reconnection_attempts,
                      reconnection_delay=reconnection_delay,
                      logger=socLogger, 
                      engineio_logger=socLogger)

queue = deque()

threadExit = threading.Event()

@soc.on('disconnect')
def disconnect():
    logger.warning(f'{soc.get_sid()} is disconnecting')

@soc.on('connect')
def connect(): #sometimes client reconnects, requiring the new session to be added to rooms
    logger.info(f'connected to {url} session id {soc.get_sid()}')
    data = {'hash': hash, 'requestExistingFiles': requestExistingFiles}
    soc.emit('request_session_data', data=data,
             callback=session_data_callback)

@soc.on('receive_metadata_event')
def receive_metadata_event(row):
    global queue
    ingestType = row['ingestType']
    filename = row.get(fnkey, row.get('koaid', 'unknown'))
    row['filename'] = filename
    if not levs[ingestType]:
        logger.debug(f'ingestType {ingestType} not allowed. skipping {filename}')
        return 
    instrument = row['instrument']
    if not instrument in instruments:
        logger.debug(f'instrument {instrument} not selected. skipping {filename}')
        return
    logger.info(f"received metadata for {instrument} file {filename}")

    if streamFile:
        queue.appendleft(row)

@soc.on('send_previous_data')
def send_previous_data(data):
    global queue
    rows = data['metadata']
    logger.info(f'processing existing data: {len(rows)} rows')
    for row in rows:
        filename = row.get('koaid')
        ofname = row.get('ofname')
        if not filename:
            continue
        dlname = os.path.join(directory, row.get(fnkey))
        if os.path.exists(dlname):
            logger.warning(f'{filename} ({ofname}) already exists in {directory}')
            continue 
        logger.info(f"{filename} ({ofname}) added to queue")
        queue.append(row)

@soc.on('receive_new_file')
def receive_new_file(data):
    filename = data['metadata'].get(fnkey, data['metadata'].get('filename'))
    filename = os.path.basename(filename)
    instrument = data['metadata'].get('instrument')
    logger.info(f'saving {instrument} file {filename} to {directory}')
    dlname = os.path.join(directory, filename)
    with open(dlname, 'wb') as f:
        f.write(data['data_bytes'])

def session_data_callback(*data):
    global instruments
    assignedInstruments = data[3]

    if not instruments:
        logger.info(f'no instruments specified. Setting to {data[3]}')
        instruments = data[3]
    else:
        instruments = [inst for inst in instruments if inst in assignedInstruments]
        logger.info(f'instruments constrained to: {instruments}')
    logger.info(f'received userinfo data: {data}')

def process_row(name, row):
    filename = row.get(fnkey, row.get('koaid', 'unknown'))
    fileExists = os.path.exists(os.path.join(directory, filename))
    if fileExists:
        logger.warning(f'{filename} already exists in {directory}')
        return 
    logger.info(f"{name} requesting {filename}")
    soc.emit('request_file', row)
    return fileExists


@log_exit('ping_worker')
def ping_worker():
    cb = lambda: logger.debug('pong received')
    while not soc.namespaces:
        threadExit.wait(1)
    while not threadExit.is_set():
        soc.emit('ping', callback=cb)
        threadExit.wait(60)

@log_exit()
def worker(name, queue):
    while not soc.namespaces:
        threadExit.wait(1)
    while not threadExit.is_set():
        if len(queue) <= 0:
            threadExit.wait(5)
            continue
        try:
            row = queue.pop()
            process_row(name, row)
            if len(queue) > 2:
                threadExit.wait(5) # pause if queue is large
        except IndexError as err:
            logger.debug(f'{err}')
        except FileExistsError as err:
            logger.info(f'{err}')
    logger.info(f'{name} exiting')


@log_exit('main')
def main():
    global queue
    global threadExit
    threadExit.clear()
    queue = deque()
    logger.info(f'connecting to {url} , socketio_path={socketio_path}')

    threads = []
    for idx in range(int(workers)):
        th = threading.Thread(target=worker, args=(f'worker-{idx}', queue))
        th.start()
        threads.append(th)
    th = threading.Thread(target=ping_worker, args=())
    th.start()
    threads.append(th)

    soc.connect(url, socketio_path=socketio_path, transports=['websocket'])
    while not soc.namespaces:
        threadExit.wait(1)
    soc.wait()
    logger.info('socket disconnected')
    # signal.raise_signal(signal.SIGINT) # this exits the main thread and all other threads
    signal.raise_signal(signal.SIGTERM) # this will shutdown all other threads. 
    for thread in threads:
        thread.join()
    logger.info('exiting odap_cli')

if __name__ == '__main__':
    reconnectWait = 1
    while True:
        try:
            logging.info('starting odap_cli')
            main()
            reconnectWait = 1
        except KeyboardInterrupt:
            logger.info('keyboard interrupt')
            signal.raise_signal(signal.SIGINT)
            break
        except ConnectionError as err:
            logger.warning(f'connection exception in odap_cli {err}')
            soc.sleep(reconnectWait)
            reconnectWait = min(reconnectWait * 2, 10)
            logger.warning('restarting odap_cli')
        except socketio.exceptions.ConnectionError as err:
            logger.warning(f'socketio connection exception in odap_cli {err}')
            soc.sleep(reconnectWait)
            reconnectWait = min(reconnectWait * 2, 10)
            logger.warning('restarting odap_cli')
        except socketio.exceptions.BadNamespaceError as err:
            logger.warning(f'socketio error in odap_cli {err}')
            soc.sleep(reconnectWait)
            reconnectWait = min(reconnectWait * 2, 10)
            logger.warning('restarting odap_cli')
        except Exception as err:
            logger.error(f'unhandled exception in odap_cli {err}')
            signal.raise_signal(signal.SIGINT)
