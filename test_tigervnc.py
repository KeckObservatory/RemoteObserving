import pytest
from pathlib import Path
import logging
import subprocess
import re

from keck_vnc_launcher import create_logger, KeckVncLauncher, create_parser


# create kvl object
create_logger()
kvl = KeckVncLauncher()
kvl.log = logging.getLogger('KRO')
kvl.log_system_info()
kvl.args = create_parser()
kvl.get_config()
kvl.check_config()


def we_using_tigervnc():
    vncviewercmd = kvl.config.get('vncviewer', 'vncviewer')
    cmd = [vncviewercmd, '--help']
    kvl.log.info(f'Checking VNC viewer: {" ".join(cmd)}')
    result = subprocess.run(cmd, capture_output=True)
    output = result.stdout.decode() + '\n' + result.stderr.decode()
    if re.search(r'TigerVNC', output):
        kvl.log.info(f'We are using TigerVNC')
        return True
    else:
        kvl.log.info(f'We are NOT using TigerVNC')
        return False


def test_tigervnc_config_file_exists():
    if we_using_tigervnc() is True:
        tigervnc_config_file = Path('~/.vnc/default.tigervnc').expanduser()
        if tigervnc_config_file.exists() is False: 
            kvl.log.error(f'Could not find {tigervnc_config_file}')
        assert tigervnc_config_file.exists()


def test_tigervnc_config_RemoteResize():
    if we_using_tigervnc() is True:
        tigervnc_config_file = Path('~/.vnc/default.tigervnc').expanduser()
        with open(tigervnc_config_file) as FO:
            tiger_config = FO.read()
        RRsearch = re.search(r'RemoteResize=(\d)', tiger_config)
        if RRsearch is None:
            kvl.log.error('Could not find RemoteResize setting')
            assert RRsearch is not None
        else:
            remote_resize_value  = int(RRsearch.group(1))
            kvl.log.info(f'Found RemoteResize set to {remote_resize_value}')
            if remote_resize_value !=0:
                kvl.log.error('RemoteResize must be set to 0')
                assert remote_resize_value == 0
