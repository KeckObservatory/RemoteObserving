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

def test_tigervnc_config():
    vncviewercmd = kvl.config.get('vncviewer', 'vncviewer')

    cmd = [vncviewercmd, '--help']
    kvl.log.info(f'Checking VNC viewer: {" ".join(cmd)}')
    result = subprocess.run(cmd, capture_output=True)
    output = result.stdout.decode() + '\n' + result.stderr.decode()

    if re.search(r'TigerVNC', output):
        # VNC Viewer is TigerVNC, so we need to verify the RemoteResize config
        tigervnc_config_file = Path('~/.vnc/default.tigervnc').expanduser()
        assert tigervnc_config_file.exists()
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
                kvl.log.error('RemoteResize must be set to 1')
                assert remote_resize_value == 0
