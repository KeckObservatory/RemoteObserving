import pytest
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

    try:
        cmd = [vncviewercmd, '--help']
        kvl.log.info(f'Checking VNC viewer: {" ".join(cmd)}')
        help_STDOUT = subprocess.check_output(cmd)
    except:
        kvl.log.warning(f'Command {" ".join(cmd)} Failed')
        raise

    if re.search(r'TigerVNC', help_STDOUT.decode()):
        # VNC Viewer is TigerVNC, so we need to verify the RemoteResize config
        with open(Path('~/.vnc/default.tigervnc').expanduser()) as FO:
            tiger_config = FO.read()
        RRsearch = re.search(r'RemoteResize=(\d)', tiger_config)
        if RRsearch is None:
            log.error('Could not find RemoteResize setting')
            assert RRsearch is not None
        else:
            remote_resize_value  = int(RRsearch.group(1))
            log.info(f'Found RemoteResize set to {remote_resize_value}')
            assert remote_resize_value == 1
