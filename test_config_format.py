import logging
from keck_vnc_launcher import create_logger, KeckVncLauncher, create_parser
import pytest
import socket
from pathlib import Path
import subprocess


# create kvl object
create_logger()
kvl = KeckVncLauncher()
kvl.log = logging.getLogger('KRO')
kvl.log_system_info()
kvl.args = create_parser()
kvl.get_config()
kvl.check_config()


def test_firewall_address():
    firewall_address = kvl.config.get('firewall_address', None)
    assert firewall_address is not None
    # the line below will throw an error if the IP address is not valid
    socket.inet_aton(firewall_address)


def test_firewall_port():
    firewall_port = kvl.config.get('firewall_port', None)
    assert firewall_port is not None
    assert isinstance(int(firewall_port), int)


def test_firewall_user():
    firewall_user = kvl.config.get('firewall_user', None)
    assert firewall_user is not None


def test_ssh_pkey():
    ssh_pkey = kvl.config.get('ssh_pkey', '~/.ssh/id_rsa')
    ssh_pkey = Path(ssh_pkey)
    assert ssh_pkey.expanduser().exists()
    assert ssh_pkey.expanduser().is_file()


def test_vncviewer():
    vncviewer = kvl.config.get('vncviewer', None)
    if vncviewer in [None, '', 'vncviewer']:
        # the line below will throw and error if which fails
        vncviewer = subprocess.check_output(['which', 'vncviewer'])
    if vncviewer != 'open':
        vncviewer = Path(vncviewer).expanduser()
        assert vncviewer.exists()