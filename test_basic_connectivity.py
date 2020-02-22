import paramiko
import sshtunnel
import logging
from getpass import getpass
from keck_vnc_launcher import create_logger, KeckVncLauncher, create_parser


# create kvl object
create_logger()
kvl = KeckVncLauncher()
kvl.log = logging.getLogger('KRO')
kvl.log_system_info()
kvl.args = create_parser()
kvl.get_config()
kvl.check_config()

servers_to_test = ['svncserver1', 'svncserver2', 'mosfire', 'hires', 'lris',
                   'kcwi', 'nirc2', 'nires', 'nirspec']

def test_firewall_authentication():
    kvl.is_authenticated = False
    if kvl.do_authenticate:
        kvl.firewall_pass = getpass(f"Password for firewall authentication: ")
        kvl.is_authenticated = kvl.authenticate(kvl.firewall_pass)
        assert kvl.is_authenticated is True


def test_ssh_key():
    if kvl.config.get('nosshkey', False) is not True:
        kvl.validate_ssh_key()
        assert kvl.is_ssh_key_valid is True


def test_connection_to_servers():
    if kvl.is_ssh_key_valid is True:
        vnc_password = None
        vnc_account = kvl.SSH_KEY_ACCOUNT
    else:
        vnc_account = kvl.args.account
        vnc_password = getpass(f"Password for user {vnc_account}: ")

    for server in servers_to_test:
        kvl.log.info(f'Testing SSH to {vnc_account}@{server}.keck.hawaii.edu')
        output = kvl.do_ssh_cmd('hostname', f'{server}.keck.hawaii.edu',
                                vnc_account, vnc_password)
        assert output is not None
        assert output != ''
        kvl.log.info(f' Passed')
