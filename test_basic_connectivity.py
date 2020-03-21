import logging
from getpass import getpass
from keck_vnc_launcher import create_logger, KeckVncLauncher, create_parser
import pytest


# create kvl object
create_logger()
kvl = KeckVncLauncher()
kvl.log = logging.getLogger('KRO')
kvl.log_system_info()
kvl.args = create_parser()
kvl.get_config()
kvl.check_config()

servers_and_results = [('svncserver1', 'kaalualu'),
                       ('svncserver2', 'ohaiula'),
                       ('mosfire', 'vm-mosfire'),
                       ('hires', 'vm-hires'),
                       ('lris', 'vm-lris'),
                       ('kcwi', 'vm-kcwi'),
                       ('nirc2', 'vm-nirc2'),
                       ('nires', 'vm-nires'),
                       ('nirspec', 'vm-nirspec')]

def test_firewall_authentication():
    kvl.firewall_opened = False
    if kvl.firewall_requested == True:
        kvl.firewall_pass = getpass(f"\nPassword for firewall authentication: ")
        kvl.firewall_opened = kvl.open_firewall(kvl.firewall_pass)
        assert kvl.firewall_opened is True


def test_ssh_key():
    kvl.validate_ssh_key()
    assert kvl.ssh_key_valid is True


@pytest.mark.parametrize("server,result", servers_and_results)
def test_connection_to_servers(server, result):
    vnc_account = kvl.kvnc_account

    kvl.log.info(f'Testing SSH to {vnc_account}@{server}.keck.hawaii.edu')
    output = kvl.do_ssh_cmd('hostname', f'{server}.keck.hawaii.edu',
                            vnc_account)
    assert output is not None
    assert output != ''
    assert output.strip() in [server, result]
    kvl.log.info(f' Passed')
