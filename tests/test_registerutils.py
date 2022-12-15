# Copyright (c) 2022 SUSE Software Solutions Germany GmbH. All rights reserved.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
# You should have received a copy of the GNU Lesser General Public
# License along with this library.

import inspect
import os
import sys
from unittest import mock
from unittest.mock import patch, call
from lxml import etree

test_path = os.path.abspath(
    os.path.dirname(inspect.getfile(inspect.currentframe())))
code_path = os.path.abspath('%s/../lib' % test_path)
config_path = os.path.abspath('%s/../etc' % test_path)
data_path = test_path + os.sep + 'data/'

sys.path.insert(0, code_path)

import cloudregister.registerutils as utils


cfg = utils.get_config(config_path + '/regionserverclnt.cfg')

CACHE_SERVER_IPS = ['54.197.240.216', '54.225.105.144', '107.22.231.220']


@patch('os.path.exists')
def test_get_available_smt_servers_no_cache(path_exists):
    path_exists.return_value = False
    available_servers = utils.get_available_smt_servers()
    assert [] == available_servers


@patch('cloudregister.registerutils.get_state_dir')
def test_get_available_smt_servers_cache(state_dir):
    state_dir.return_value = data_path
    available_servers = utils.get_available_smt_servers()
    assert len(available_servers) == 3
    for srv in available_servers:
        assert srv.get_ipv4() in CACHE_SERVER_IPS


def test_get_credentials_no_file():
    user, passwd = utils.get_credentials(data_path + 'foo')
    assert user is None
    assert passwd is None


def test_get_credentials():
    user, passwd = utils.get_credentials(data_path + 'credentials')
    assert user == 'SCC_1'
    assert passwd == 'a23'


def test_get_state_dir():
    state_dir = utils.get_state_dir()
    assert state_dir == '/var/cache/cloudregister/'


@patch('cloudregister.registerutils.get_state_dir')
def test_get_zypper_pid_cache_has_cache(state_dir):
    state_dir.return_value = data_path
    assert utils.get_zypper_pid_cache() == '28989'


@patch('os.path.exists')
def test_get_zypper_pid_cache_no_cache(path_exists):
    path_exists.return_value = False
    assert utils.get_zypper_pid_cache() == 0


@patch('cloudregister.registerutils.__get_region_server_args')
@patch('cloudregister.registerutils.__get_framework_plugin')
@patch('cloudregister.registerutils.get_framework_identifier_path')
@patch('cloudregister.registerutils.exec_subprocess')
def test_has_region_changed_no_change(subproc, id_path, plugin, srvargs):
    subproc.return_value = (b'Google', b'')
    id_path.return_value = data_path + 'framework_info'
    plugin.return_value = True
    srvargs.return_value = 'regionHint=us-central1-d'
    assert False == utils.has_region_changed(cfg)


@patch('cloudregister.registerutils.__get_system_mfg')
@patch('cloudregister.registerutils.__get_framework_plugin')
def test_has_region_changed_no_dmidecode(plugin, mfg):
    plugin.return_value = False
    mfg.return_value = False
    assert False == utils.has_region_changed(cfg)


@patch('cloudregister.registerutils.__get_system_mfg')
@patch('cloudregister.registerutils.__get_framework_plugin')
def test_has_region_changed_no_plugin(plugin, mfg):
    plugin.return_value = False
    mfg.return_value = 'Google'
    assert False == utils.has_region_changed(cfg)


@patch('cloudregister.registerutils.__get_region_server_args')
@patch('cloudregister.registerutils.__get_framework_plugin')
@patch('cloudregister.registerutils.get_framework_identifier_path')
@patch('cloudregister.registerutils.exec_subprocess')
def test_has_region_changed_provider_change(subproc, id_path, plugin, srvargs):
    subproc.return_value = (b'Amazon EC2', b'')
    id_path.return_value = data_path + 'framework_info'
    plugin.return_value = True
    srvargs.return_value = 'regionHint=us-central1-d'
    assert True == utils.has_region_changed(cfg)


@patch('cloudregister.registerutils.__get_region_server_args')
@patch('cloudregister.registerutils.__get_framework_plugin')
@patch('cloudregister.registerutils.get_framework_identifier_path')
@patch('cloudregister.registerutils.exec_subprocess')
def test_has_region_changed_provider_and_region_change(
        subproc, id_path, plugin, srvargs
):
    subproc.return_value = (b'Amazon EC2', b'')
    id_path.return_value = data_path + 'framework_info'
    plugin.return_value = True
    srvargs.return_value = 'regionHint=us-east-1'
    assert True == utils.has_region_changed(cfg)


@patch('cloudregister.registerutils.__get_region_server_args')
@patch('cloudregister.registerutils.__get_framework_plugin')
@patch('cloudregister.registerutils.get_framework_identifier_path')
@patch('cloudregister.registerutils.exec_subprocess')
def test_has_region_changed_region_change(
        subproc, id_path, plugin, srvargs
):
    subproc.return_value = (b'Google', b'')
    id_path.return_value = data_path + 'framework_info'
    plugin.return_value = True
    srvargs.return_value = 'regionHint=us-east2-f'
    assert True == utils.has_region_changed(cfg)


def test_is_registration_supported_SUSE_Family():
    cfg.set('service', 'packageBackend', 'zypper')
    assert utils.is_registration_supported(cfg) is True


def test_is_registration_supported_RHEL_Family():
    cfg.set('service', 'packageBackend', 'dnf')
    assert utils.is_registration_supported(cfg) is False


def test_has_rmt_in_hosts_has_ipv4():
    hosts_content = """
    # simulates hosts file containing the ipv4 we are looking for in the test

    1.1.1.1   smt-foo.susecloud.net  smt-foo
    """
    server = MockServer()
    with mock.patch('builtins.open', mock.mock_open(read_data=hosts_content)):
        has_entry = utils.has_rmt_in_hosts(server)

    assert True == has_entry


def test_has_rmt_in_hosts_has_ipv4_6():
    hosts_content = """
    # simulates hosts file containing the ipv4 and iv6 we are looking for
    # in the test

    1.1.1.1   smt-foo.susecloud.net  smt-foo
    11:22:33:44::00   smt-foo.susecloud.net  smt-foo
    """
    server = MockServer()
    with mock.patch('builtins.open', mock.mock_open(read_data=hosts_content)):
        has_entry = utils.has_rmt_in_hosts(server)

    assert True == has_entry


def test_has_rmt_in_hosts_ipv4_not_found():
    hosts_content = """
    # simulates hosts file containing a different ipv4

    2.1.1.1   smt-foo.susecloud.net  smt-foo
    """
    server = MockServer()
    with mock.patch('builtins.open', mock.mock_open(read_data=hosts_content)):
        has_entry = utils.has_rmt_in_hosts(server)

    assert False == has_entry


def test_has_rmt_in_hosts_has_ipv6():
    hosts_content = """
    # simulates hosts file containing the ipv6 we are looking for in the test

    11:22:33:44::00   smt-foo.susecloud.net  smt-foo
    """
    server = MockServer()
    with mock.patch('builtins.open', mock.mock_open(read_data=hosts_content)):
        has_entry = utils.has_rmt_in_hosts(server)

    assert True == has_entry


def test_has_rmt_in_hosts_has_ipv6_4():
    hosts_content = """
    # simulates hosts file containing the ipv4 and iv6 we are looking for
    # in the test

    11:22:33:44::00   smt-foo.susecloud.net  smt-foo
    1.1.1.1   smt-foo.susecloud.net  smt-foo
    """
    server = MockServer()
    with mock.patch('builtins.open', mock.mock_open(read_data=hosts_content)):
        has_entry = utils.has_rmt_in_hosts(server)

    assert True == has_entry


def test_has_rmt_in_hosts_ipv6_not_found():
    hosts_content = """
    # simulates hosts file containing the ipv6 we are looking for in the test

    22:22:33:44::00   smt-foo.susecloud.net  smt-foo
    """
    server = MockServer()
    with mock.patch('builtins.open', mock.mock_open(read_data=hosts_content)):
        has_entry = utils.has_rmt_in_hosts(server)

    assert False == has_entry


def test_clean_host_file_no_empty_bottom_lines():
    hosts_content = """
# simulates hosts file containing the ipv6 we are looking for in the test

1.2.3.4   smt-foo.susecloud.net  smt-foo

# Added by SMT, please, do NOT remove this line
2.3.4.5   smt-entry.susecloud.net smt-entry

4.3.2.1   another_entry.whatever.com another_entry"""
    expected_cleaned_hosts = """
# simulates hosts file containing the ipv6 we are looking for in the test

1.2.3.4   smt-foo.susecloud.net  smt-foo


4.3.2.1   another_entry.whatever.com another_entry"""
    with mock.patch('builtins.open', mock.mock_open(read_data=hosts_content.encode())) as m:  # noqa: E501
        utils.clean_hosts_file('smt-entry'.encode())

    expected_write_calls = []
    expected_lines = expected_cleaned_hosts.split('\n')
    for line in expected_lines[:-1]:
        line = line + '\n'
        expected_write_calls.append(call(line.encode()))
    if expected_lines[-1] != '':
        expected_write_calls.append(call(expected_lines[-1].encode()))

    expected_write_calls.append(call(b'\n'))

    assert m().write.mock_calls == expected_write_calls


def test_clean_host_file_one_empty_bottom_line():
    hosts_content = """
# simulates hosts file containing the ipv6 we are looking for in the test

1.2.3.4   smt-foo.susecloud.net  smt-foo

# Added by SMT, please, do NOT remove this line
2.3.4.5   smt-entry.susecloud.net smt-entry

4.3.2.1   another_entry.whatever.com another_entry
"""
    expected_cleaned_hosts = """
# simulates hosts file containing the ipv6 we are looking for in the test

1.2.3.4   smt-foo.susecloud.net  smt-foo


4.3.2.1   another_entry.whatever.com another_entry
"""
    with mock.patch('builtins.open', mock.mock_open(read_data=hosts_content.encode())) as m:  # noqa: E501
        utils.clean_hosts_file('smt-entry'.encode())

    expected_write_calls = []
    expected_lines = expected_cleaned_hosts.split('\n')
    for line in expected_lines[:-1]:
        line = line + '\n'
        expected_write_calls.append(call(line.encode()))
    if expected_lines[-1] != '':
        expected_write_calls.append(call(expected_lines[-1].encode()))

    expected_write_calls.append(call(b'\n'))

    assert m().write.mock_calls == expected_write_calls


def test_clean_host_file_some_empty_bottom_lines():
    hosts_content = """
# simulates hosts file containing the ipv6 we are looking for in the test

1.2.3.4   smt-foo.susecloud.net  smt-foo

# Added by SMT, please, do NOT remove this line
2.3.4.5   smt-entry.susecloud.net smt-entry

4.3.2.1   another_entry.whatever.com another_entry



"""
    expected_cleaned_hosts = """
# simulates hosts file containing the ipv6 we are looking for in the test

1.2.3.4   smt-foo.susecloud.net  smt-foo


4.3.2.1   another_entry.whatever.com another_entry
"""
    with mock.patch('builtins.open', mock.mock_open(read_data=hosts_content.encode())) as m:  # noqa: E501
        utils.clean_hosts_file('smt-entry'.encode())

    expected_write_calls = []
    expected_lines = expected_cleaned_hosts.split('\n')
    for line in expected_lines[:-1]:
        line = line + '\n'
        expected_write_calls.append(call(line.encode()))
    if expected_lines[-1] != '':
        expected_write_calls.append(call(expected_lines[-1].encode()))

    expected_write_calls.append(call(b'\n'))

    assert m().write.mock_calls == expected_write_calls


def test_clean_host_file_some_empty_bottom_lines_smt_entry_is_last():
    hosts_content = """
# simulates hosts file containing the ipv6 we are looking for in the test

1.2.3.4   smt-foo.susecloud.net  smt-foo


4.3.2.1   another_entry.whatever.com another_entry

# Added by SMT, please, do NOT remove this line
2.3.4.5   smt-entry.susecloud.net smt-entry



"""
    expected_cleaned_hosts = """
# simulates hosts file containing the ipv6 we are looking for in the test

1.2.3.4   smt-foo.susecloud.net  smt-foo


4.3.2.1   another_entry.whatever.com another_entry
"""

    with mock.patch('builtins.open', mock.mock_open(read_data=hosts_content.encode())) as m:  # noqa: E501
        utils.clean_hosts_file('smt-entry'.encode())

    expected_write_calls = []
    expected_lines = expected_cleaned_hosts.split('\n')
    for line in expected_lines[:-1]:
        line = line + '\n'
        expected_write_calls.append(call(line.encode()))
    if expected_lines[-1] != '':
        expected_write_calls.append(call(expected_lines[-1].encode()))

    expected_write_calls.append(call(b'\n'))

    assert m().write.mock_calls == expected_write_calls


def test_clean_host_file_one_empty_bottom_lines_smt_entry_is_last():
    hosts_content = """
# simulates hosts file containing the ipv6 we are looking for in the test

1.2.3.4   smt-foo.susecloud.net  smt-foo


4.3.2.1   another_entry.whatever.com another_entry

# Added by SMT, please, do NOT remove this line
2.3.4.5   smt-entry.susecloud.net smt-entry

"""
    expected_cleaned_hosts = """
# simulates hosts file containing the ipv6 we are looking for in the test

1.2.3.4   smt-foo.susecloud.net  smt-foo


4.3.2.1   another_entry.whatever.com another_entry
"""

    with mock.patch('builtins.open', mock.mock_open(read_data=hosts_content.encode())) as m:  # noqa: E501
        utils.clean_hosts_file('smt-entry'.encode())

    expected_write_calls = []
    expected_lines = expected_cleaned_hosts.split('\n')
    for line in expected_lines[:-1]:
        line = line + '\n'
        expected_write_calls.append(call(line.encode()))
    if expected_lines[-1] != '':
        expected_write_calls.append(call(expected_lines[-1].encode()))

    expected_write_calls.append(call(b'\n'))

    assert m().write.mock_calls == expected_write_calls


def test_clean_host_file_no_empty_bottom_lines_smt_entry_is_last():
    hosts_content = """
# simulates hosts file containing the ipv6 we are looking for in the test

1.2.3.4   smt-foo.susecloud.net  smt-foo


4.3.2.1   another_entry.whatever.com another_entry

# Added by SMT, please, do NOT remove this line
2.3.4.5   smt-entry.susecloud.net smt-entry"""
    expected_cleaned_hosts = """
# simulates hosts file containing the ipv6 we are looking for in the test

1.2.3.4   smt-foo.susecloud.net  smt-foo


4.3.2.1   another_entry.whatever.com another_entry
"""
    with mock.patch('builtins.open', mock.mock_open(read_data=hosts_content.encode())) as m:  # noqa: E501
        utils.clean_hosts_file('smt-entry'.encode())

    expected_write_calls = []
    expected_lines = expected_cleaned_hosts.split('\n')
    for line in expected_lines[:-1]:
        line = line + '\n'
        expected_write_calls.append(call(line.encode()))
    if expected_lines[-1] != '':
        expected_write_calls.append(call(expected_lines[-1].encode()))

    expected_write_calls.append(call(b'\n'))

    assert m().write.mock_calls == expected_write_calls


# ---------------------------------------------------------------------------
# Helper functions

def get_servers_data():
    """The XML data matching the data pickled server objects"""
    srv_xml = """<regionSMTdata>\n
        <smtInfo
            SMTserverIP="107.22.231.220"
            SMTserverName="smt-ec2.susecloud.net"
            fingerprint=
            "9E:B5:BD:DA:97:52:DA:55:F0:F2:5D:5C:64:60:D3:E0:5C:D4:FB:79"/>\n
        <smtInfo
            SMTserverIP="54.197.240.216"
            SMTserverName="smt-ec2.susecloud.net"
            fingerprint=
            "9E:B5:BD:DA:97:52:DA:55:F0:F2:5D:5C:64:60:D3:E0:5C:D4:FB:79"/>\n
        <smtInfo
            SMTserverIP="54.225.105.144"
            SMTserverName="smt-ec2.susecloud.net"
            fingerprint=
            "9E:B5:BD:DA:97:52:DA:55:F0:F2:5D:5C:64:60:D3:E0:5C:D4:FB:79"/>\n
    </regionSMTdata>
    """

    return etree.fromstring(srv_xml)


def get_modified_servers_data():
    """The XML with 1 server different than the data pickled server objects"""
    srv_xml = """<regionSMTdata>\n
        <smtInfo
            SMTserverIP="107.22.231.220"
            SMTserverName="smt-ec2.susecloud.net"
            fingerprint=
            "99:88:77:66"/>\n
        <smtInfo
            SMTserverIP="54.197.240.216"
            SMTserverName="smt-ec2.susecloud.net"
            fingerprint=
            "9E:B5:BD:DA:97:52:DA:55:F0:F2:5D:5C:64:60:D3:E0:5C:D4:FB:79"/>\n
        <smtInfo
            SMTserverIP="54.225.105.144"
            SMTserverName="smt-ec2.susecloud.net"
            fingerprint=
            "9E:B5:BD:DA:97:52:DA:55:F0:F2:5D:5C:64:60:D3:E0:5C:D4:FB:79"/>\n
    </regionSMTdata>
    """

    return etree.fromstring(srv_xml)


class MockServer:
    def get_ipv4(self):
        return '1.1.1.1'

    def get_ipv6(self):
        return '11:22:33:44::00'
