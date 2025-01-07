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

import configparser
import inspect
import io
import json
import os
import pickle
import requests
import sys
import tempfile
import toml
import yaml
from collections import namedtuple
from pytest import raises
from textwrap import dedent

from unittest.mock import patch, call, MagicMock, Mock, mock_open
from lxml import etree

test_path = os.path.abspath(
    os.path.dirname(inspect.getfile(inspect.currentframe())))
code_path = os.path.abspath('%s/../lib' % test_path)
data_path = test_path + os.sep + 'data/'

sys.path.insert(0, code_path)

import cloudregister.registerutils as utils # noqa
from cloudregister.smt import SMT # noqa

CACHE_SERVER_IPS = ['54.197.240.216', '54.225.105.144', '107.22.231.220']


def test_get_profile_env_var():
    assert utils.get_profile_env_var(
        'some', '{0}/some_env'.format(data_path)
    ) == 'data'


@patch('os.path.exists')
def test_is_registry_registered(mock_os_path_exists):
    mock_os_path_exists.return_value = True
    utils.HOSTSFILE_PATH = '{0}/hosts'.format(data_path)
    utils.PROFILE_LOCAL_PATH = '{0}/some_env'.format(data_path)
    # some.box is in the hosts file and REGISTRY_AUTH_FILE is correct
    assert utils.is_registry_registered('some.box') is True

    # REGISTRY_AUTH_FILE does not exist
    mock_os_path_exists.return_value = False
    assert utils.is_registry_registered('some.box') is False
    mock_os_path_exists.return_value = True

    # some is not in the hosts file
    assert utils.is_registry_registered('some') is False

    utils.PROFILE_LOCAL_PATH = '{0}/some_invalid_env'.format(data_path)
    # some.box is in the hosts file but REGISTRY_AUTH_FILE is bogus
    assert utils.is_registry_registered('some.box') is False

    utils.HOSTSFILE_PATH = '/etc/hosts'
    utils.PROFILE_LOCAL_PATH = '/etc/profile.local'


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


@patch('cloudregister.registerutils.get_zypper_command')
def test_get_zypper_target_root_no_zypper(zypp_cmd):
    """Test behavior when zypper is not running"""
    zypp_cmd.return_value = None
    assert utils.get_zypper_target_root() == ''


@patch('cloudregister.registerutils.get_zypper_command')
def test_get_zypper_target_root_set_R_short(zypp_cmd):
    """Test behavior when zypper is "running" and has root set using -R and no
       other args"""
    zypp_cmd.return_value = '-R /foobar'
    assert utils.get_zypper_target_root() == '/foobar'


@patch('cloudregister.registerutils.get_zypper_command')
def test_get_zypper_target_root_set_R_long(zypp_cmd):
    """Test behavior when zypper is "running" and has root set using -R and
       other args"""
    zypp_cmd.return_value = '-R /foobar --no-interactive'
    assert utils.get_zypper_target_root() == '/foobar'


@patch('cloudregister.registerutils.get_zypper_command')
def test_get_zypper_target_root_set_root_short(zypp_cmd):
    """Test behavior when zypper is "running" and has root set using --root
       and no other args"""
    zypp_cmd.return_value = '--root /foobar'
    assert utils.get_zypper_target_root() == '/foobar'


@patch('cloudregister.registerutils.get_zypper_command')
def test_get_zypper_target_root_set_root_long(zypp_cmd):
    """Test behavior when zypper is "running" and has root set using --root
       and other args"""
    zypp_cmd.return_value = '--root /foobar --no-interactive'
    assert utils.get_zypper_target_root() == '/foobar'


@patch('cloudregister.registerutils.__get_region_server_args')
@patch('cloudregister.registerutils.__get_framework_plugin')
@patch('cloudregister.registerutils.get_framework_identifier_path')
@patch('cloudregister.registerutils.exec_subprocess')
def test_has_region_changed_no_change(subproc, id_path, plugin, srvargs):
    subproc.return_value = (b'Google', b'', 0)
    id_path.return_value = data_path + 'framework_info'
    plugin.return_value = True
    srvargs.return_value = 'regionHint=us-central1-d'
    cfg = get_test_config()
    assert utils.has_region_changed(cfg) is False


@patch('cloudregister.registerutils.__get_system_mfg')
@patch('cloudregister.registerutils.__get_framework_plugin')
def test_has_region_changed_no_dmidecode(plugin, mfg):
    plugin.return_value = False
    mfg.return_value = False
    cfg = get_test_config()
    assert utils.has_region_changed(cfg) is False


@patch('cloudregister.registerutils.__get_system_mfg')
@patch('cloudregister.registerutils.__get_framework_plugin')
def test_has_region_changed_no_plugin(plugin, mfg):
    plugin.return_value = False
    mfg.return_value = 'Google'
    cfg = get_test_config()
    assert utils.has_region_changed(cfg) is False


@patch('cloudregister.registerutils.__get_region_server_args')
@patch('cloudregister.registerutils.__get_framework_plugin')
@patch('cloudregister.registerutils.get_framework_identifier_path')
@patch('cloudregister.registerutils.exec_subprocess')
def test_has_region_changed_provider_change(subproc, id_path, plugin, srvargs):
    cfg = get_test_config()
    subproc.return_value = (b'Amazon EC2', b'', 0)
    id_path.return_value = data_path + 'framework_info'
    plugin.return_value = True
    srvargs.return_value = 'regionHint=us-central1-d'
    assert utils.has_region_changed(cfg) is True


@patch('cloudregister.registerutils.__get_region_server_args')
@patch('cloudregister.registerutils.__get_framework_plugin')
@patch('cloudregister.registerutils.get_framework_identifier_path')
@patch('cloudregister.registerutils.exec_subprocess')
def test_has_region_changed_provider_and_region_change(
        subproc, id_path, plugin, srvargs
):
    subproc.return_value = (b'Amazon EC2', b'', 0)
    id_path.return_value = data_path + 'framework_info'
    plugin.return_value = True
    srvargs.return_value = 'regionHint=us-east-1'
    cfg = get_test_config()
    assert utils.has_region_changed(cfg) is True


@patch('cloudregister.registerutils.__get_region_server_args')
@patch('cloudregister.registerutils.__get_framework_plugin')
@patch('cloudregister.registerutils.get_framework_identifier_path')
@patch('cloudregister.registerutils.exec_subprocess')
def test_has_region_changed_region_change(
        subproc, id_path, plugin, srvargs
):
    subproc.return_value = (b'Google', b'', 0)
    id_path.return_value = data_path + 'framework_info'
    plugin.return_value = True
    srvargs.return_value = 'regionHint=us-east2-f'
    cfg = get_test_config()
    assert utils.has_region_changed(cfg) is True


@patch('cloudregister.registerutils.json.loads')
@patch('cloudregister.registerutils.__get_region_server_args')
@patch('cloudregister.registerutils.__get_framework_plugin')
@patch('cloudregister.registerutils.get_framework_identifier_path')
@patch('cloudregister.registerutils.exec_subprocess')
def test_has_region_changed_provider_and_region_change_exception(
    mock_subproc,
    mock_id_path,
    mock_plugin,
    mock_srvargs,
    mock_json_loads
):
    mock_subproc.return_value = (b'Amazon EC2', b'', 0)
    mock_id_path.return_value = data_path + 'framework_info'
    mock_plugin.return_value = True
    mock_srvargs.return_value = 'regionHint=us-east-1'
    mock_srvargs.return_value = 'regionHint=us-east-1'
    mock_json_loads.side_effect = Exception('foo')
    cfg = get_test_config()
    assert utils.has_region_changed(cfg) is False


def test_is_registration_supported_SUSE_Family():
    cfg = get_test_config()
    cfg.add_section('service')
    cfg.set('service', 'packageBackend', 'zypper')
    assert utils.is_registration_supported(cfg) is True


def test_is_registration_supported_RHEL_Family():
    cfg = get_test_config()
    cfg.add_section('service')
    cfg.set('service', 'packageBackend', 'dnf')
    assert utils.is_registration_supported(cfg) is False


def test_has_rmt_in_hosts():
    utils.HOSTSFILE_PATH = '{0}/hosts'.format(data_path)
    server = Mock()

    # The following entry is expected to be found
    server.get_FQDN = Mock(return_value='smt-foo.susecloud.net')
    assert utils.has_rmt_in_hosts(server) is True

    # The following entry is expected to be not found
    server.get_FQDN = Mock(return_value='bogus')
    assert utils.has_rmt_in_hosts(server) is False

    utils.HOSTSFILE_PATH = '/etc/hosts'


def test_has_registry_in_hosts():
    utils.HOSTSFILE_PATH = '{0}/hosts'.format(data_path)
    server = Mock()

    # The following entry is expected to be found
    server.get_registry_FQDN = Mock(return_value='registry-foo.susecloud.net')
    assert utils.has_registry_in_hosts(server) is True

    # The following entry is expected to be not found
    server.get_registry_FQDN = Mock(return_value='bogus')
    assert utils.has_registry_in_hosts(server) is False

    utils.HOSTSFILE_PATH = '/etc/hosts'


def test_clean_host_file_no_empty_bottom_lines():
    hosts_content = """
# simulates hosts file containing the ipv6 we are looking for in the test

1.2.3.4   smt-foo.susecloud.net  smt-foo

# Added by SMT, please, do NOT remove this line
2.3.4.5   smt-entry.susecloud.net smt-entry
2.3.4.5   registry-entry.susecloud.net

4.3.2.1   another_entry.whatever.com another_entry"""
    expected_cleaned_hosts = """
# simulates hosts file containing the ipv6 we are looking for in the test

1.2.3.4   smt-foo.susecloud.net  smt-foo


4.3.2.1   another_entry.whatever.com another_entry"""
    with patch('builtins.open', mock_open(read_data=hosts_content.encode())) as m:  # noqa: E501
        utils.clean_hosts_file('susecloud.net')

    expected_write_calls = []
    expected_lines = expected_cleaned_hosts.split('\n')
    for line in expected_lines[:-1]:
        line = line + '\n'
        expected_write_calls.append(call(line.encode()))
    if expected_lines[-1] != '':
        expected_write_calls.append(call(expected_lines[-1].encode()))

    expected_write_calls.append(call(b'\n'))

    assert m().write.mock_calls == expected_write_calls


def test_clean_host_file_no_empty_bottom_lines_user_interfered():
    hosts_content = """
# simulates hosts file containing the ipv6 we are looking for in the test

1.2.3.4   smt-foo.susecloud.net  smt-foo

# Added by SMT, please, do NOT remove this line
2.3.4.5   smt-entry.susecloud.net smt-entry
1.1.1.1   my.specialhost.us
2.3.4.5   registry-entry.susecloud.net

4.3.2.1   another_entry.whatever.com another_entry"""
    expected_cleaned_hosts = """
# simulates hosts file containing the ipv6 we are looking for in the test

1.2.3.4   smt-foo.susecloud.net  smt-foo

1.1.1.1   my.specialhost.us

4.3.2.1   another_entry.whatever.com another_entry"""
    with patch('builtins.open', mock_open(read_data=hosts_content.encode())) as m:  # noqa: E501
        utils.clean_hosts_file('susecloud.net')

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
2.3.4.5   registry-entry.susecloud.net

4.3.2.1   another_entry.whatever.com another_entry
"""
    expected_cleaned_hosts = """
# simulates hosts file containing the ipv6 we are looking for in the test

1.2.3.4   smt-foo.susecloud.net  smt-foo


4.3.2.1   another_entry.whatever.com another_entry
"""
    with patch('builtins.open', mock_open(read_data=hosts_content.encode())) as m:  # noqa: E501
        utils.clean_hosts_file('susecloud.net'.encode())

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
2.3.4.5   registry-entry.susecloud.net

4.3.2.1   another_entry.whatever.com another_entry



"""
    expected_cleaned_hosts = """
# simulates hosts file containing the ipv6 we are looking for in the test

1.2.3.4   smt-foo.susecloud.net  smt-foo


4.3.2.1   another_entry.whatever.com another_entry
"""
    with patch('builtins.open', mock_open(read_data=hosts_content.encode())) as m:  # noqa: E501
        utils.clean_hosts_file('susecloud.net'.encode())

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
2.3.4.5   registry-entry.susecloud.net


"""
    expected_cleaned_hosts = """
# simulates hosts file containing the ipv6 we are looking for in the test

1.2.3.4   smt-foo.susecloud.net  smt-foo


4.3.2.1   another_entry.whatever.com another_entry
"""
    with patch('builtins.open', mock_open(read_data=hosts_content.encode())) as m:  # noqa: E501
        utils.clean_hosts_file('susecloud.net'.encode())

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
2.3.4.5   registry-entry.susecloud.net

"""
    expected_cleaned_hosts = """
# simulates hosts file containing the ipv6 we are looking for in the test

1.2.3.4   smt-foo.susecloud.net  smt-foo


4.3.2.1   another_entry.whatever.com another_entry
"""

    with patch('builtins.open', mock_open(read_data=hosts_content.encode())) as m:  # noqa: E501
        utils.clean_hosts_file('susecloud.net'.encode())

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
2.3.4.5   smt-entry.susecloud.net smt-entry
2.3.4.5   registry-entry.susecloud.net"""
    expected_cleaned_hosts = """
# simulates hosts file containing the ipv6 we are looking for in the test

1.2.3.4   smt-foo.susecloud.net  smt-foo


4.3.2.1   another_entry.whatever.com another_entry
"""
    with patch('builtins.open', mock_open(read_data=hosts_content.encode())) as m:  # noqa: E501
        utils.clean_hosts_file('susecloud.net'.encode())

    expected_write_calls = []
    expected_lines = expected_cleaned_hosts.split('\n')
    for line in expected_lines[:-1]:
        line = line + '\n'
        expected_write_calls.append(call(line.encode()))
    if expected_lines[-1] != '':
        expected_write_calls.append(call(expected_lines[-1].encode()))

    expected_write_calls.append(call(b'\n'))

    assert m().write.mock_calls == expected_write_calls


def test_clean_host_file_some_empty_bottom_lines_only_FQDN_not_registry():
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
    with patch('builtins.open', mock_open(read_data=hosts_content.encode())) as m:  # noqa: E501
        utils.clean_hosts_file('susecloud.net'.encode())

    expected_write_calls = []
    expected_lines = expected_cleaned_hosts.split('\n')
    for line in expected_lines[:-1]:
        line = line + '\n'
        expected_write_calls.append(call(line.encode()))
    if expected_lines[-1] != '':
        expected_write_calls.append(call(expected_lines[-1].encode()))
    expected_write_calls.append(call(b'\n'))
    assert m().write.mock_calls == expected_write_calls


def test_clean_host_file_raised_exception():
    hosts_content = ""
    with patch('builtins.open', mock_open(read_data=hosts_content.encode())) as m:  # noqa: E501
        utils.clean_hosts_file('susecloud.net')

    assert m().write.mock_calls == []


@patch('cloudregister.registerutils.has_rmt_ipv6_access')
def test_add_hosts_entry(mock_has_rmt_ipv6_access):
    """Test hosts entry has a new entry added by us."""
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="fantasy.example.com"
         SMTregistryName="registry-fantasy.example.com"
         region="antarctica-1"/>''')

    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_has_rmt_ipv6_access.return_value = True
    with patch('builtins.open', create=True) as mock_open:
        mock_open.return_value = MagicMock(spec=io.IOBase)
        file_handle = mock_open.return_value.__enter__.return_value
        utils.add_hosts_entry(smt_server)
    mock_open.assert_called_once_with('/etc/hosts', 'a')
    file_content_comment = (
        '\n# Added by SMT registration do not remove, '
        'retain comment as well\n'
    )
    file_content_entry = (
        '{ip}\t{fqdn}\t{name}\n{ip_reg}\t{reg_name}\n'.format(
            ip=smt_server.get_ipv6(),
            fqdn=smt_server.get_FQDN(),
            name=smt_server.get_name(),
            ip_reg=smt_server.get_ipv6(),
            reg_name=smt_server.get_registry_FQDN()
        )
    )
    assert file_handle.write.mock_calls == [
        call(file_content_comment),
        call(file_content_entry)
    ]


@patch('cloudregister.registerutils.has_rmt_ipv6_access')
def test_add_hosts_entry_no_registry(mock_has_rmt_ipv6_access):
    """Test hosts entry has a new entry added by us."""
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="fantasy.example.com"
         region="antarctica-1"/>''')

    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_has_rmt_ipv6_access.return_value = True
    with patch('builtins.open', create=True) as mock_open:
        mock_open.return_value = MagicMock(spec=io.IOBase)
        file_handle = mock_open.return_value.__enter__.return_value
        utils.add_hosts_entry(smt_server)
    mock_open.assert_called_once_with('/etc/hosts', 'a')
    file_content_comment = (
        '\n# Added by SMT registration do not remove, '
        'retain comment as well\n'
    )
    file_content_entry = (
        '{ip}\t{fqdn}\t{name}\n'.format(
            ip=smt_server.get_ipv6(),
            fqdn=smt_server.get_FQDN(),
            name=smt_server.get_name(),
        )
    )
    assert file_handle.write.mock_calls == [
        call(file_content_comment),
        call(file_content_entry)
    ]


@patch('cloudregister.registerutils.has_rmt_ipv6_access')
def test_add_hosts_entry_registry_optional_empty(mock_has_ipv6_access):
    """Test hosts entry has a new entry added by us."""
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="fantasy.example.com"
         SMTregistryName=""
         region="antarctica-1"/>''')

    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_has_ipv6_access.return_value = True
    with patch('builtins.open', create=True) as mock_open:
        mock_open.return_value = MagicMock(spec=io.IOBase)
        file_handle = mock_open.return_value.__enter__.return_value
        utils.add_hosts_entry(smt_server)
        mock_open.assert_called_once_with('/etc/hosts', 'a')
        file_content_comment = (
            '\n# Added by SMT registration do not remove, '
            'retain comment as well\n'
        )
        file_content_entry = (
            '{ip}\t{fqdn}\t{name}\n'.format(
                ip=smt_server.get_ipv6(),
                fqdn=smt_server.get_FQDN(),
                name=smt_server.get_name(),
            )
        )
        assert file_handle.write.mock_calls == [
             call(file_content_comment),
             call(file_content_entry)
        ]


@patch('cloudregister.amazonec2.generateRegionSrvArgs')
@patch('cloudregister.registerutils.__get_framework_plugin')
def test_add_region_server_args_to_URL(
    mock_get_framework_plugin,
    mock_generate_region_srv_args
):
    cfg = get_test_config()
    api = cfg.get('server', 'api')
    mock_get_framework_plugin.return_value = __import__(
        'cloudregister.amazonec2', fromlist=['']
    )
    mock_generate_region_srv_args.return_value = 'regionHint=eu-central-1'
    expected_args = 'regionInfo?regionHint=eu-central-1'
    assert utils.add_region_server_args_to_URL(api, cfg) == expected_args


@patch('cloudregister.registerutils.__get_framework_plugin')
def test_add_region_server_args_to_URL_no_module(mock_get_framework_plugin):
    cfg = get_test_config()
    mock_get_framework_plugin.return_value = None
    utils.add_region_server_args_to_URL(None, cfg)


@patch('cloudregister.registerutils.os.unlink')
@patch('cloudregister.registerutils.os.path.exists')
def test_clean_framework_identifier(
    mock_os_path_exists,
    mock_os_unlink
):
    utils.clean_framework_identifier()
    framework_info_path = '/var/cache/cloudregister/framework_info'
    mock_os_path_exists.assert_called_once_with(framework_info_path)
    mock_os_unlink.assert_called_once_with(framework_info_path)


@patch('cloudregister.registerutils.glob.glob')
@patch('cloudregister.registerutils.os.unlink')
def test_clean_smt_cache(mock_os_unlink, mock_glob):
    mock_glob.return_value = ['currentSMTInfo.obj']
    utils.clean_smt_cache()
    mock_os_unlink.assert_called_once_with('currentSMTInfo.obj')


@patch('cloudregister.registerutils.os.unlink')
def test_clear_new_reg_flag(mock_os_unlink):
    mock_os_unlink.side_effect = FileNotFoundError
    utils.clear_new_registration_flag()
    mock_os_unlink.assert_called_once_with(
        '/var/cache/cloudregister/newregistration'
    )


@patch('cloudregister.registerutils.os.unlink')
def test_clear_rmt_as_scc_proxy_flag(mock_os_unlink):
    mock_os_unlink.side_effect = FileNotFoundError
    utils.clear_rmt_as_scc_proxy_flag()
    mock_os_unlink.assert_called_once_with(
        '/var/cache/cloudregister/rmt_is_scc_proxy'
    )


@patch('cloudregister.registerutils.register_product')
@patch('cloudregister.registerutils.get_installed_products')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.get_credentials')
@patch('cloudregister.registerutils.get_product_tree')
@patch('cloudregister.registerutils.get_current_smt')
@patch('cloudregister.registerutils.requests.get')
def test_clean_non_free_extensions(
    mock_requests_get,
    mock_get_current_smt,
    mock_get_product_tree,
    mock_get_creds,
    mock_logging,
    mock_get_installed_products,
    mock_register_product
):
    mock_get_installed_products.return_value = ['SLES-LTSS/15.4/x86_64']
    response = Response()
    response.status_code = requests.codes.ok
    json_mock = Mock()
    json_mock.return_value = {
        'id': 2001,
        'name': 'SUSE Linux Enterprise Server',
        'identifier': 'SLES',
        'former_identifier': 'SLES',
        'version': '15.4',
        'release_type': None,
        'release_stage': 'released',
        'arch': 'x86_64',
        'friendly_name': 'SUSE Linux Enterprise Server 15 SP4 x86_64',
        'product_class': '30',
        'extensions': [
            {
                'id': 23,
                'name': 'SUSE Linux Enterprise Server LTSS',
                'identifier': 'SLES-LTSS',
                'former_identifier': 'SLES-LTSS',
                'version': '15.4',
                'release_type': None,
                'release_stage': 'released',
                'arch': 'x86_64',
                'friendly_name':
                'SUSE Linux Enterprise Server LTSS 15 SP4 x86_64',
                'product_class': 'SLES15-SP4-LTSS-X86',
                'free': False,
                'repositories': [],
                'product_type': 'extension',
                'extensions': [],
                'recommended': False,
                'available': True
            }
        ]
    }
    response.json = json_mock
    mock_requests_get.return_value = response
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="fantasy.example.com"
         SMTregistryName=""
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_current_smt.return_value = smt_server
    mock_get_creds.return_value = 'SCC_foo', 'bar'
    base_product = dedent('''\
        <?xml version="1.0" encoding="UTF-8"?>
        <product schemeversion="0">
          <vendor>SUSE</vendor>
          <name>SLES</name>
          <version>15.4</version>
          <baseversion>15</baseversion>
          <patchlevel>4</patchlevel>
          <release>0</release>
          <endoflife></endoflife>
          <arch>x86_64</arch></product>''')
    mock_get_product_tree.return_value = etree.fromstring(
        base_product[base_product.index('<product'):]
    )
    prod_reg_type = namedtuple(
        'prod_reg_type', ['returncode', 'output', 'error']
    )
    mock_register_product.return_value = prod_reg_type(
        returncode=0,
        output='all OK',
        error='stderr'
    )
    utils.clean_non_free_extensions()
    assert mock_register_product.call_args_list == [
        call(
            registration_target=smt_server,
            product='SLES-LTSS/15.4/x86_64',
            de_register=True
        )
    ]
    assert mock_logging.info.call_args_list == [
        call('No credentials entry for "*fantasy_example_com"'),
        call('No credentials entry for "SCC*"'),
        call('Non free extension SLES-LTSS/15.4/x86_64 removed')
    ]


@patch('cloudregister.registerutils.register_product')
@patch('cloudregister.registerutils.get_installed_products')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.get_credentials')
@patch('cloudregister.registerutils.get_product_tree')
@patch('cloudregister.registerutils.get_current_smt')
@patch('cloudregister.registerutils.requests.get')
def test_clean_non_free_extensions_failed(
    mock_requests_get,
    mock_get_current_smt,
    mock_get_product_tree,
    mock_get_creds,
    mock_logging,
    mock_get_installed_products,
    mock_register_product
):
    mock_get_installed_products.return_value = ['SLES-LTSS/15.4/x86_64']
    response = Response()
    response.status_code = requests.codes.ok
    json_mock = Mock()
    json_mock.return_value = {
        'id': 2001,
        'name': 'SUSE Linux Enterprise Server',
        'identifier': 'SLES',
        'former_identifier': 'SLES',
        'version': '15.4',
        'release_type': None,
        'release_stage': 'released',
        'arch': 'x86_64',
        'friendly_name': 'SUSE Linux Enterprise Server 15 SP4 x86_64',
        'product_class': '30',
        'extensions': [
            {
                'id': 23,
                'name': 'SUSE Linux Enterprise Server LTSS',
                'identifier': 'SLES-LTSS',
                'former_identifier': 'SLES-LTSS',
                'version': '15.4',
                'release_type': None,
                'release_stage': 'released',
                'arch': 'x86_64',
                'friendly_name':
                'SUSE Linux Enterprise Server LTSS 15 SP4 x86_64',
                'product_class': 'SLES15-SP4-LTSS-X86',
                'free': False,
                'repositories': [],
                'product_type': 'extension',
                'extensions': [],
                'recommended': False,
                'available': True
            }
        ]
    }
    response.json = json_mock
    mock_requests_get.return_value = response
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="fantasy.example.com"
         SMTregistryName=""
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_current_smt.return_value = smt_server
    mock_get_creds.return_value = 'SCC_foo', 'bar'
    base_product = dedent('''\
        <?xml version="1.0" encoding="UTF-8"?>
        <product schemeversion="0">
          <vendor>SUSE</vendor>
          <name>SLES</name>
          <version>15.4</version>
          <baseversion>15</baseversion>
          <patchlevel>4</patchlevel>
          <release>0</release>
          <endoflife></endoflife>
          <arch>x86_64</arch></product>''')
    mock_get_product_tree.return_value = etree.fromstring(
        base_product[base_product.index('<product'):]
    )
    prod_reg_type = namedtuple(
        'prod_reg_type', ['returncode', 'output', 'error']
    )
    mock_register_product.return_value = prod_reg_type(
        returncode=1,
        output='all OK',
        error='stderr'
    )
    utils.clean_non_free_extensions()
    assert mock_register_product.call_args_list == [
        call(
            registration_target=smt_server,
            product='SLES-LTSS/15.4/x86_64',
            de_register=True
        )
    ]
    assert mock_logging.info.call_args_list == [
        call('No credentials entry for "*fantasy_example_com"'),
        call('No credentials entry for "SCC*"'),
        call('Non free extension SLES-LTSS/15.4/x86_64 failed to be removed')
    ]


@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.os.unlink')
@patch('cloudregister.registerutils.get_credentials')
@patch('cloudregister.registerutils.get_product_tree')
@patch('cloudregister.registerutils.get_current_smt')
@patch('cloudregister.registerutils.requests.get')
def test_clean_non_free_extensions_request_failed(
    mock_requests_get,
    mock_get_current_smt,
    mock_get_product_tree,
    mock_get_creds,
    mock_os_unlink,
    mock_logging
):
    response = Response()
    response.status_code = requests.codes.forbidden
    response.reason = 'Because nope'
    response.content = str(json.dumps('no accessio')).encode()
    mock_requests_get.return_value = response
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="fantasy.example.com"
         SMTregistryName=""
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_current_smt.return_value = smt_server
    mock_get_creds.return_value = 'SCC_foo', 'bar'
    base_product = dedent('''\
        <?xml version="1.0" encoding="UTF-8"?>
        <product schemeversion="0">
          <vendor>SUSE</vendor>
          <name>SLES</name>
          <version>15.4</version>
          <baseversion>15</baseversion>
          <patchlevel>4</patchlevel>
          <release>0</release>
          <endoflife></endoflife>
          <arch>x86_64</arch></product>''')
    mock_get_product_tree.return_value = etree.fromstring(
        base_product[base_product.index('<product'):]
    )
    with raises(Exception):
        utils.clean_non_free_extensions()
    assert mock_os_unlink.mock_calls == []
    assert mock_logging.error.call_args_list == [
        call('No matching credentials file found'),
        call(
            'Unable to obtain product information '
            'from server "192.168.1.1,fc00::1"\n\tBecause nope\n\t'
            '"no accessio", exiting.'
        )
    ]


@patch('cloudregister.registerutils.os.unlink')
@patch('cloudregister.registerutils.get_credentials')
@patch('cloudregister.registerutils.get_product_tree')
@patch('cloudregister.registerutils.get_current_smt')
@patch('cloudregister.registerutils.requests.get')
def test_clean_non_free_extensions_no_credentials(
    mock_requests_get,
    mock_get_current_smt,
    mock_get_product_tree,
    mock_get_creds,
    mock_os_unlink
):
    mock_get_current_smt.return_value = None
    utils.clean_non_free_extensions()
    assert mock_os_unlink.mock_calls == []


@patch('cloudregister.registerutils.get_register_cmd')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.os.access')
@patch('cloudregister.registerutils.os.path.exists')
@patch('cloudregister.registerutils.subprocess.Popen')
def test_register_product_no_transactional_ok(
    mock_popen, mock_os_path_exists,
    mock_os_access, mock_logging,
    mock_get_register_cmd
):
    mock_os_path_exists.return_value = True
    mock_os_access.return_value = True
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="AA:BB:CC:DD"
         SMTserverIP="1.2.3.5"
         SMTserverIPv6="fc00::1"
         SMTserverName="foo-ec2.susecloud.net"
         SMTregistryName="registry-ec2.susecloud.net"
         region="antarctica-1"/>''')

    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_register_cmd.return_value = '/usr/sbin/SUSEConnect'
    expected_cmd = (
        'Registration: '
        '/usr/sbin/SUSEConnect '
        '--url https://foo-ec2.susecloud.net '
        '--product product '
        '--instance-data instance_data_filepath '
        '--email email '
        '--regcode XXXX'
    )
    mock_process = Mock()
    mock_process.communicate = Mock(
        return_value=[str.encode('OK'), str.encode('not_OK')]
    )
    mock_process.returncode = 0
    mock_popen.return_value = mock_process
    result = utils.register_product(
        smt_server, 'reg_code', 'email', 'instance_data_filepath', 'product'
    )
    prod_reg_type = namedtuple(
        'prod_reg_type', ['returncode', 'output', 'error']
    )
    assert result == prod_reg_type(
        returncode=0,
        output='OK',
        error='not_OK'
    )
    assert mock_logging.info.call_args_list == [call(expected_cmd)]


@patch('cloudregister.registerutils.get_register_cmd')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.os.access')
@patch('cloudregister.registerutils.os.path.exists')
@patch('cloudregister.registerutils.subprocess.Popen')
def test_register_product_no_transactional_de_register_ok(
    mock_popen, mock_os_path_exists,
    mock_os_access, mock_logging,
    mock_get_register_cmd
):
    mock_os_path_exists.return_value = True
    mock_os_access.return_value = True
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="AA:BB:CC:DD"
         SMTserverIP="1.2.3.5"
         SMTserverIPv6="fc00::1"
         SMTserverName="foo-ec2.susecloud.net"
         SMTregistryName="registry-ec2.susecloud.net"
         region="antarctica-1"/>''')

    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_register_cmd.return_value = '/usr/sbin/SUSEConnect'
    expected_cmd = (
        'Registration: '
        '/usr/sbin/SUSEConnect '
        '--url https://foo-ec2.susecloud.net '
        '--de-register '
        '--product product'
    )
    mock_process = Mock()
    mock_process.communicate = Mock(
        return_value=[str.encode('OK'), str.encode('not_OK')]
    )
    mock_process.returncode = 0
    mock_popen.return_value = mock_process
    result = utils.register_product(
        registration_target=smt_server,
        product='product',
        de_register=True
    )
    prod_reg_type = namedtuple(
        'prod_reg_type', ['returncode', 'output', 'error']
    )
    assert result == prod_reg_type(
        returncode=0,
        output='OK',
        error='not_OK'
    )
    assert mock_logging.info.call_args_list == [call(expected_cmd)]


@patch('cloudregister.registerutils.get_register_cmd')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.os.access')
@patch('cloudregister.registerutils.os.path.exists')
@patch('cloudregister.registerutils.subprocess.Popen')
def test_register_product_no_transactional_de_register_missing_product(
    mock_popen, mock_os_path_exists,
    mock_os_access, mock_logging,
    mock_get_register_cmd
):
    mock_os_path_exists.return_value = True
    mock_os_access.return_value = True
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="AA:BB:CC:DD"
         SMTserverIP="1.2.3.5"
         SMTserverIPv6="fc00::1"
         SMTserverName="foo-ec2.susecloud.net"
         SMTregistryName="registry-ec2.susecloud.net"
         region="antarctica-1"/>''')

    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_register_cmd.return_value = '/usr/sbin/SUSEConnect'
    mock_process = Mock()
    mock_process.communicate = Mock(
        return_value=[str.encode('OK'), str.encode('not_OK')]
    )
    mock_process.returncode = 0
    mock_popen.return_value = mock_process
    with raises(SystemExit) as sys_exit:
        utils.register_product(
            registration_target=smt_server,
            product='',
            de_register=True
        )
    assert sys_exit.value.code == 1
    print(mock_logging.error.call_args_list)
    assert mock_logging.error.call_args_list == [
        call('De-register the system is not allowed for SUSEConnect')
    ]


@patch('cloudregister.registerutils.get_register_cmd')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.os.access')
@patch('cloudregister.registerutils.os.path.exists')
@patch('cloudregister.registerutils.subprocess.Popen')
def test_register_product_transactional_ok(
    mock_popen, mock_os_path_exists,
    mock_os_access, mock_logging,
    mock_get_register_cmd
):
    mock_os_path_exists.return_value = True
    mock_os_access.return_value = True
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="AA:BB:CC:DD"
         SMTserverIP="1.2.3.5"
         SMTserverIPv6="fc00::1"
         SMTserverName="foo-ec2.susecloud.net"
         SMTregistryName="registry-ec2.susecloud.net"
         region="antarctica-1"/>''')

    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_register_cmd.return_value = '/usr/sbin/transactional'
    expected_cmd = (
        'Registration: '
        '/usr/sbin/transactional '
        'register --url https://foo-ec2.susecloud.net '
        '--product product '
        '--instance-data instance_data_filepath '
        '--email email '
        '--regcode XXXX'
    )
    mock_process = Mock()
    mock_process.communicate = Mock(
        return_value=[str.encode('OK'), str.encode('not_OK')]
    )
    mock_process.returncode = 0
    mock_popen.return_value = mock_process
    result = utils.register_product(
        smt_server, 'reg_code', 'email', 'instance_data_filepath', 'product'
    )
    prod_reg_type = namedtuple(
        'prod_reg_type', ['returncode', 'output', 'error']
    )
    assert result == prod_reg_type(
        returncode=0,
        output='OK',
        error='not_OK'
    )
    assert mock_logging.info.call_args_list == [call(expected_cmd)]


@patch('cloudregister.registerutils.get_register_cmd')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.os.access')
@patch('cloudregister.registerutils.os.path.exists')
@patch('cloudregister.registerutils.subprocess.Popen')
def test_register_product_no_exists(
    mock_popen, mock_os_path_exists,
    mock_os_access, mock_logging,
    mock_get_register_cmd
):
    mock_os_path_exists.return_value = False
    with raises(SystemExit) as sys_exit:
        utils.register_product('foo')
    assert sys_exit.value.code == 1
    assert mock_logging.error.call_args_list == [
        call('No registration executable found')
    ]


@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.subprocess.Popen')
def test_get_register_cmd_error(mock_popen, mock_logging):
    mock_process = Mock()
    mock_process.communicate = Mock(
        return_value=[str.encode(''), str.encode('')]
    )
    mock_process.returncode = 1
    mock_popen.return_value = mock_process
    assert utils.get_register_cmd() == '/usr/sbin/SUSEConnect'
    assert mock_logging.warning.call_args_list == [
        call('Unable to find filesystem information for "/"')
    ]


@patch('cloudregister.registerutils.os.path.exists')
@patch('cloudregister.registerutils.json.loads')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.subprocess.Popen')
def test_get_register_cmd_path_not_exist(
    mock_popen, mock_logging, mock_json_loads, mock_os_path_exists
):
    mock_process = Mock()
    mock_process.communicate = Mock(
        return_value=[str.encode(''), str.encode('')]
    )
    mock_process.returncode = 0
    mock_popen.return_value = mock_process
    mock_json_loads.return_value = {
        'filesystems': [
            {
                'target': '/',
                'source': '/dev/xvda3',
                'fstype': 'xfs',
                'options':
                'ro,relatime,attr2,inode64,logbufs=8,logbsize=32k,noquota'
            }
        ]
    }
    mock_os_path_exists.return_value = False
    with raises(SystemExit) as sys_exit:
        utils.get_register_cmd()
    assert sys_exit.value.code == 1
    assert mock_logging.error.call_args_list == [
        call(
            'transactional-update command not found. But is required on a RO '
            'filesystem for registration'
        )
    ]


@patch('cloudregister.registerutils.os.path.exists')
@patch('cloudregister.registerutils.json.loads')
@patch('cloudregister.registerutils.subprocess.Popen')
def test_get_register_cmd_ok(
    mock_popen, mock_json_loads, mock_os_path_exists
):
    mock_process = Mock()
    mock_process.communicate = Mock(
        return_value=[str.encode(''), str.encode('')]
    )
    mock_process.returncode = 0
    mock_popen.return_value = mock_process
    mock_json_loads.return_value = {
        'filesystems': [
            {
                'target': '/',
                'source': '/dev/xvda3',
                'fstype': 'xfs',
                'options':
                'ro,relatime,attr2,inode64,logbufs=8,logbsize=32k,noquota'
            }
        ]
    }
    mock_os_path_exists.return_value = True
    assert utils.get_register_cmd() == \
        '/sbin/transactional-update'


@patch('cloudregister.registerutils.os.path.exists')
@patch('cloudregister.registerutils.json.loads')
@patch('cloudregister.registerutils.subprocess.Popen')
def test_get_register_cmd_ok_not_transactional(
    mock_popen, mock_json_loads, mock_os_path_exists
):
    mock_process = Mock()
    mock_process.communicate = Mock(
        return_value=[str.encode(''), str.encode('')]
    )
    mock_process.returncode = 0
    mock_popen.return_value = mock_process
    mock_json_loads.return_value = {
        'filesystems': [
            {
                'target': '/',
                'source': '/dev/xvda3',
                'fstype': 'xfs',
                'options':
                'rw,relatime,attr2,inode64,logbufs=8,logbsize=32k,noquota'
            }
        ]
    }
    mock_os_path_exists.return_value = True
    assert utils.get_register_cmd() == '/usr/sbin/SUSEConnect'


@patch('cloudregister.registerutils.os.path.isfile')
def test_get_product_tree(mock_path_isfile):
    base_product = dedent('''\
        <?xml version="1.0" encoding="UTF-8"?>
        <product schemeversion="0">
          <vendor>SUSE</vendor>
          <name>SLES</name>
          <version>15.4</version>
          <baseversion>15</baseversion>
          <patchlevel>4</patchlevel>
          <release>0</release>
          <endoflife></endoflife>
          <arch>x86_64</arch></product>''')
    expected_tree = etree.fromstring(
        base_product[base_product.index('<product'):]
    )
    mock_path_isfile.return_value = True
    with patch('builtins.open', mock_open(read_data=base_product)):
        result = utils.get_product_tree()
        assert etree.tostring(result) == etree.tostring(expected_tree)


@patch('cloudregister.registerutils.get_credentials')
def test_credentials_files_are_equal(mock_get_credentials):
    mock_get_credentials.side_effect = [('SCC_foo', 'bar'), ('SCC_foo', 'bar')]
    assert utils.credentials_files_are_equal('foo') is True
    assert mock_get_credentials.mock_calls == [
        call('/etc/zypp/credentials.d/SCCcredentials'),
        call('/etc/zypp/credentials.d/foo')
    ]

    mock_get_credentials.side_effect = [('SCC_bar', 'bar'), ('SCC_foo', 'bar')]
    assert utils.credentials_files_are_equal('foo') is False


def test_credentials_files_are_equal_no_credentials():
    assert utils.credentials_files_are_equal(None) is False


def test_credentials_files_are_equal_no_valid_credentials():
    assert utils.credentials_files_are_equal('foo'.encode('utf-8')) is False
    assert utils.credentials_files_are_equal([]) is False
    assert utils.credentials_files_are_equal(['foo']) is False
    assert utils.credentials_files_are_equal('') is False


@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.exec_subprocess')
def test_enable_repository(mock_exec_subprocess, mock_logging):
    utils.enable_repository('super_repo')
    mock_exec_subprocess.assert_called_once_with(
        ['zypper', 'mr', '-e', 'super_repo']
    )
    assert mock_logging.error.called


def test_exec_subprocess_exception():
    assert utils.exec_subprocess(['aa']) == -1


@patch('cloudregister.registerutils.subprocess.Popen')
def test_exec_subprocess(mock_popen):
    mock_process = Mock()
    mock_process.communicate = Mock(
        return_value=[str.encode('stdout'), str.encode('stderr')]
    )
    mock_process.returncode = 1
    mock_popen.return_value = mock_process
    assert utils.exec_subprocess(['foo'], True) == (
        'stdout'.encode(), 'stderr'.encode(), 1
    )
    assert utils.exec_subprocess(['foo']) == 1


@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.requests.get')
def test_fetch_smt_data_not_200_exception(
    mock_request_get,
    mock_logging,
):
    cfg = get_test_config()
    response = Response()
    response.status_code = 422
    mock_request_get.return_value = response
    with raises(SystemExit):
        utils.fetch_smt_data(cfg, None)
    assert mock_logging.error.call_args_list == [
        call('===================='),
        call('Metadata server returned 422'),
        call('Unable to obtain update server information, exiting')
    ]


@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.requests.get')
def test_fetch_smt_data_no_response_text(
    mock_request_get,
    mock_logging,
):
    cfg = get_test_config()
    response = Response()
    response.status_code = 200
    response.text = "{}"
    mock_request_get.return_value = response
    with raises(SystemExit):
        utils.fetch_smt_data(cfg, None)
    assert mock_logging.error.call_args_list == [
        call('Metadata server did not supply a value for "fingerprint"'),
        call('Cannot proceed, exiting registration code')
    ]


@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.requests.get')
def test_fetch_smt_data_metadata_server(
    mock_request_get,
    mock_logging,
):
    cfg = get_test_config()
    response = Response()
    response.status_code = 200
    response.text = (
        '{"fingerprint":"foo","SMTserverIP":"bar","SMTserverName":"foobar"}'
    )
    mock_request_get.return_value = response
    smt_data_fetched = dedent('''\
    <regionSMTdata><smtInfo fingerprint="foo" SMTserverIP="bar" \
    SMTserverName="foobar" /></regionSMTdata>''')
    smt_server = etree.fromstring(smt_data_fetched)
    fetched_smt_data = utils.fetch_smt_data(cfg, None)
    assert etree.tostring(fetched_smt_data, encoding='utf-8') == \
        etree.tostring(smt_server, encoding='utf-8')


@patch('cloudregister.registerutils.has_network_access_by_ip_address')
@patch('cloudregister.registerutils.time.sleep')
@patch('cloudregister.registerutils.logging')
def test_fetch_smt_data_api_no_answer(
    mock_logging,
    mock_time_sleep,
    mock_has_network_access
):
    cfg = get_test_config()
    del cfg['server']['metadata_server']
    cfg.set('server', 'regionsrv', '1.1.1.1')
    with raises(SystemExit):
        utils.fetch_smt_data(cfg, None)
    mock_has_network_access.return_value = False
    assert mock_logging.info.call_args_list == [
        call('Using API: regionInfo'),
        call('Getting update server information, attempt 1'),
        call('\tUsing region server: 1.1.1.1'),
        call(
            '\tNo cert found: /usr/lib/regionService/certs/1.1.1.1.pem '
            'skip this server'
        ),
        call('Waiting 20 seconds before next attempt'),
        call('Getting update server information, attempt 2'),
        call('\tUsing region server: 1.1.1.1'),
        call(
            '\tNo cert found: /usr/lib/regionService/certs/1.1.1.1.pem '
            'skip this server'
        ),
        call('Waiting 10 seconds before next attempt'),
        call('Getting update server information, attempt 3'),
        call('\tUsing region server: 1.1.1.1'),
        call(
            '\tNo cert found: /usr/lib/regionService/certs/1.1.1.1.pem '
            'skip this server'
        )
    ]

    assert mock_logging.error.call_args_list == [
        call('Request not answered by any server after 3 attempts'),
        call('Exiting without registration')
    ]


@patch('cloudregister.registerutils.has_network_access_by_ip_address')
@patch('cloudregister.registerutils.requests.get')
@patch('cloudregister.registerutils.os.path.isfile')
@patch('cloudregister.registerutils.time.sleep')
@patch('cloudregister.registerutils.logging')
def test_fetch_smt_data_api_answered(
    mock_logging,
    mock_time_sleep,
    mock_os_path_isfile,
    mock_request_get,
    mock_has_network_access
):
    cfg = get_test_config()
    del cfg['server']['metadata_server']
    cfg.set('server', 'regionsrv', '1.1.1.1')
    mock_os_path_isfile.return_value = True
    response = Response()
    response.status_code = 200
    smt_xml = dedent('''\
    <regionSMTdata>
      <smtInfo fingerprint="99:88:77:66"
        SMTserverIP="1.2.3.4"
        SMTserverIPv6="fc11::2"
        SMTserverName="foo.susecloud.net"
        />
    </regionSMTdata>''')
    response.text = smt_xml
    mock_request_get.return_value = response
    mock_has_network_access.return_value = False
    utils.fetch_smt_data(cfg, None)
    assert mock_logging.info.call_args_list == [
        call('Using API: regionInfo'),
        call('Getting update server information, attempt 1'),
        call('\tUsing region server: 1.1.1.1'),
    ]


@patch('socket.create_connection')
@patch('cloudregister.registerutils.ipaddress.ip_address')
@patch('cloudregister.registerutils.requests.get')
@patch('cloudregister.registerutils.os.path.isfile')
@patch('cloudregister.registerutils.time.sleep')
@patch('cloudregister.registerutils.logging')
def test_fetch_smt_data_api_no_valid_ip(
    mock_logging,
    mock_time_sleep,
    mock_os_path_isfile,
    mock_request_get,
    mock_ipaddress_ip_address,
    mock_socket_create_connection
):
    cfg = get_test_config()
    del cfg['server']['metadata_server']
    cfg.set('server', 'regionsrv', 'foo')
    mock_os_path_isfile.return_value = True
    response = Response()
    response.status_code = 200
    smt_xml = dedent(
        '''<regionSMTdata><smtInfo fingerprint="99:88:77:66" '''
        '''SMTserverIP="1.2.3.4" SMTserverIPv6="fc11::2" '''
        '''SMTserverName="foo.susecloud.net"/></regionSMTdata>'''
    )
    response.text = smt_xml
    mock_request_get.side_effect = [response, response]
    mock_ipaddress_ip_address.side_effect = [ValueError, ValueError]
    mock_socket_create_connection.side_effect = OSError
    smt_data = utils.fetch_smt_data(cfg, None)
    assert etree.tostring(smt_data, encoding='utf-8') == smt_xml.encode()


@patch('cloudregister.registerutils.has_network_access_by_ip_address')
@patch('cloudregister.registerutils.requests.get')
@patch('cloudregister.registerutils.os.path.isfile')
@patch('cloudregister.registerutils.time.sleep')
@patch('cloudregister.registerutils.logging')
def test_fetch_smt_data_api_error_response(
    mock_logging,
    mock_time_sleep,
    mock_os_path_isfile,
    mock_request_get,
    mock_has_network_access
):
    cfg = get_test_config()
    del cfg['server']['metadata_server']
    cfg.set('server', 'regionsrv', '1.1.1.1')
    mock_os_path_isfile.return_value = True
    response = Response()
    response.status_code = 422
    response.reason = 'well, you shall not pass'
    mock_request_get.return_value = response
    mock_has_network_access.return_value = False
    with raises(SystemExit):
        utils.fetch_smt_data(cfg, None)
    print(mock_logging.info.call_args_list)
    assert mock_logging.info.call_args_list == [
        call('Using API: regionInfo'),
        call('Getting update server information, attempt 1'),
        call('\tUsing region server: 1.1.1.1'),
        call('Waiting 20 seconds before next attempt'),
        call('Getting update server information, attempt 2'),
        call('\tUsing region server: 1.1.1.1'),
        call('Waiting 10 seconds before next attempt'),
        call('Getting update server information, attempt 3'),
        call('\tUsing region server: 1.1.1.1')
    ]
    assert mock_logging.error.call_args_list == [
        call('===================='),
        call('Server returned: 422'),
        call('Server error: "well, you shall not pass"'),
        call('===================='),
        call('\tAll servers reported an error'),
        call('===================='),
        call('Server returned: 422'),
        call('Server error: "well, you shall not pass"'),
        call('===================='),
        call('\tAll servers reported an error'),
        call('===================='),
        call('Server returned: 422'),
        call('Server error: "well, you shall not pass"'),
        call('===================='),
        call('\tAll servers reported an error'),
        call('Request not answered by any server after 3 attempts'),
        call('Exiting without registration')
    ]


@patch('cloudregister.registerutils.has_network_access_by_ip_address')
@patch('cloudregister.registerutils.requests.get')
@patch('cloudregister.registerutils.os.path.isfile')
@patch('cloudregister.registerutils.time.sleep')
@patch('cloudregister.registerutils.logging')
def test_fetch_smt_data_api_exception(
    mock_logging,
    mock_time_sleep,
    mock_os_path_isfile,
    mock_request_get,
    mock_has_network_access
):
    cfg = get_test_config()
    del cfg['server']['metadata_server']
    cfg.set('server', 'regionsrv', 'fc00::11')
    mock_os_path_isfile.return_value = True
    response = Response()
    response.status_code = 422
    response.reason = 'well, you shall not pass'
    mock_request_get.side_effect = requests.exceptions.RequestException('foo')
    mock_has_network_access.return_value = True
    with raises(SystemExit):
        utils.fetch_smt_data(cfg, None)
    assert mock_logging.info.call_args_list == [
        call('Using API: regionInfo'),
        call('Getting update server information, attempt 1'),
        call('\tUsing region server: fc00::11'),
        call('Waiting 20 seconds before next attempt'),
        call('Getting update server information, attempt 2'),
        call('\tUsing region server: fc00::11'),
        call('Waiting 10 seconds before next attempt'),
        call('Getting update server information, attempt 3'),
        call('\tUsing region server: fc00::11')
    ]
    assert mock_logging.error.call_args_list == [
        call('\tNo response from: fc00::11'),
        call('\tNone of the servers responded'),
        call("\tAttempted: [IPv6Address('fc00::11')]"),
        call('\tNo response from: fc00::11'),
        call('\tNone of the servers responded'),
        call("\tAttempted: [IPv6Address('fc00::11')]"),
        call('\tNo response from: fc00::11'),
        call('\tNone of the servers responded'),
        call("\tAttempted: [IPv6Address('fc00::11')]"),
        call('Request not answered by any server after 3 attempts'),
        call('Exiting without registration')
    ]


@patch('cloudregister.registerutils.has_network_access_by_ip_address')
@patch('cloudregister.registerutils.requests.get')
@patch('cloudregister.registerutils.os.path.isfile')
@patch('cloudregister.registerutils.time.sleep')
@patch('cloudregister.registerutils.logging')
def test_fetch_smt_data_api_exception_quiet(
    mock_logging,
    mock_time_sleep,
    mock_os_path_isfile,
    mock_request_get,
    mock_has_network_access
):
    cfg = get_test_config()
    del cfg['server']['metadata_server']
    cfg.set('server', 'regionsrv', '1.1.1.1')
    mock_os_path_isfile.return_value = True
    response = Response()
    response.status_code = 422
    response.reason = 'well, you shall not pass'
    mock_request_get.side_effect = requests.exceptions.RequestException('foo')
    mock_has_network_access.return_value = True
    with raises(SystemExit):
        utils.fetch_smt_data(cfg, 'foo', quiet=True)
    assert mock_logging.info.call_args_list == [
        call('Using API: regionInfo'),
        call('Waiting 20 seconds before next attempt'),
        call('Waiting 10 seconds before next attempt'),
    ]
    assert mock_logging.error.call_args_list == [
        call('Request not answered by any server after 3 attempts'),
        call('Exiting without registration')
    ]


@patch.object(SMT, 'is_responsive')
def test_find_equivalent_smt_server(mock_is_responsive):
    """Test hosts entry has a new entry added by us."""
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="fantasy.example.com"
         SMTregistryName="registry-fantasy.example.com"
         region="antarctica-1"/>''')
    smt_data_ipv46_2 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.2.1"
         SMTserverIPv6="fc00::2"
         SMTserverName="fantasy.example.net"
         SMTregistryName="registry-fantasy.example.net"
         region="antarctica-1"/>''')
    smt_a = SMT(etree.fromstring(smt_data_ipv46))
    smt_b = SMT(etree.fromstring(smt_data_ipv46_2))
    mock_is_responsive.return_value = True

    assert utils.find_equivalent_smt_server(smt_a, [smt_a, smt_b]) == smt_b
    assert utils.find_equivalent_smt_server(smt_a, [smt_a]) is None


@patch('cloudregister.registerutils.glob.glob')
def test_find_repos(mock_glob):
    mock_glob.return_value = ['tests/data/repo_foo.repo']
    assert utils.find_repos('Foo') == ['SLE-Module-Live-Foo15-SP5-Source-Pool']


@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.get_credentials_file')
@patch('cloudregister.registerutils.get_credentials')
@patch('cloudregister.registerutils.get_smt')
def test_get_activations_no_user_pass(
    mock_get_smt,
    mock_get_creds,
    mock_get_creds_file,
    mock_logging
):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="fantasy.example.com"
         SMTregistryName="registry-fantasy.example.com"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_smt.return_value = smt_server
    mock_get_creds.return_value = None, 'foo'
    assert utils.get_activations() == {}
    mock_logging.error.assert_called_once_with(
        'Unable to extract username and password for "fantasy.example.com"'
    )


@patch('cloudregister.registerutils.requests.get')
@patch('cloudregister.registerutils.get_instance_data')
@patch('cloudregister.registerutils.get_config')
@patch('cloudregister.registerutils.HTTPBasicAuth')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.get_credentials_file')
@patch('cloudregister.registerutils.get_credentials')
@patch('cloudregister.registerutils.get_smt')
def test_get_activations_request_wrong(
    mock_get_smt,
    mock_get_creds,
    mock_get_creds_file,
    mock_logging,
    mock_http_basic_auth,
    mock_config,
    mock_get_instance_data,
    mock_request_get
):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="fantasy.example.com"
         SMTregistryName="registry-fantasy.example.com"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_smt.return_value = smt_server
    mock_get_creds.return_value = 'foo', 'bar'
    mock_http_basic_auth.return_value = 'foobar'
    mock_get_instance_data.return_value = 'super_instance_data'
    response = Response()
    response.status_code = 422
    response.reason = 'no reason'
    mock_request_get.return_value = response
    assert utils.get_activations() == {}
    assert mock_logging.error.call_args_list == [
        call(
            'Unable to get product info from update server: '
            '"(\'192.168.1.1\', \'fc00::1\')"'
        ),
        call('\tReason: "no reason"'),
        call('\tCode: %d', 422)
    ]
    mock_request_get.assert_called_once_with(
        'https://fantasy.example.com/connect/systems/activations',
        auth='foobar',
        headers={'X-Instance-Data': b'c3VwZXJfaW5zdGFuY2VfZGF0YQ=='}
    )


@patch('cloudregister.registerutils.requests.get')
@patch('cloudregister.registerutils.get_instance_data')
@patch('cloudregister.registerutils.get_config')
@patch('cloudregister.registerutils.HTTPBasicAuth')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.get_credentials_file')
@patch('cloudregister.registerutils.get_credentials')
@patch('cloudregister.registerutils.get_smt')
def test_get_activations_request_OK(
    mock_get_smt,
    mock_get_creds,
    mock_get_creds_file,
    mock_logging,
    mock_http_basic_auth,
    mock_config,
    mock_get_instance_data,
    mock_request_get
):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="fantasy.example.com"
         SMTregistryName="registry-fantasy.example.com"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_smt.return_value = smt_server
    mock_get_creds.return_value = 'foo', 'bar'
    mock_http_basic_auth.return_value = 'foobar'
    mock_get_instance_data.return_value = 'super_instance_data'
    response = Response()
    response.status_code = 200
    json_mock = Mock()
    json_mock.return_value = {"foo": "bar"}
    response.json = json_mock
    mock_request_get.return_value = response
    assert utils.get_activations() == {'foo': 'bar'}
    assert mock_logging.error.not_called
    mock_request_get.assert_called_once_with(
        'https://fantasy.example.com/connect/systems/activations',
        auth='foobar',
        headers={'X-Instance-Data': b'c3VwZXJfaW5zdGFuY2VfZGF0YQ=='}
    )


@patch('cloudregister.registerutils.configparser.RawConfigParser.read')
def test_get_config(mock_config_parser):
    mock_config_parser.return_value = data_path + '/regionserverclnt.cfg'
    assert type(utils.get_config()) == configparser.RawConfigParser


@patch('cloudregister.registerutils.sys.exit')
def test_get_config_not_parsed(mock_sys_exit):
    utils.get_config()
    mock_sys_exit.assert_called_once_with(1)


@patch('cloudregister.registerutils.configparser.RawConfigParser.read')
def test_get_config_exception(mock_configparser):
    mock_configparser.side_effect = configparser.Error
    with raises(SystemExit) as pytest_wrapped_e:
        utils.get_config()

    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 1


@patch('cloudregister.registerutils.glob.glob')
@patch('cloudregister.registerutils.logging')
def test_get_credentials_file_no_file(mock_logging, mock_glob):
    mock_glob.return_value = []
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="fantasy.example.com"
         SMTregistryName="registry-fantasy.example.com"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    utils.get_credentials_file(smt_server, 'bar')
    assert mock_logging.info.mock_calls == [
        call('No credentials entry for "*bar*"'),
        call('No credentials entry for "*fantasy_example_com"'),
        call('No credentials entry for "SCC*"'),
    ]

    mock_logging.error.assert_called_once_with(
        'No matching credentials file found'
    )


@patch('cloudregister.registerutils.glob.glob')
@patch('cloudregister.registerutils.logging')
def test_get_credentials_two_files(mock_logging, mock_glob):
    mock_glob.return_value = ['foo', 'bar']
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="fantasy.example.com"
         SMTregistryName="registry-fantasy.example.com"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    assert utils.get_credentials_file(smt_server) == 'foo'
    assert mock_logging.warning.mock_calls == [
        call('Found multiple credentials for "None" entry and '
             'hoping for the best')
    ]  # TODO: check this warning


@patch('cloudregister.registerutils.get_smt_from_store')
def test_get_current_smt_no_smt(mock_get_smt_from_store):
    mock_get_smt_from_store.return_value = None
    assert utils.get_current_smt() is None


@patch('cloudregister.registerutils.os.unlink')
@patch('cloudregister.registerutils.get_smt_from_store')
def test_get_current_smt_no_match(mock_get_smt_from_store, mock_os_unlink):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="fantasy.example.com"
         SMTregistryName="registry-fantasy.example.com"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_smt_from_store.return_value = smt_server
    utils.get_current_smt()


@patch('cloudregister.registerutils.glob.glob')
@patch('cloudregister.registerutils.get_smt_from_store')
def test_get_current_smt_no_registered(
    mock_get_smt_from_store, mock_glob_glob
):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="smt-foo.susecloud.net"
         SMTregistryName="registry-foo.example.net"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_smt_from_store.return_value = smt_server
    mock_glob_glob.return_value = ['tests/data/service.service']
    hosts_content = """
    # simulates hosts file containing the ipv4 we are looking for in the test

    192.168.1.1   smt-foo.susecloud.net  smt-foo
    """
    open_mock_hosts = mock_open(read_data=hosts_content.encode())
    open_mock = mock_open(read_data=hosts_content)

    def open_f(filename, *args, **kwargs):
        if filename == '/etc/hosts':
            return open_mock_hosts()
        return open_mock()

    with patch('builtins.open') as m_open:
        m_open.side_effect = open_f
        assert utils.get_current_smt() is None


@patch('cloudregister.registerutils.is_registered')
@patch('cloudregister.registerutils.get_smt_from_store')
def test_get_current_smt(mock_get_smt_from_store, mock_is_registered):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="smt-foo.susecloud.net"
         SMTregistryName="registry-foo.susecloud.net"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_smt_from_store.return_value = smt_server
    mock_is_registered.return_value = True
    hosts_content = """
    # simulates hosts file containing the ipv4 we are looking for in the test

    192.168.1.1   smt-foo.susecloud.net  smt-foo
    """
    with patch('builtins.open', mock_open(
        read_data=hosts_content.encode()
    )):
        assert utils.get_current_smt() == smt_server


def test_get_framework_identifier_path():
    assert utils.get_framework_identifier_path() == \
        '/var/cache/cloudregister/framework_info'


def test_get_instance_no_instance_section():
    """The configuration has no instance section configured"""
    cfg = get_test_config()
    expected_data = '<repoformat>plugin:susecloud</repoformat>\n'
    assert utils.get_instance_data(cfg) == expected_data


def test_get_instance_no_data_provider_option():
    """The configuration has no dataProvider configured"""
    cfg = get_test_config()
    cfg.add_section('instance')
    expected_data = '<repoformat>plugin:susecloud</repoformat>\n'
    assert utils.get_instance_data(cfg) == expected_data


def test_get_instance_data_provider_option_none():
    """The configuration has a dataProvider option but it is set to none"""
    cfg = get_test_config()
    cfg.add_section('instance')
    cfg.set('instance', 'dataProvider', 'none')
    expected_data = '<repoformat>plugin:susecloud</repoformat>\n'
    assert utils.get_instance_data(cfg) == expected_data


@patch('cloudregister.registerutils.logging')
def test_get_instance_data_cmd_not_found(mock_logging):
    cfg = get_test_config()
    cfg.add_section('instance')
    # Let's assume we run on a system where the fussball command does not exist
    cfg.set('instance', 'dataProvider', 'fussball')
    expected_data = '<repoformat>plugin:susecloud</repoformat>\n'
    assert utils.get_instance_data(cfg) == expected_data
    mock_logging.error.assert_called_once_with(
        'Could not find configured dataProvider: fussball'
    )


@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.os.access')
@patch('cloudregister.registerutils.exec_subprocess')
def test_get_instance_data_cmd_error(
        mock_exec_sub,
        mock_access,
        mock_logging
):
    """Test instance data gathering with the specified command
       returning an error"""
    cfg = get_test_config()
    cfg.add_section('instance')
    cfg.set('instance', 'dataProvider', '/foo')
    mock_exec_sub.return_value = (b'', b'bar', 0)
    mock_access.return_value = True
    expected_data = '<repoformat>plugin:susecloud</repoformat>\n'
    assert utils.get_instance_data(cfg) == expected_data
    mock_logging.error.assert_called_once_with(
        'Data collected from stderr for instance data collection "bar"'
    )


@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.os.access')
@patch('cloudregister.registerutils.exec_subprocess')
def test_get_instance_data_no_data(
        mock_exec_sub,
        mock_access,
        mock_logging
):
    """Test instance data gathering with the specified command
       returning no data"""
    cfg = get_test_config()
    cfg.add_section('instance')
    cfg.set('instance', 'dataProvider', '/foo')
    mock_exec_sub.return_value = (b'', b'', 0)
    mock_access.return_value = True
    expected_data = '<repoformat>plugin:susecloud</repoformat>\n'
    assert utils.get_instance_data(cfg) == expected_data
    mock_logging.warning.assert_called_once_with(
        'Possible issue accessing the metadata service. Metadata is empty, '
        'may result in registration failure.'
    )


@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.os.access')
@patch('cloudregister.registerutils.exec_subprocess')
def test_get_instance_data_instance_data(
        mock_exec_sub,
        mock_access,
        mock_logging
):
    """Test instance data gathering with the specified command"""
    cfg = get_test_config()
    cfg.add_section('instance')
    cfg.set('instance', 'dataProvider', '/foo')
    mock_exec_sub.return_value = (b'<mydata>', b'', 0)
    mock_access.return_value = True
    expected_data = '<mydata><repoformat>plugin:susecloud</repoformat>\n'
    assert utils.get_instance_data(cfg) == expected_data


@patch('cloudregister.registerutils.time.sleep')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.is_zypper_running')
def test_get_installed_products_no_zypper_lock(
    mock_is_zypper_running,
    mock_logging,
    mock_time_sleep
):
    # mock_is_zypper_running.side_effect = [True, False]
    mock_is_zypper_running.return_value = True
    assert utils.get_installed_products() == []
    mock_logging.error.assert_called_once_with(
        'Wait time expired could not acquire zypper lock file'
    )


@patch('cloudregister.registerutils.subprocess.Popen')
@patch('cloudregister.registerutils.time.sleep')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.is_zypper_running')
def test_get_installed_products_cmd_error(
    mock_is_zypper_running,
    mock_logging,
    mock_time_sleep,
    mock_popen
):
    mock_is_zypper_running.side_effect = [True, False]
    mock_process = Mock()
    mock_process.communicate = Mock(
        return_value=[str.encode(''), str.encode('')]
    )
    mock_process.returncode = 1
    mock_popen.return_value = mock_process
    assert utils.get_installed_products() == []
    mock_logging.error.assert_called_once_with(
        'zypper product query returned with zypper code 1'
    )


@patch('cloudregister.registerutils.subprocess.Popen')
@patch('cloudregister.registerutils.time.sleep')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.is_zypper_running')
def test_get_installed_products_cmd_oserror_exception(
    mock_is_zypper_running,
    mock_logging,
    mock_time_sleep,
    mock_popen
):
    mock_is_zypper_running.side_effect = [True, False]
    mock_popen.side_effect = OSError('No such file or directory')
    assert utils.get_installed_products() == []
    mock_logging.error.assert_called_once_with(
        'Could not get product list %s',
        'zypper --no-remote -x products'
    )


@patch('cloudregister.registerutils.os.path.realpath')
@patch('cloudregister.registerutils.os.path.islink')
@patch('cloudregister.registerutils.subprocess.Popen')
@patch('cloudregister.registerutils.time.sleep')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.is_zypper_running')
def test_get_installed_products_OK(
    mock_is_zypper_running,
    mock_logging,
    mock_time_sleep,
    mock_popen,
    mock_os_path_islink,
    mock_os_path_realpath,
):
    prod = dedent('''<?xml version="1.0"?>\n<stream>\n<message type="info">foo\
    \n</message><product-list><product name="sle-super-prod" version="12"\
    arch="x86_64">foo</product></product-list></stream>''')
    mock_is_zypper_running.side_effect = [True, False]
    mock_process = Mock()
    mock_process.communicate = Mock(
        return_value=[prod.encode(), str.encode('')]
    )
    mock_process.returncode = 0
    mock_popen.return_value = mock_process
    mock_os_path_islink.return_value = True
    mock_os_path_realpath.return_value = '/real/path/to/base/prod'
    assert utils.get_installed_products() == ['sle-super-prod/12/x86_64']
    assert mock_logging.error.not_called


@patch('cloudregister.registerutils.os.path.realpath')
@patch('cloudregister.registerutils.os.path.islink')
@patch('cloudregister.registerutils.subprocess.Popen')
@patch('cloudregister.registerutils.time.sleep')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.is_zypper_running')
def test_get_installed_products_baseprod(
    mock_is_zypper_running,
    mock_logging,
    mock_time_sleep,
    mock_popen,
    mock_os_path_islink,
    mock_os_path_realpath,
):
    prod = dedent('''<?xml version="1.0"?>\n<stream>\n<message type="info">foo\
    \n</message><product-list><product name="prod" version="12"\
    arch="x86_64">foo</product></product-list></stream>''')
    mock_is_zypper_running.side_effect = [True, False]
    mock_process = Mock()
    mock_process.communicate = Mock(
        return_value=[prod.encode(), str.encode('')]
    )
    mock_process.returncode = 0
    mock_popen.return_value = mock_process
    mock_os_path_islink.return_value = True
    mock_os_path_realpath.return_value = '/real/path/to/base/prod'
    assert utils.get_installed_products() == []
    assert mock_logging.error.not_called


@patch('cloudregister.registerutils.os.path.realpath')
@patch('cloudregister.registerutils.os.path.islink')
@patch('cloudregister.registerutils.subprocess.Popen')
@patch('cloudregister.registerutils.time.sleep')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.is_zypper_running')
def test_get_installed_products_no_link(
    mock_is_zypper_running,
    mock_logging,
    mock_time_sleep,
    mock_popen,
    mock_os_path_islink,
    mock_os_path_realpath,
):
    prod = dedent('''<?xml version="1.0"?>\n<stream>\n<message type="info">foo\
    \n</message><product-list><product name="sle-super-prod" version="12"\
    arch="x86_64">foo</product></product-list></stream>''')
    mock_is_zypper_running.side_effect = [True, False]
    mock_process = Mock()
    mock_process.communicate = Mock(
        return_value=[prod.encode(), str.encode('')]
    )
    mock_process.returncode = 0
    mock_popen.return_value = mock_process
    mock_os_path_islink.return_value = False
    assert utils.get_installed_products() == []
    mock_logging.error.assert_called_once_with(
        'No baseproduct installed system cannot be registered'
    )


@patch('cloudregister.registerutils.glob.glob')
def test_get_repo_url(mock_glob):
    mock_glob.return_value = ['tests/data/repo_foo.repo']
    assert utils.get_repo_url('SLE-Module-Live-Foo15-SP5-Source-Pool') == (
        'plugin:/susecloud?credentials=SUSE_Linux_Enterprise_Live_Foo_x86_64&'
        'path=/repo/SUSE/Products/SLE-Module-Live-Foo/15-SP5/x86_64/'
        'product_source/')


@patch('cloudregister.registerutils.glob.glob')
def test_get_repo_url_no_repos(mock_glob):
    mock_glob.return_value = []
    assert utils.get_repo_url('') == ''


@patch('cloudregister.registerutils.logging')
@patch.object(SMT, 'is_responsive')
@patch('cloudregister.registerutils.is_registered')
@patch('cloudregister.registerutils.get_available_smt_servers')
@patch('cloudregister.registerutils.get_current_smt')
def test_get_smt_network_issue(
        mock_get_current_smt,
        mock_get_available_smt_servers,
        mock_is_registered,
        mock_smt_is_responsive,
        mock_logging
):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="smt-foo.susecloud.net"
         SMTregistryName="registry-foo.susecloud.net"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_current_smt.return_value = smt_server
    mock_is_registered.return_value = True
    mock_smt_is_responsive.side_effect = [False, True]
    assert utils.get_smt() == smt_server
    assert mock_logging.info.call_args_list == [
        call('Waiting for current server to show up for 5 s'),
        call('No failover needed, system access recovered')
    ]


@patch('cloudregister.registerutils.logging')
@patch.object(SMT, 'is_responsive')
@patch('cloudregister.registerutils.is_registered')
@patch('cloudregister.registerutils.get_available_smt_servers')
@patch('cloudregister.registerutils.get_current_smt')
def test_get_smt_registered_no_network(
        mock_get_current_smt,
        mock_get_available_smt_servers,
        mock_is_registered,
        mock_smt_is_responsive,
        mock_logging
):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="smt-foo.susecloud.net"
         SMTregistryName="registry-foo.susecloud.net"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_current_smt.return_value = smt_server
    mock_is_registered.return_value = True
    mock_smt_is_responsive.return_value = True
    assert utils.get_smt() == smt_server
    mock_logging.info.assert_called_once_with(
        'Current update server will be used: "(\'192.168.1.1\', \'fc00::1\')"'
    )


@patch('cloudregister.registerutils.set_as_current_smt')
@patch('cloudregister.registerutils.replace_hosts_entry')
@patch('cloudregister.registerutils.has_smt_access')
@patch('cloudregister.registerutils.get_credentials')
@patch('cloudregister.registerutils.get_credentials_file')
@patch('cloudregister.registerutils.import_smt_cert')
@patch('cloudregister.registerutils.logging')
@patch.object(SMT, 'is_responsive')
@patch('cloudregister.registerutils.find_equivalent_smt_server')
@patch('cloudregister.registerutils.is_registered')
@patch('cloudregister.registerutils.get_available_smt_servers')
@patch('cloudregister.registerutils.get_current_smt')
def test_get_smt_find_equivalent(
        mock_get_current_smt,
        mock_get_available_smt_servers,
        mock_is_registered,
        mock_find_equivalent_smt_server,
        mock_smt_is_responsive,
        mock_logging,
        mock_import_smt_cert,
        mock_get_credentials_file,
        mock_get_credentials,
        mock_has_smt_access,
        mock_replace_hosts_entry,
        mock_set_as_current_smt
):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="smt-foo.susecloud.net"
         SMTregistryName="registry-foo.susecloud.net"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="42.168.1.1"
         SMTserverIPv6="fc00::7"
         SMTserverName="smt-foo.susecloud.net"
         SMTregistryName="registry-foo.susecloud.net"
         region="antarctica-1"/>''')
    equivalent_smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_current_smt.return_value = smt_server
    mock_is_registered.return_value = True
    mock_smt_is_responsive.side_effect = [False, False, False, False]
    mock_find_equivalent_smt_server.return_value = equivalent_smt_server
    mock_has_smt_access.return_value = True
    mock_get_credentials.return_value = 'foo', 'bar'
    assert utils.get_smt() == equivalent_smt_server
    assert mock_logging.info.call_args_list == [
        call('Waiting for current server to show up for 5 s'),
        call('Waiting for current server to show up for 3 s'),
        call('Waiting for current server to show up for 1 s'),
        call('Using equivalent update server: "(\'42.168.1.1\', \'fc00::7\')"')
    ]


@patch('cloudregister.registerutils.set_as_current_smt')
@patch('cloudregister.registerutils.replace_hosts_entry')
@patch('cloudregister.registerutils.has_smt_access')
@patch('cloudregister.registerutils.get_credentials')
@patch('cloudregister.registerutils.get_credentials_file')
@patch('cloudregister.registerutils.import_smt_cert')
@patch('cloudregister.registerutils.logging')
@patch.object(SMT, 'is_responsive')
@patch('cloudregister.registerutils.find_equivalent_smt_server')
@patch('cloudregister.registerutils.is_registered')
@patch('cloudregister.registerutils.get_available_smt_servers')
@patch('cloudregister.registerutils.get_current_smt')
def test_get_smt_equivalent_smt_no_access(
        mock_get_current_smt,
        mock_get_available_smt_servers,
        mock_is_registered,
        mock_find_equivalent_smt_server,
        mock_smt_is_responsive,
        mock_logging,
        mock_import_smt_cert,
        mock_get_credentials_file,
        mock_get_credentials,
        mock_has_smt_access,
        mock_replace_hosts_entry,
        mock_set_as_current_smt
):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="smt-foo.susecloud.net"
         SMTregistryName="registry-foo.susecloud.net"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="42.168.1.1"
         SMTserverIPv6="fc00::7"
         SMTserverName="smt-foo.susecloud.net"
         SMTregistryName="registry-foo.susecloud.net"
         region="antarctica-1"/>''')
    equivalent_smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_current_smt.return_value = smt_server
    mock_is_registered.return_value = True
    mock_smt_is_responsive.side_effect = [False, False, False, False]
    mock_find_equivalent_smt_server.return_value = equivalent_smt_server
    mock_has_smt_access.return_value = False
    mock_get_credentials.return_value = 'foo', 'bar'
    assert utils.get_smt() == smt_server
    assert mock_logging.info.call_args_list == [
        call('Waiting for current server to show up for 5 s'),
        call('Waiting for current server to show up for 3 s'),
        call('Waiting for current server to show up for 1 s'),
        call('Using equivalent update server: "(\'42.168.1.1\', \'fc00::7\')"')
    ]
    mock_logging.error.assert_called_once_with(
        "Sibling update server, ('42.168.1.1', 'fc00::7'), does not have "
        'system credentials cannot failover. Retaining current, '
        "('192.168.1.1', 'fc00::1'), target update server.Try again later."
    )


@patch('cloudregister.registerutils.set_as_current_smt')
@patch('cloudregister.registerutils.add_hosts_entry')
@patch('cloudregister.registerutils.import_smt_cert')
@patch('cloudregister.registerutils.logging')
@patch.object(SMT, 'is_responsive')
@patch('cloudregister.registerutils.clean_hosts_file')
@patch('cloudregister.registerutils.get_available_smt_servers')
@patch('cloudregister.registerutils.get_current_smt')
def test_get_smt_alternative_server(
        mock_get_current_smt,
        mock_get_available_smt_servers,
        mock_clean_hosts_file,
        mock_smt_is_responsive,
        mock_logging,
        mock_import_smt_cert,
        mock_add_hosts_entry,
        mock_set_as_current_smt
):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="smt-foo.susecloud.net"
         SMTregistryName="registry-foo.susecloud.net"
         region="antarctica-1"/>''')
    alternative_smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_available_smt_servers.return_value = [alternative_smt_server]
    mock_get_current_smt.return_value = None
    mock_smt_is_responsive.return_value = True
    assert utils.get_smt() == alternative_smt_server
    mock_logging.info.assert_called_once_with(
        'Found alternate update server: "(\'192.168.1.1\', \'fc00::1\')"'
    )
    mock_add_hosts_entry.assert_called_once_with(alternative_smt_server)
    mock_set_as_current_smt.assert_called_once_with(alternative_smt_server)
    mock_set_as_current_smt.assert_called_once_with(alternative_smt_server)
    mock_clean_hosts_file.assert_called_once_with('susecloud.net')


@patch('cloudregister.registerutils.__populate_srv_cache')
@patch('cloudregister.registerutils.clean_smt_cache')
@patch('cloudregister.registerutils.logging')
@patch.object(SMT, 'is_responsive')
@patch('cloudregister.registerutils.clean_hosts_file')
@patch('cloudregister.registerutils.get_available_smt_servers')
@patch('cloudregister.registerutils.get_current_smt')
def test_get_smt_refresh_cache(
        mock_get_current_smt,
        mock_get_available_smt_servers,
        mock_clean_hosts_file,
        mock_smt_is_responsive,
        mock_logging,
        mock_clean_smt_cache,
        mock_populate_srv_cache
):
    mock_get_available_smt_servers.return_value = []
    mock_get_current_smt.return_value = None
    utils.get_smt()
    mock_clean_smt_cache.assert_called_once()
    mock_populate_srv_cache.assert_called_once()


@patch('cloudregister.registerutils.os.path.exists')
def test_get_smt_from_store_non_existing_path(mock_os_path_exists):
    mock_os_path_exists.return_value = False
    assert utils.get_smt_from_store('foo') is None


@patch.object(pickle, 'Unpickler')
def test_get_smt_from_store_raise_exception(mock_unpickler):
    unpick = Mock()
    mock_unpickler.return_value = unpick
    unpick.load.side_effect = pickle.UnpicklingError
    assert utils.get_smt_from_store(
        'tests/data/availableSMTInfo_1.obj'
    ) is None


@patch('cloudregister.registerutils.get_available_smt_servers')
def test_get_update_server_name_from_hosts(mock_get_available_smt_servers):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="smt-foo.susecloud.net"
         SMTregistryName="registry-foo.susecloud.net"
         region="antarctica-1"/>''')
    alternative_smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_available_smt_servers.return_value = [alternative_smt_server]

    hosts_content = """
    # simulates hosts file containing the ipv4 we are looking for in the test

    1.1.1.1   smt-foo.susecloud.net  smt-foo
    """
    with patch(
        'builtins.open', mock_open(read_data=hosts_content.encode())
    ):
        assert utils.get_update_server_name_from_hosts() == \
            'smt-foo.susecloud.net'


@patch('cloudregister.registerutils.get_zypper_pid')
def test_get_zypper_command(mock_zypper_pid):
    mock_zypper_pid.return_value = 42
    with patch(
        'builtins.open', mock_open(read_data='\x00foo')
    ):
        assert utils.get_zypper_command() == ' foo'


@patch('cloudregister.registerutils.subprocess.Popen')
def test_get_zypper_pid_one_pid(mock_popen):
    mock_process = Mock()
    mock_process.communicate = Mock(
        return_value=[str.encode('12345 '), str.encode('stderr')]
    )
    mock_process.returncode = 0
    mock_popen.return_value = mock_process
    assert utils.get_zypper_pid() == '12345'


@patch('cloudregister.registerutils.subprocess.Popen')
def test_get_zypper_pid_with_child_pid(mock_popen):
    mock_process = Mock()
    mock_process.communicate = Mock(
        return_value=[str.encode('12345\n    6789\n'), str.encode('stderr')]
    )
    mock_process.returncode = 0
    mock_popen.return_value = mock_process
    assert utils.get_zypper_pid() == '12345'


@patch('cloudregister.registerutils.has_ipv6_access')
def test_has_rmt_ipv6_access_no_ipv6_defined(mock_ipv6_access):
    smt_data_ipv4 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverName="smt-foo.susecloud.net"
         SMTregistryName="registry-foo.susecloud.net"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv4))
    mock_ipv6_access.return_value = True
    assert utils.has_rmt_ipv6_access(smt_server) is False


@patch('cloudregister.registerutils.has_ipv6_access')
@patch('cloudregister.registerutils.get_config')
@patch('cloudregister.registerutils.requests.get')
@patch('cloudregister.registerutils.https_only')
def test_has_rmt_ipv6_access_https(
    mock_https_only, mock_request,
    mock_get_config, mock_ipv6_access
):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="smt-foo.susecloud.net"
         SMTregistryName="registry-foo.susecloud.net"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    response = Response()
    response.status_code = 200
    response.text = 'such a request !'
    mock_request.return_value = response
    mock_https_only.return_value = True
    mock_ipv6_access.return_value = True
    assert utils.has_rmt_ipv6_access(smt_server)
    mock_request.assert_called_once_with(
        'https://[fc00::1]/smt.crt',
        timeout=3,
        verify=False
    )


@patch('cloudregister.registerutils.has_ipv6_access')
@patch('cloudregister.registerutils.get_config')
@patch('cloudregister.registerutils.requests.get')
@patch('cloudregister.registerutils.https_only')
def test_has_rmt_ipv6_access_exception(
    mock_https_only,
    mock_request,
    mock_get_config,
    mock_ipv6_access
):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="smt-foo.susecloud.net"
         SMTregistryName="registry-foo.susecloud.net"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_request.side_effect = Exception("Server's too far, cant be reached")
    mock_https_only.return_value = True
    mock_ipv6_access.return_value = True
    assert utils.has_rmt_ipv6_access(smt_server) is False
    mock_request.assert_called_once_with(
        'https://[fc00::1]/smt.crt',
        timeout=3,
        verify=False
    )


@patch('cloudregister.registerutils.exec_subprocess')
def test_has_nvidia_support(mock_subprocess):
    mock_subprocess.return_value = b'NVIDIA', 'bar', 0
    assert utils.has_nvidia_support() is True


@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.exec_subprocess')
def test_has_nvidia_support_exception(mock_subprocess, mock_logging):
    mock_subprocess.side_effect = TypeError('foo')
    assert utils.has_nvidia_support() is False
    mock_logging.info.assert_called_once_with(
        'lspci command not found, instance Nvidia support cannot be determined'
    )


@patch('cloudregister.registerutils.exec_subprocess')
def test_has_nvidia_no_support(mock_subprocess):
    mock_subprocess.return_value = b'foo', 'bar', 0
    assert utils.has_nvidia_support() is False


@patch('cloudregister.registerutils.__get_service_plugins')
def test_has_services_service_plugin(mock_get_service_plugins):
    mock_get_service_plugins.return_value = 'foo'
    assert utils.has_services('foo') is True


@patch('cloudregister.registerutils.glob.glob')
def test_has_services_service(mock_get_service_plugins):
    mock_get_service_plugins.return_value = ['foo']
    content = 'url=plugin:susecloud'
    with patch('builtins.open', mock_open(read_data=content)):
        assert utils.has_services('foo') is True


@patch('cloudregister.registerutils.requests.post')
@patch('cloudregister.registerutils.HTTPBasicAuth')
def test_has_smt_access_unauthorized(mock_http_basic_auth, mock_post):
    response = Response()
    response.reason = 'Unauthorized'
    mock_post.return_value = response
    assert utils.has_smt_access('foo', 'bar', 'foobar') is False


@patch('cloudregister.registerutils.requests.post')
@patch('cloudregister.registerutils.HTTPBasicAuth')
def test_has_smt_access_authorized(mock_http_basic_auth, mock_post):
    response = Response()
    response.reason = 'Super_Authorized'
    mock_post.return_value = response
    assert utils.has_smt_access('foo', 'bar', 'foobar') is True


def test_https_only():
    cfg = get_test_config()
    cfg.add_section('instance')
    cfg.set('instance', 'httpsOnly', 'true')
    assert utils.https_only(cfg) is True


def test_https_only_no():
    cfg = get_test_config()
    assert utils.https_only(cfg) is False


@patch.object(SMT, 'write_cert')
def test_import_smtcert_12_no_write_cert(mock_smt_write_cert):
    mock_smt_write_cert.return_value = False
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="fantasy.example.com"
         SMTregistryName="registry-fantasy.example.com"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))

    assert utils.import_smtcert_12(smt_server) == 0


@patch('cloudregister.registerutils.update_ca_chain')
@patch.object(SMT, 'write_cert')
def test_import_smtcert_12_no_update_ca_chain(
    mock_smt_write_cert,
    mock_update_ca_chain
):
    mock_smt_write_cert.return_value = True
    mock_update_ca_chain.return_value = False
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="fantasy.example.com"
         SMTregistryName="registry-fantasy.example.com"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))

    assert utils.import_smtcert_12(smt_server) == 0


@patch('cloudregister.registerutils.update_ca_chain')
@patch.object(SMT, 'write_cert')
def test_import_smtcert_12(
    mock_smt_write_cert,
    mock_update_ca_chain
):
    mock_smt_write_cert.return_value = True
    mock_update_ca_chain.return_value = True
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="fantasy.example.com"
         SMTregistryName="registry-fantasy.example.com"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))

    assert utils.import_smtcert_12(smt_server) == 1


@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.import_smtcert_12')
def test_import_smt_cert_fail(mock_import_smtcert_12, mockin_logging):
    mock_import_smtcert_12.return_value = False
    assert utils.import_smt_cert('foo') is None
    mockin_logging.error.assert_called_once_with(
        'SMT certificate import failed'
    )


@patch('cloudregister.registerutils.glob.glob')
@patch('cloudregister.registerutils.site')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.import_smtcert_12')
def test_import_smt_cert_cert_middling(
    mock_import_smtcert_12,
    mockin_logging,
    mockin_site,
    mockin_glob
):
    mock_import_smtcert_12.return_value = True
    mockin_site.getsitepackages.return_value = ['foo']
    mockin_glob.return_value = ['foo/certifi/foo.pem']
    assert utils.import_smt_cert('foo') == 1
    mockin_logging.warning.assert_called_once_with(
        'SMT certificate imported, but "foo/certifi/foo.pem" exist. '
        'This may lead to registration failure'
    )


@patch('cloudregister.registerutils.get_state_dir')
def test_is_new_registration_not_new(mock_state_dir):
    mock_state_dir.return_value = data_path
    assert utils.is_new_registration() is False


def test_is_registration_supported_exception():
    cfg_template = get_test_config()
    del cfg_template['server']
    assert utils.is_registration_supported(cfg_template) is False


def test_is_registration_supported():
    cfg_template = get_test_config()
    assert utils.is_registration_supported(cfg_template) is True


@patch('cloudregister.registerutils.glob.glob')
def test_is_scc_connected(mock_glob):
    mock_glob.return_value = ['tests/data/scc_repo.repo']
    assert utils.is_scc_connected() is True


@patch('cloudregister.registerutils.glob.glob')
def test_is_scc_not_connected(mock_glob):
    mock_glob.return_value = []
    assert utils.is_scc_connected() is False


@patch('cloudregister.registerutils.get_zypper_pid')
def test_is_zypper_running_not(mock_get_zypper_pid):
    mock_get_zypper_pid.return_value = ''
    assert utils.is_zypper_running() is False


@patch('cloudregister.registerutils.get_zypper_pid')
def test_is_zypper_running(mock_get_zypper_pid):
    mock_get_zypper_pid.return_value = 42
    assert utils.is_zypper_running()


@patch('cloudregister.registerutils.get_state_dir')
def test_refresh_zypper_pid_cache(mock_get_state_dir):
    with tempfile.TemporaryDirectory() as tmpdirname:
        mock_get_state_dir.return_value = tmpdirname
        utils.refresh_zypper_pid_cache()


@patch('cloudregister.registerutils.get_state_dir')
def test_set_as_current_smt(mock_get_state_dir):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="fantasy.example.com"
         SMTregistryName="registry-fantasy.example.com"
         region="antarctica-1"/>''')

    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    with tempfile.TemporaryDirectory() as tmpdirname:
        mock_get_state_dir.return_value = tmpdirname + '/foo'
        utils.set_as_current_smt(smt_server)


@patch.dict(
    os.environ,
    {'http_proxy': 'foo', 'https_proxy': 'bar'},
    clear=True
)
@patch('cloudregister.registerutils.logging')
def test_set_proxy_proxy_set_on_os_env(mock_logging):
    assert utils.set_proxy() is False
    assert mock_logging.info.call_args_list == [
        call('Using proxy settings from execution environment'),
        call('\thttp_proxy: foo'),
        call('\thttps_proxy: bar'),
    ]


@patch('cloudregister.registerutils.os.path.exists')
def test_set_proxy_proxy_set_on_directory(mock_os_path_exists):
    mock_os_path_exists.return_value = False
    assert utils.set_proxy() is False


@patch('cloudregister.registerutils.os.path.exists')
def test_set_proxy(mock_os_path_exists):
    mock_os_path_exists.return_value = True
    proxy_content = """
    HTTP_PROXY="http://proxy.provider.de:3128/"
    HTTPS_PROXY="https://proxy.provider.de:3128/"
    NO_PROXY="localhost, 127.0.0.1"
    """
    with patch('builtins.open', mock_open(read_data=proxy_content)):
        assert utils.set_proxy() is True


@patch.dict(os.environ, {'http_proxy': '', 'https_proxy': ''}, clear=True)
@patch('cloudregister.registerutils.os.path.exists')
def test_proxy_not_enable(mock_os_path_exists):
    mock_os_path_exists.return_value = True
    proxy_content = """
    PROXY_ENABLED="no"
    """
    with patch('builtins.open', mock_open(read_data=proxy_content)):
        assert utils.set_proxy() is False


@patch('cloudregister.registerutils.Path')
def test_new_registration_flag(mock_path):
    utils.set_new_registration_flag()
    mock_path.assert_called_once_with(
        '/var/cache/cloudregister/newregistration'
    )


@patch('cloudregister.registerutils.Path')
def test_rmt_as_scc_proxy_flag(mock_path):
    utils.set_rmt_as_scc_proxy_flag()
    mock_path.assert_called_once_with(
        '/var/cache/cloudregister/',
        'rmt_is_scc_proxy'
    )


@patch('cloudregister.registerutils.get_available_smt_servers')
def test_switch_services_to_plugin_no_servers(mock_get_available_smt_servers):
    mock_get_available_smt_servers.return_value = []
    assert utils.switch_services_to_plugin() is None


@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.configparser.RawConfigParser.read')
@patch('cloudregister.registerutils.glob.glob')
@patch('cloudregister.registerutils.get_available_smt_servers')
def test_switch_services_to_plugin_config_parse_error(
    mock_get_available_smt_servers,
    mock_glob,
    mock_raw_config_parser_read,
    mock_logging
):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="smt-foo.susecloud.net"
         SMTregistryName="registry-foo.susecloud.net"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_available_smt_servers.return_value = [smt_server]
    mock_glob.return_value = ['foo']
    mock_raw_config_parser_read.side_effect = configparser.Error('foo')
    utils.switch_services_to_plugin()
    mock_logging.warning.assert_called_once_with(
        'Unable to parse "foo" skipping'
    )


@patch('cloudregister.registerutils.os.path.exists')
@patch('cloudregister.registerutils.os.unlink')
@patch('cloudregister.registerutils.os.symlink')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.glob.glob')
@patch('cloudregister.registerutils.get_available_smt_servers')
def test_switch_services_to_plugin_unlink_service(
    mock_get_available_smt_servers,
    mock_glob,
    mock_logging,
    mock_os_symlink,
    mock_os_unlink,
    mock_os_path_exists
):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="smt-foo.susecloud.net"
         SMTregistryName="registry-foo.susecloud.net"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_available_smt_servers.return_value = [smt_server]
    mock_glob.return_value = ['tests/data/service.service']
    mock_os_path_exists.return_value = True
    utils.switch_services_to_plugin()
    mock_os_symlink.assert_called_once_with(
        '/usr/sbin/cloudguest-repo-service',
        '/usr/lib/zypp/plugins/services/Public_Cloud_Module_x86_64'
    )
    assert mock_os_unlink.call_args_list == [
        call('/usr/lib/zypp/plugins/services/Public_Cloud_Module_x86_64'),
        call('tests/data/service.service')
    ]


@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.get_credentials')
@patch('cloudregister.registerutils.__get_registered_smt_file_path')
def test_remove_registration_data_no_user(
    mock_get_registered_smt_file_path,
    mock_get_creds,
    mock_logging
):
    mock_get_creds.return_value = None, None
    assert utils.remove_registration_data() is None
    mock_logging.info.assert_called_once_with(
        'No credentials, nothing to do server side'
    )


@patch('cloudregister.registerutils.os.path.exists')
@patch('cloudregister.registerutils.is_scc_connected')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.get_credentials')
@patch('cloudregister.registerutils.__get_registered_smt_file_path')
def test_remove_registration_data_no_registration(
    mock_get_registered_smt_file_path,
    mock_get_creds,
    mock_logging,
    mock_is_scc_connected,
    mock_os_path_exists,
):
    mock_get_creds.return_value = 'foo', 'bar'
    mock_is_scc_connected.return_value = False
    mock_os_path_exists.return_value = False
    assert utils.remove_registration_data() is None
    mock_logging.info.assert_called_once_with(
        'No current registration server set.'
    )


@patch('cloudregister.registerutils.is_scc_connected')
@patch('cloudregister.registerutils.os.unlink')
@patch('cloudregister.registerutils.__remove_repo_artifacts')
@patch('cloudregister.registerutils.clean_hosts_file')
@patch('cloudregister.registerutils.requests.delete')
@patch('cloudregister.registerutils.get_smt_from_store')
@patch('cloudregister.registerutils.os.path.exists')
@patch('cloudregister.registerutils.HTTPBasicAuth')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.get_credentials')
@patch('cloudregister.registerutils.__get_registered_smt_file_path')
def test_remove_registration_data(
    mock_get_registered_smt_file_path,
    mock_get_creds,
    mock_logging,
    mock_http_basic_auth,
    mock_os_path_exists,
    mock_get_smt_from_store,
    mock_request_delete,
    mock_clean_hosts_file,
    mock_remove_repo_artifacts,
    mock_os_unlink,
    mock_is_scc_connected
):
    mock_get_creds.return_value = 'foo', 'bar'
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="smt-foo.susecloud.net"
         SMTregistryName="registry-foo.susecloud.net"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_smt_from_store.return_value = smt_server
    mock_os_path_exists.return_value = True
    mock_http_basic_auth.return_value = 'http basic auth'
    response = Response()
    response.status_code = 204
    mock_request_delete.return_value = response
    mock_is_scc_connected.return_value = True
    assert utils.remove_registration_data() is None
    print(mock_logging.info.call_args_list)
    assert mock_logging.info.call_args_list == [
        call("Clean current registration server: ('192.168.1.1', 'fc00::1')"),
        call('System successfully removed from update infrastructure'),
        call('Removing system from SCC'),
        call('System successfully removed from SCC')
    ]


@patch('cloudregister.registerutils.is_scc_connected')
@patch('cloudregister.registerutils.os.unlink')
@patch('cloudregister.registerutils.__remove_repo_artifacts')
@patch('cloudregister.registerutils.clean_hosts_file')
@patch('cloudregister.registerutils.requests.delete')
@patch('cloudregister.registerutils.get_smt_from_store')
@patch('cloudregister.registerutils.os.path.exists')
@patch('cloudregister.registerutils.HTTPBasicAuth')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.get_credentials')
@patch('cloudregister.registerutils.__get_registered_smt_file_path')
def test_remove_registration_data_request_not_OK(
    mock_get_registered_smt_file_path,
    mock_get_creds,
    mock_logging,
    mock_http_basic_auth,
    mock_os_path_exists,
    mock_get_smt_from_store,
    mock_request_delete,
    mock_clean_hosts_file,
    mock_remove_repo_artifacts,
    mock_os_unlink,
    mock_is_scc_connected
):
    mock_get_creds.return_value = 'foo', 'bar'
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="smt-foo.susecloud.net"
         SMTregistryName="registry-foo.susecloud.net"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_smt_from_store.return_value = smt_server
    mock_os_path_exists.return_value = True
    mock_http_basic_auth.return_value = 'http basic auth'
    response = Response()
    response.status_code = 504
    mock_request_delete.return_value = response
    mock_is_scc_connected.return_value = True
    assert utils.remove_registration_data() is None
    print(mock_logging.info.call_args_list)
    assert mock_logging.info.call_args_list == [
        call("Clean current registration server: ('192.168.1.1', 'fc00::1')"),
        call(
            'System unknown to update infrastructure, '
            'continue with local changes'
        ),
        call('Removing system from SCC'),
        call(
            'System not found in SCC. The system may still be tracked '
            'against your subscription. It is recommended to investigate '
            'the issue. System user name: "foo". '
            'Local registration artifacts removed.'
        )
    ]


@patch('cloudregister.registerutils.is_scc_connected')
@patch('cloudregister.registerutils.os.unlink')
@patch('cloudregister.registerutils.__remove_repo_artifacts')
@patch('cloudregister.registerutils.clean_hosts_file')
@patch('cloudregister.registerutils.requests.delete')
@patch('cloudregister.registerutils.get_smt_from_store')
@patch('cloudregister.registerutils.os.path.exists')
@patch('cloudregister.registerutils.HTTPBasicAuth')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.get_credentials')
@patch('cloudregister.registerutils.__get_registered_smt_file_path')
def test_remove_registration_data_request_exception(
    mock_get_registered_smt_file_path,
    mock_get_creds,
    mock_logging,
    mock_http_basic_auth,
    mock_os_path_exists,
    mock_get_smt_from_store,
    mock_request_delete,
    mock_clean_hosts_file,
    mock_remove_repo_artifacts,
    mock_os_unlink,
    mock_is_scc_connected
):
    mock_get_creds.return_value = 'foo', 'bar'
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="smt-foo.susecloud.net"
         SMTregistryName="registry-foo.susecloud.net"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_smt_from_store.return_value = smt_server
    mock_os_path_exists.return_value = True
    mock_http_basic_auth.return_value = 'http basic auth'
    response = Response()
    response.status_code = 504
    exception = requests.exceptions.RequestException('foo')
    mock_request_delete.side_effect = exception
    mock_is_scc_connected.return_value = True
    assert utils.remove_registration_data() is None
    print(mock_logging.error.call_args_list)
    assert mock_logging.warning.call_args_list == [
        call('Unable to remove client registration from server'),
        call(exception),
        call(exception)
    ]
    mock_logging.error.assert_called_with(
        'Unable to remove client registration from SCC. '
        'The system is most likely still tracked against your '
        'subscription. Please inform your SCC administrator that '
        'the system with "foo" user should be removed from SCC. '
        'Registration artifacts removed locally.'
    )


@patch('cloudregister.registerutils.add_hosts_entry')
@patch('cloudregister.registerutils.clean_hosts_file')
def test_replace_hosts_entry(mock_clean_hosts_file, mock_add_hosts_entry):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="smt-foo.susecloud.net"
         SMTregistryName="registry-foo.susecloud.net"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    utils.replace_hosts_entry(smt_server, 'new_smt')
    mock_clean_hosts_file.assert_called_once_with('susecloud.net')
    mock_add_hosts_entry.assert_called_once_with('new_smt')


@patch('builtins.print')
@patch('cloudregister.registerutils.sys.exit')
@patch('cloudregister.registerutils.logging')
def test_start_logging(mock_logging, mock_sys_exit, mock_print):
    mock_logging.basicConfig.side_effect = IOError('foo')
    utils.start_logging()
    mock_logging.basicConfig.assert_called_once_with(
        filename='/var/log/cloudregister',
        level=mock_logging.INFO,
        format='%(asctime)s %(levelname)s:%(message)s'
    )
    mock_sys_exit.assert_called_once_with(1)
    mock_print.assert_called_once_with(
        'Could not open log file "',
        '/var/log/cloudregister',
        '" for writing.'
    )


@patch('cloudregister.registerutils.pickle.dump')
@patch('cloudregister.registerutils.pickle')
@patch('cloudregister.registerutils.os.fchmod')
def test_store_smt_data(mock_os_fchmod, mock_pickle, mock_dump):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="smt-foo.susecloud.net"
         SMTregistryName="registry-foo.susecloud.net"
        region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    with tempfile.TemporaryDirectory() as tmpdirname:
        utils.store_smt_data(
            os.path.join(tmpdirname, 'foo'),
            smt_server
        )
    mock_os_fchmod.assert_called_once_with(11, 384)
    mock_pickle.Pickler.assert_called_once()


@patch('cloudregister.registerutils.glob.glob')
@patch('cloudregister.registerutils.get_current_smt')
def test_switch_smt_repos(mock_get_current_smt, mock_glob):
    new_smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="111.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="ANOTHER_NAME"
         SMTregistryName="ANOTHER_REGISTRY_NAME"
         region="antarctica-1"/>''')
    new_smt_server = SMT(etree.fromstring(new_smt_data_ipv46))
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="111.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="plugin:/susecloud"
         SMTregistryName="registry-susecloud"
         region="antarctica-1"/>''')
    current_smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_current_smt.return_value = current_smt_server
    mock_glob.return_value = ['tests/data/repo_foo.repo']
    file_azo = ""
    with open('tests/data/repo_foo.repo') as f:
        file_azo = ' '.join(f.readlines())
    open_mock = mock_open(read_data=file_azo)

    def open_f(filename, *args, **kwargs):
        return open_mock()

    with patch('builtins.open', create=True) as m_open:
        m_open.side_effect = open_f
        utils.switch_smt_repos(new_smt_server)
        assert m_open.call_args_list == [
            call('tests/data/repo_foo.repo', 'r'),
            call('tests/data/repo_foo.repo', 'w')
        ]
        expected_content = file_azo.replace(
           'plugin:/susecloud',
           new_smt_server.get_FQDN()
        )
        m_open(
            'tests/data/repo_foo.repo', 'w'
        ).write.assert_called_once_with(expected_content)


@patch('cloudregister.registerutils.glob.glob')
@patch('cloudregister.registerutils.get_current_smt')
def test_switch_smt_service(mock_get_current_smt, mock_glob):
    new_smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="111.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="ANOTHER_NAME"
         SMTregistryName="ANOTHER_REGISTRY_NAME"
         region="antarctica-1"/>''')
    new_smt_server = SMT(etree.fromstring(new_smt_data_ipv46))
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="111.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="plugin:/susecloud"
         SMTregistryName="registry-susecloud"
         region="antarctica-1"/>''')
    current_smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_current_smt.return_value = current_smt_server
    mock_glob.return_value = ['tests/data/service.service']
    file_azo = ""
    with open('tests/data/repo_foo.repo') as f:
        file_azo = ' '.join(f.readlines())
    open_mock = mock_open(read_data=file_azo)

    def open_f(filename, *args, **kwargs):
        return open_mock()

    with patch('builtins.open', create=True) as m_open:
        m_open.side_effect = open_f
        utils.switch_smt_service(new_smt_server)
        assert m_open.call_args_list == [
            call('tests/data/service.service', 'r'),
            call('tests/data/service.service', 'w')
        ]
        expected_content = file_azo.replace(
            'plugin:/susecloud',
            new_smt_server.get_FQDN()
        )
        m_open(
            'tests/data/repo_foo.repo', 'w'
        ).write.assert_called_once_with(expected_content)


@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.exec_subprocess')
def test_update_ca_chain(mock_exec_subprocess, mock_logging):
    mock_exec_subprocess.return_value = 314
    utils.update_ca_chain(['cmd']) == 1
    assert mock_logging.error.call_args_list == [
        call('Certificate update failed attempt 1'),
        call('Certificate update failed attempt 2'),
        call('Certificate update failed attempt 3')
    ]


@patch('cloudregister.registerutils.exec_subprocess')
def test_update_ca_chain_failed(mock_exec_subprocess):
    mock_exec_subprocess.return_value = 0
    utils.update_ca_chain(['cmd']) == 1


@patch('cloudregister.registerutils.is_new_registration')
def test_update_rmt_cert_new_registration(mock_is_new_registration):
    mock_is_new_registration.return_value = True
    assert utils.update_rmt_cert('foo') is None


@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.get_config')
@patch('cloudregister.registerutils.import_smt_cert')
@patch('cloudregister.registerutils.fetch_smt_data')
@patch('cloudregister.registerutils.set_proxy')
@patch('cloudregister.registerutils.is_new_registration')
def test_update_rmt_cert_no_cert_change(
    mock_is_new_registration,
    mock_set_proxy,
    mock_fetch_smt_data,
    mock_import_smt_cert,
    mock_config,
    mock_logging
):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="111.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="ANOTHER_NAME"
         SMTregistryName="ANOTHER_REGISTRY_NAME"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    smt_xml = dedent('''\
    <regionSMTdata>
      <smtInfo fingerprint="99:88:77:66"
        SMTserverIP="1.2.3.4"
        SMTserverIPv6="fc11::2"
        SMTserverName="foo.susecloud.net"
        SMTregistryName="registry-foo.susecloud.net"
        />
    </regionSMTdata>''')
    region_smt_data = etree.fromstring(smt_xml)

    mock_is_new_registration.return_value = False
    mock_set_proxy.return_value = True
    mock_fetch_smt_data.return_value = region_smt_data
    assert utils.update_rmt_cert(smt_server) is False
    assert mock_logging.info.call_args_list == [
        call('Check for cert update'),
        call('No cert change')
    ]


@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.get_config')
@patch('cloudregister.registerutils.import_smt_cert')
@patch('cloudregister.registerutils.fetch_smt_data')
@patch('cloudregister.registerutils.set_proxy')
@patch('cloudregister.registerutils.is_new_registration')
def test_update_rmt_cert(
    mock_is_new_registration,
    mock_set_proxy,
    mock_fetch_smt_data,
    mock_import_smt_cert,
    mock_config,
    mock_logging
):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="111.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="ANOTHER_NAME"
         SMTregistryName="ANOTHER_REGISTRY_NAME"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    smt_xml = dedent('''\
    <regionSMTdata>
      <smtInfo fingerprint="99:88:77:66"
        SMTserverIP="111.168.1.1"
        SMTserverIPv6="fc00::1"
        SMTserverName="foo.susecloud.net"
        SMTregistryName="registryfoo.susecloud.net"
        />
    </regionSMTdata>''')
    region_smt_data = etree.fromstring(smt_xml)

    mock_is_new_registration.return_value = False
    mock_set_proxy.return_value = True
    mock_fetch_smt_data.return_value = region_smt_data
    assert utils.update_rmt_cert(smt_server) is True
    assert mock_logging.info.call_args_list == [
        call('Check for cert update'),
        call('Update server cert updated')
    ]


def test_uses_rmt_as_scc_proxy():
    assert utils.uses_rmt_as_scc_proxy() is False


@patch('cloudregister.registerutils.json.dumps')
@patch('cloudregister.registerutils.get_framework_identifier_path')
@patch('cloudregister.registerutils.__get_region_server_args')
@patch('cloudregister.registerutils.__get_framework_plugin')
@patch('cloudregister.registerutils.__get_system_mfg')
def test_write_framework_identifier(
    mock_get_system_mfg,
    mock_get_framework_plugin,
    mock_get_region_servers_args,
    mock_get_framework_identifier_path,
    mock_json_dumps
):
    mock_get_system_mfg.return_value = 'unknown'
    mock_plugin = Mock()
    mock_plugin.__file__ = 'amazonec2.py'
    mock_get_framework_plugin.return_value = mock_plugin
    mock_get_region_servers_args.return_value = 'regionHint=eu-central1-d'
    with tempfile.TemporaryDirectory() as tmpdirname:
        # TODO: asumption that framework id path exists
        # if it didnt => unhandled exception
        mock_get_framework_identifier_path.return_value = os.path.join(
            tmpdirname, 'foo'
        )
        with patch('builtins.open', create=True):
            utils.write_framework_identifier('foo')
            # TODO: fix/check framework unknown + plugin OK valid combination
            mock_json_dumps.assert_called_once_with(
                {
                    'framework': 'unknown',
                    'region': 'eu-central1-d',
                    'plugin': 'amazonec2.py'
                }
            )


@patch('cloudregister.registerutils.json.dumps')
@patch('cloudregister.registerutils.get_framework_identifier_path')
@patch('cloudregister.registerutils.__get_region_server_args')
@patch('cloudregister.registerutils.__get_framework_plugin')
@patch('cloudregister.registerutils.__get_system_mfg')
def test_write_framework_identifier_no_region(
    mock_get_system_mfg,
    mock_get_framework_plugin,
    mock_get_region_servers_args,
    mock_get_framework_identifier_path,
    mock_json_dumps
):
    mock_get_system_mfg.return_value = 'unknown'
    mock_plugin = Mock()
    mock_plugin.__file__ = 'amazonec2.py'
    mock_get_framework_plugin.return_value = mock_plugin
    mock_get_region_servers_args.return_value = None
    with tempfile.TemporaryDirectory() as tmpdirname:
        # TODO: asumption that framework id path exists
        # if it didnt => unhandled exception
        mock_get_framework_identifier_path.return_value = os.path.join(
            tmpdirname, 'foo'
        )
        with patch('builtins.open', create=True):
            utils.write_framework_identifier('foo')
            # TODO: fix/check framework unknown + plugin OK valid combination
            mock_json_dumps.assert_called_once_with(
                {
                    'framework': 'unknown',
                    'region': 'unknown',
                    'plugin': 'amazonec2.py'
                }
            )


@patch('cloudregister.registerutils.json.dumps')
@patch('cloudregister.registerutils.get_framework_identifier_path')
@patch('cloudregister.registerutils.__get_region_server_args')
@patch('cloudregister.registerutils.__get_framework_plugin')
@patch('cloudregister.registerutils.__get_system_mfg')
def test_write_framework_identifier_non_existing_path(
    mock_get_system_mfg,
    mock_get_framework_plugin,
    mock_get_region_servers_args,
    mock_get_framework_identifier_path,
    mock_json_dumps
):
    mock_get_system_mfg.return_value = 'unknown'
    mock_plugin = Mock()
    mock_plugin.__file__ = 'amazonec2.py'
    mock_get_framework_plugin.return_value = mock_plugin
    mock_get_region_servers_args.return_value = 'regionHint=eu-central1-d'
    mock_get_framework_identifier_path.return_value = os.path.join(
        'tmpdirname', 'foo'
    )
    with raises(FileNotFoundError):
        utils.write_framework_identifier('foo')


@patch('cloudregister.registerutils.logging')
def test_get_framework_plugin_no_existing(mock_logging):
    cfg = get_test_config()
    cfg.add_section('instance')
    cfg.set('instance', 'instanceArgs', 'foo')
    assert utils.__get_framework_plugin(cfg) is None
    mock_logging.warning.assert_called_once_with(
        'Configured instanceArgs module could not be loaded. '
        'Continuing without additional arguments.'
    )


def test_get_framework_plugin():
    cfg = get_test_config()
    cfg.add_section('instance')
    cfg.set('instance', 'instanceArgs', 'amazonec2')
    expected_mod = __import__('cloudregister.amazonec2', fromlist=[''])
    assert utils.__get_framework_plugin(cfg) == expected_mod
    cfg.set('instance', 'instanceArgs', 'none')


@patch('cloudregister.registerutils.glob.glob')
def test_get_referenced_credentials(mock_glob):
    mock_glob.return_value = ['tests/data/repo_foo.repo']
    assert utils.__get_referenced_credentials('foo') == [
        'SUSE_Linux_Enterprise_Live_Foo_x86_64'
    ]


@patch('cloudregister.registerutils.get_config')
@patch('cloudregister.registerutils.glob.glob')
def test_get_referenced_credentials_not_found(mock_glob, mock_get_config):
    mock_glob.return_value = ['tests/data/repo_foo.repo']
    cfg = get_test_config()
    cfg.set('server', 'baseurl', 'bar')
    mock_get_config.return_value = cfg
    assert utils.__get_referenced_credentials('foo') == []


@patch('cloudregister.registerutils.logging')
def test_get_region_server_args_exception(
    mock_logging
):
    mod = __import__('cloudregister.smt', fromlist=[''])
    assert utils.__get_region_server_args(mod) == ''
    mock_logging.error.assert_called_once_with(
        'Configured and loaded module "{}" does not provide the required '
        'generateRegionSrvArgs function.'.format(mod.__file__)
    )


@patch('cloudregister.registerutils.logging')
@patch('cloudregister.amazonec2.generateRegionSrvArgs')
def test_get_region_server_args_not_region_srv_args(
    mock_amazon_generate_region_args,
    mock_logging
):
    mock_amazon_generate_region_args.return_value = None
    mod = __import__('cloudregister.amazonec2', fromlist=[''])
    assert utils.__get_region_server_args(mod) is None
    mock_logging.assert_not_called


@patch('cloudregister.registerutils.os.path.basename')
@patch('cloudregister.registerutils.glob.glob')
def test_get_service_plugins(mock_glob, mock_os_path_basename):
    mock_glob.return_value = ['tests/data/service.service']
    mock_os_path_basename.return_value = 'cloudguest-repo-service'
    assert utils.__get_service_plugins() == ['tests/data/service.service']


@patch('cloudregister.registerutils.exec_subprocess')
def test_get_system_mfg(mock_exec_subprocess):
    mock_exec_subprocess.side_effect = TypeError('foo')
    assert utils.__get_system_mfg() == 'unknown'


@patch('cloudregister.registerutils.__get_referenced_credentials')
@patch('cloudregister.registerutils.glob.glob')
def test_has_credentials_in_system(mock_glob, mock_get_referenced_creds):
    mock_glob.return_value = ['/etc/zypp/credentials.d/SCCcredentials']
    assert utils.__has_credentials('foo') is True


@patch('cloudregister.registerutils.__get_referenced_credentials')
@patch('cloudregister.registerutils.glob.glob')
def test_has_credentials_in_service(mock_glob, mock_get_referenced_creds):
    mock_glob.return_value = ['/etc/zypp/credentials.d/service']
    mock_get_referenced_creds.return_value = ['service']
    assert utils.__has_credentials('foo') is True


@patch('cloudregister.registerutils.__get_referenced_credentials')
@patch('cloudregister.registerutils.glob.glob')
def test_has_credentials_not_found(mock_glob, mock_get_referenced_creds):
    mock_glob.return_value = []
    assert utils.__has_credentials('foo') is False


@patch('cloudregister.registerutils.store_smt_data')
@patch('cloudregister.registerutils.fetch_smt_data')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.get_config')
@patch('cloudregister.registerutils.set_proxy')
def test_populate_srv_cache(
    mock_set_proxy,
    mock_get_config,
    mock_logging,
    mock_fetch_smt_data,
    mock_store_smt_data
):
    mock_set_proxy.return_value = True
    mock_get_config.return_value = get_test_config()
    smt_xml = dedent('''\
    <regionSMTdata>
      <smtInfo fingerprint="99:88:77:66"
        SMTserverIP="1.2.3.4"
        SMTserverIPv6="fc11::2"
        SMTserverName="foo.susecloud.net"
        SMTregistryName="registry-foo.susecloud.net"
        />
    </regionSMTdata>''')
    region_smt_data = etree.fromstring(smt_xml)
    mock_fetch_smt_data.return_value = region_smt_data
    utils.__populate_srv_cache()
    mock_logging.info.assert_called_once_with('Populating server cache')
    smt_data_ipv46 = dedent('''\
      <smtInfo fingerprint="99:88:77:66"
        SMTserverIP="1.2.3.4"
        SMTserverIPv6="fc11::2"
        SMTserverName="foo.susecloud.net"
        SMTregistryName="registry-foo.susecloud.net"
        />''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_store_smt_data.assert_called_once_with(
        '/var/cache/cloudregister/availableSMTInfo_1.obj',
        smt_server
    )


@patch('cloudregister.registerutils.os.unlink')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.__get_referenced_credentials')
@patch('cloudregister.registerutils.glob.glob')
def test_remove_credentials(
    mock_glob,
    mock_get_referenced_creds,
    mock_logging,
    mock_os_unlink
):
    mock_glob.return_value = ['/etc/zypp/credentials.d/SCCcredentials']
    mock_get_referenced_creds.return_value = ['SCCcredentials']
    assert utils.__remove_credentials('foo') == 1
    mock_logging.info.assert_called_once_with(
        'Removing credentials: /etc/zypp/credentials.d/SCCcredentials'
    )
    mock_os_unlink.assert_called_once_with(
        '/etc/zypp/credentials.d/SCCcredentials'
    )


@patch('cloudregister.registerutils.os.unlink')
@patch('cloudregister.registerutils.os.path.exists')
@patch('cloudregister.registerutils.__remove_service')
@patch('cloudregister.registerutils.__remove_repos')
@patch('cloudregister.registerutils.__remove_credentials')
def test_remove_artifacts(
    mock_remove_creds,
    mock_remove_repos,
    mock_remove_service,
    mock_os_path_exists,
    mock_os_unlink
):
    mock_os_path_exists.return_value = True
    assert utils.__remove_repo_artifacts('foo') is None
    mock_remove_creds.assert_called_once_with('foo')
    mock_remove_repos.assert_called_once_with('foo')
    mock_remove_service.assert_called_once_with('foo')
    mock_os_path_exists.assert_called_once_with('/etc/SUSEConnect')
    mock_os_unlink.assert_called_once_with('/etc/SUSEConnect')


@patch('cloudregister.registerutils.os.unlink')
@patch('cloudregister.registerutils.os.path.exists')
@patch('cloudregister.registerutils.__remove_service')
@patch('cloudregister.registerutils.__remove_repos')
@patch('cloudregister.registerutils.__remove_credentials')
def test_remove_artifacts_no_remove_etc_scccreds(
    mock_remove_creds,
    mock_remove_repos,
    mock_remove_service,
    mock_os_path_exists,
    mock_os_unlink
):
    assert utils.__remove_repo_artifacts('foo') is None
    mock_remove_creds.assert_called_once_with('foo')
    mock_remove_repos.assert_called_once_with('foo')
    mock_remove_service.assert_called_once_with('foo')
    mock_os_path_exists.assert_called_once_with('/etc/SUSEConnect')
    mock_os_unlink.assert_not_called


@patch('cloudregister.registerutils.glob.glob')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.os.unlink')
def test_remove_repos(mock_os_unlink, mock_logging, mock_glob):
    mock_glob.return_value = ['tests/data/repo_foo.repo']
    assert utils.__remove_repos('foo') == 1
    mock_os_unlink.assert_called_once_with('tests/data/repo_foo.repo')
    mock_logging.info.called_once_with('Removing repo: repo_foo.repo')


@patch('cloudregister.registerutils.glob.glob')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.os.unlink')
def test_remove_repos_removed_nothing(mock_os_unlink, mock_logging, mock_glob):
    mock_glob.return_value = ['tests/data/scc_repo.repo']
    assert utils.__remove_repos('foo') == 1
    mock_os_unlink.not_called()
    mock_logging.info.not_called()


@patch('cloudregister.registerutils.__get_service_plugins')
@patch('cloudregister.registerutils.glob.glob')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.os.unlink')
def test_remove_service_not_plugins(
    mock_os_unlink,
    mock_logging,
    mock_glob,
    mock_get_service_plugin
):
    mock_glob.return_value = ['tests/data/service.service']
    mock_get_service_plugin.return_value = []
    assert utils.__remove_service('192') == 1
    mock_os_unlink.assert_called_once_with('tests/data/service.service')
    mock_logging.info.called_once_with('Removing repo: service.service')


@patch('cloudregister.registerutils.__get_service_plugins')
@patch('cloudregister.registerutils.glob.glob')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.os.unlink')
def test_remove_service(
    mock_os_unlink,
    mock_logging,
    mock_glob,
    mock_get_service_plugins
):
    mock_glob.return_value = []
    mock_get_service_plugins.return_value = ['foo']
    assert utils.__remove_service('192') == 1
    mock_os_unlink.assert_called_once_with('foo')
    mock_logging.info.not_called()


@patch('cloudregister.registerutils.has_network_access_by_ip_address')
def test_has_ipv4_access(mock_has_network_access):
    mock_has_network_access.return_value = True
    assert utils.has_ipv4_access()


@patch('cloudregister.registerutils.has_network_access_by_ip_address')
def test_has_ipv6_access(mock_has_network_access):
    mock_has_network_access.return_value = True
    assert utils.has_ipv6_access()


@patch('cloudregister.registerutils.socket.create_connection')
def test_has_network_access_by_ip_address(mock_socket_create_connection):
    assert utils.has_network_access_by_ip_address('1.1.1.1')


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.socket.create_connection')
def test_has_network_access_by_ip_address_no_connection(
        mock_socket_create_connection, mock_logging
        ):
    mock_socket_create_connection.side_effect = OSError
    has_access = utils.has_network_access_by_ip_address('FFF::0')
    assert not has_access
    assert mock_logging.info.called_once_with(
        'Skipping IPv6 protocol version, no network configuration'
    )


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.set_registries_conf')
@patch('cloudregister.registerutils.set_container_engines_env_vars')
@patch('cloudregister.registerutils.os.path.exists')
@patch('cloudregister.registerutils.os.makedirs')
@patch('cloudregister.registerutils.json.dump')
@patch('cloudregister.registerutils.json.load')
def test_setup_registry_empty_file(
    mock_json_load, mock_json_dump, mock_os_makedirs,
    mock_os_path_exists, mock_set_container_engines_env_vars, _
):
    mock_os_path_exists.return_value = [False, True]
    mock_json_load.return_value = {}
    with patch('builtins.open', create=True) as mock_open:
        file_handle = mock_open.return_value.__enter__.return_value
        utils.setup_registry(
            'registry-supercloud.susecloud.net',
            'login',
            'pass'
        )
        assert mock_open.call_args_list == [
            call('/etc/containers/config.json', 'r'),
            call('/etc/containers/config.json', 'w')
        ]
        mock_json_dump.assert_called_once_with(
            {
                'auths': {
                    'registry-supercloud.susecloud.net': {
                        'auth': 'bG9naW46cGFzcw=='
                    }
                }
            },
            file_handle
        )


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.set_registries_conf')
@patch('cloudregister.registerutils.set_container_engines_env_vars')
@patch('cloudregister.registerutils.os.path.exists')
@patch('cloudregister.registerutils.os.makedirs')
@patch('cloudregister.registerutils.json.dump')
def test_setup_registry_file_not_exists(
    mock_json_dump, _mock_os_makedirs,  mock_os_path_exists,
    _mock_set_container_env_vars, _mock_set_reg_conf
):
    mock_os_path_exists.side_effect = [False, False]
    with patch('builtins.open', create=True) as mock_open:
        file_handle = mock_open.return_value.__enter__.return_value
        utils.setup_registry(
            'registry-supercloud.susecloud.net',
            'login',
            'pass'
        )
        assert mock_open.call_args_list == [
            call('/etc/containers/config.json', 'w')
        ]
        mock_json_dump.assert_called_once_with(
            {
                'auths': {
                    'registry-supercloud.susecloud.net': {
                        'auth': 'bG9naW46cGFzcw=='
                    }
                }
            },
            file_handle
        )


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.set_registries_conf')
@patch('cloudregister.registerutils.set_container_engines_env_vars')
@patch('cloudregister.registerutils.os.path.exists')
@patch('cloudregister.registerutils.os.makedirs')
@patch('cloudregister.registerutils.json.dump')
@patch('cloudregister.registerutils.json.load')
def test_setup_registry_content(
    mock_json_load, mock_json_dump,
    mock_os_makedirs, mock_os_path_exists,
    mock_set_env_vars, mock_set_reg_conf
):
    mock_os_path_exists.return_value = True
    mock_json_load.return_value = {
        'auths': {
            'some-domain.com': {'auth': 'foo'}
        }
    }
    with patch('builtins.open', create=True) as mock_open:
        file_handle = mock_open.return_value.__enter__.return_value
        utils.setup_registry(
            'registry-supercloud.susecloud.net',
            'login',
            'pass'
        )
        assert mock_open.call_args_list == [
            call('/etc/containers/config.json', 'r'),
            call('/etc/containers/config.json', 'w')
        ]
        mock_json_dump.assert_called_once_with(
            {
                'auths': {
                    'some-domain.com': {'auth': 'foo'},
                    'registry-supercloud.susecloud.net': {
                        'auth': 'bG9naW46cGFzcw=='
                    }
                }
            },
            file_handle
        )


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.exec_subprocess')
@patch('cloudregister.registerutils.os.path.exists')
@patch('cloudregister.registerutils.os.makedirs')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.json.load')
def test_setup_registry_content_json_error_preserve_fail(
    mock_json_load, mock_logging, mock_os_makedirs,
    mock_os_path_exists, mock_exec_subprocess
):
    mock_os_path_exists.return_value = [False, True]
    mock_json_load.side_effect = json.decoder.JSONDecodeError('a', 'b', 1)
    mock_exec_subprocess.return_value = 1
    with patch('builtins.open', create=True) as mock_open:
        mock_exec_subprocess.return_value = 1
        assert utils.setup_registry(
            'registry-supercloud.susecloud.net',
            'login',
            'pass'
        ) is False
        mock_open.assert_called_once_with('/etc/containers/config.json', 'r')
        log_calls = [
            call(
                'Unable to parse existing /etc/containers/config.json, '
                'preserving file as /etc/containers/config.json.bak, '
                'writing new credentials'
            ),
            call('File not preserved.')
        ]
        assert mock_logging.info.call_args_list == log_calls
        mock_exec_subprocess.assert_called_once_with(
            ['mv', '-Z',
             '/etc/containers/config.json',
             '/etc/containers/config.json.bak']
        )


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.exec_subprocess')
@patch('cloudregister.registerutils.os.path.exists')
@patch('cloudregister.registerutils.os.makedirs')
@patch('cloudregister.registerutils.logging')
def test_setup_registry_content_open_file_error(
    mock_logging, mock_os_makedirs,
    mock_os_path_exists, mock_exec_subprocess
):
    mock_os_path_exists.return_value = True
    with patch('builtins.open', create=True) as mock_open:
        mock_open.side_effect = OSError('oh no ! an error')
        mock_exec_subprocess.return_value = 1
        assert utils.setup_registry(
            'registry-supercloud.susecloud.net',
            'login',
            'pass'
        ) is False
        mock_open.assert_called_once_with('/etc/containers/config.json', 'r')
        log_calls = [
            call('oh no ! an error'),
            call(
                'Unable to open existing /etc/containers/config.json, '
                'preserving file as /etc/containers/config.json.bak, '
                'writing new credentials'
            ),
            call('File not preserved.')
        ]
        assert mock_logging.info.call_args_list == log_calls
        mock_exec_subprocess.assert_called_once_with(
            ['mv', '-Z',
             '/etc/containers/config.json',
             '/etc/containers/config.json.bak']
        )


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.os.path.exists')
@patch('cloudregister.registerutils.os.makedirs')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.json.dump')
@patch('cloudregister.registerutils.json.load')
def test_setup_registry_content_write_error(
    mock_json_load, mock_json_dump, mock_logging,
    mock_os_makedirs, mock_os_path_exists
):
    mock_os_path_exists.side_effect = [False, False]
    mock_os_path_exists.return_value = False
    mock_json_dump.side_effect = Exception('something happened !')
    with patch('builtins.open', create=True) as mock_open:
        utils.setup_registry(
            'registry-supercloud.susecloud.net',
            'login',
            'pass'
        )
        mock_open.assert_called_once_with(
            '/etc/containers/config.json', 'w'
        )
        mock_logging.error.assert_called_once_with(
            'Could not add the registry credentials: something happened !'
        )


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.update_bashrc')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.os.path.exists')
def test_set_container_engines_env_vars_new(
    mock_os_path_exists, mock_logging, mock_up_bashrc
):
    bashrc_content = """
export foo=bar
"""
    expected_ouput = (
        '\nexport REGISTRY_AUTH_FILE=/etc/containers/config.json\n'
        '\nexport DOCKER_CONFIG=/etc/containers\n'
    )
    mock_os_path_exists.return_value = True
    with patch('builtins.open', mock_open(read_data=bashrc_content)):
        utils.set_container_engines_env_vars()
        mock_up_bashrc.assert_called_once_with(expected_ouput, 'a')


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.os.path.exists')
def test_set_container_engines_env_vars_no_update(
    mock_os_path_exists, mock_logging
):
    bashrc_content = """
export foo=bar

export REGISTRY_AUTH_FILE=/etc/containers/config.json

export DOCKER_CONFIG=/etc/containers

"""
    mock_os_path_exists.return_value = True
    with patch('builtins.open', mock_open(read_data=bashrc_content)):
        utils.set_container_engines_env_vars()


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.__mv_file_backup')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.os.path.exists')
def test_set_container_engines_env_vars_file_error(
    mock_os_path_exists, mock_logging, mock_mv
):
    mock_os_path_exists.return_value = True
    with patch('builtins.open', create=True) as mock_open:
        mock_open.side_effect = OSError('an error !')
        assert utils.set_container_engines_env_vars() is False
        assert mock_logging.info.call_args_list == [
            call('Could not open /etc/profile.local: an error !')
        ]


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.logging')
def test_update_bashrc_open_file_OK(
    mock_logging
):

    with patch('builtins.open', create=True) as mock_open:
        assert utils.update_bashrc({'foo': 'bar'}, 'w')
        mock_open.assert_called_once_with('/etc/profile.local', 'w')
        mock_logging.info.assert_called_once_with(
            '/etc/profile.local updated'
        )


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.clean_bashrc_local')
@patch('cloudregister.registerutils.os.path.exists')
@patch('cloudregister.registerutils.logging')
def test_unset_env_vars_no_env_vars_in_file(
    mock_logging, mock_os_path_exists, mock_clean_bashrc_local
):
    mock_os_path_exists.return_value = True
    mock_clean_bashrc_local.return_value = [], False, False, False
    assert utils.unset_env_vars() is True
    mock_logging.info.assert_called_once_with(
        'Environment variables not present in /etc/profile.local'
    )


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.clean_bashrc_local')
@patch('cloudregister.registerutils.os.path.exists')
def test_unset_env_vars_no_file_access_no_backup(
    mock_os_path_exists, mock_clean_bashrc_local
):
    mock_os_path_exists.return_value = True
    mock_clean_bashrc_local.return_value = [], False, True, True
    assert utils.unset_env_vars() is False


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.update_bashrc')
@patch('cloudregister.registerutils.clean_bashrc_local')
@patch('cloudregister.registerutils.os.path.exists')
def test_unset_env_vars_modified_content(
    mock_os_path_exists, mock_clean_bashrc_local, mock_update_bashrc
):
    mock_os_path_exists.return_value = True
    mock_clean_bashrc_local.return_value = ['no-registry'], True, False, False
    mock_update_bashrc.return_value = True
    assert utils.unset_env_vars() is True
    mock_update_bashrc.called_once_with('no-registry', 'w')


# ---------------------------------------------------------------------------
def test_clean_bashrc_local():
    bashrc_content = """
export foo=bar

export REGISTRY_AUTH_FILE=/etc/containers/config.json

export DOCKER_CONFIG=/etc/containers

"""
    with patch('builtins.open', mock_open(read_data=bashrc_content)):
        new_lines, modified, keep_failed, mv = utils.clean_bashrc_local(
            ['REGISTRY_AUTH_FILE', 'DOCKER_CONFIG']
        )
        assert new_lines == ['\n', 'export foo=bar\n', '\n', '\n', '\n']
        assert modified
        assert modified is True
        assert not keep_failed
        assert not mv


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.__mv_file_backup')
@patch('cloudregister.registerutils.logging')
def test_clean_bashrc_local_open_error(mock_logging, mock_mv_file_backup):
    mock_mv_file_backup.return_value = 0
    with patch('builtins.open', create=True) as mock_open:
        mock_open.side_effect = OSError('oh no !')
        new_lines, modified, keep_failed, mv = utils.clean_bashrc_local(
            ['REGISTRY_AUTH_FILE', 'DOCKER_CONFIG']
        )
        assert new_lines == []
        assert not modified
        assert not keep_failed
        assert mv
        mock_mv_file_backup.assert_called_once_with('/etc/profile.local')
        mock_logging.info.assert_called_once_with(
            'Could not open /etc/profile.local: oh no !'
        )


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.os.unlink')
@patch('cloudregister.registerutils.os.path.exists')
def test_clean_registry_content_no_file(mock_os_path_exists, mock_os_unlink):
    mock_os_path_exists.return_value = False
    assert utils.clean_registry_setup() is None


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.get_smt_from_store')
@patch('cloudregister.registerutils.__get_registered_smt_file_path')
@patch('cloudregister.registerutils.clean_registries_conf')
@patch('cloudregister.registerutils.clean_registry_auth')
@patch('cloudregister.registerutils.os.path.exists')
def test_clean_registry_content_file_exists(
    mock_os_path_exists, mock_clean_registry_auth, mock_clean_reg_conf,
    mock_get_registered_smt, mock_get_smt_from_store
):
    mock_os_path_exists.return_value = True
    smt_data_ipv46 = dedent('''\
      <smtInfo fingerprint="99:88:77:66"
        SMTserverIP="1.2.3.4"
        SMTserverIPv6="fc11::2"
        SMTserverName="foo.susecloud.net"
        SMTregistryName="registry-foo.susecloud.net"
        />''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_smt_from_store.return_value = smt_server
    assert utils.clean_registry_setup() is None


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.os.unlink')
@patch('cloudregister.registerutils.os.path.exists')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.json.load')
def test_clean_registry_auth_empty_file(
    mock_json_load, mock_logging, mock_os_path_exists, mock_os_unlink
):
    mock_json_load.return_value = {}
    mock_os_path_exists.return_value = True
    with patch('builtins.open', create=True) as mock_open:
        assert utils.clean_registry_auth('registry-foo.susecloud.net')
        mock_open.assert_called_once_with(
            '/etc/containers/config.json', 'r'
        )
        assert mock_logging.info.call_args_list == [
            call('JSON content is empty')
        ]


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.__generate_registry_auth_token')
@patch('cloudregister.registerutils.os.path.exists')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.json.load')
def test_clean_registry_auth_no_registry_entry_in_file(
    mock_json_load, mock_logging, mock_os_path_exists,
    mock_generate_registry_auth_token
):
    mock_generate_registry_auth_token.return_value = 'auth_token'
    mock_json_load.return_value = {
        'auths': {'another_fqdn.com': 'bar'},
        'more_keys': 'and_content'
    }
    with patch('builtins.open', create=True) as mock_open:
        assert utils.clean_registry_auth('registry-foo.susecloud.net') is None
        mock_open.assert_called_once_with('/etc/containers/config.json', 'r')
        mock_logging.info.assert_called_once_with(
            'Unsetting the auth entry for registry-foo.susecloud.net'
        )


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.set_registries_conf')
@patch('cloudregister.registerutils.exec_subprocess')
@patch('cloudregister.registerutils.__generate_registry_auth_token')
@patch('cloudregister.registerutils.os.path.exists')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.json.load')
def test_clean_registry_auth_no_registry_entry_in_file_wrong_dict_content(
    mock_json_load, mock_logging, mock_os_path_exists,
    mock_generate_registry_auth_token, mock_exec_subprocess,
    mock_set_Registries_conf
):
    mock_generate_registry_auth_token.return_value = 'auth_token'
    mock_json_load.return_value = {'auths': 'bar'}
    mock_exec_subprocess.return_value = 0
    with patch('builtins.open', create=True) as mock_open:
        assert utils.clean_registry_auth('registry-foo.susecloud.net') is None
        mock_open.assert_called_once_with('/etc/containers/config.json', 'r')
        assert mock_logging.info.call_args_list == [
            call(
                'Preserving file /etc/containers/config.json as '
                '/etc/containers/config.json.bak'
            ),
            call('File preserved.')
        ]
        mock_logging.error.assert_called_once_with(
            'The entry for "auths" key is not a dictionary'
        )


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.exec_subprocess')
@patch('cloudregister.registerutils.get_credentials')
@patch('cloudregister.registerutils.os.path.exists')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.json.load')
def test_clean_registry_content_json_error(
    mock_json_load, mock_logging, mock_os_path_exists,
    mock_get_credentials, mock_exec_subprocess
):
    mock_json_load.side_effect = json.decoder.JSONDecodeError('a', 'b', 1)
    mock_get_credentials.return_value = ('SCC_login', 'password')
    mock_exec_subprocess.return_value = 1
    with patch('builtins.open', create=True) as mock_open:
        utils.clean_registry_auth('registry-foo.susecloud.net')
        mock_open.assert_called_once_with('/etc/containers/config.json', 'r')
        log_calls = [
            call(
                'Unable to parse existing /etc/containers/config.json, '
                'preserving file as /etc/containers/config.json.bak'
            ),
            call('File not preserved.')
        ]
        assert mock_logging.info.call_args_list == log_calls


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.__generate_registry_auth_token')
@patch('cloudregister.registerutils.os.path.exists')
@patch('cloudregister.registerutils.json.dump')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.get_smt_from_store')
@patch('cloudregister.registerutils.__get_registered_smt_file_path')
@patch('cloudregister.registerutils.json.load')
def test_clean_registry_auth_content_write(
    mock_json_load, mock_get_registered_smt,
    mock_get_smt_from_store, mock_logging, mock_json_dump,
    mock_os_path_exists, mock_generate_registry_auth_token
):
    registry_fqdn = 'registry-foo.susecloud.net'
    mock_generate_registry_auth_token.return_value = 'foo'
    mock_json_load.return_value = {
        'auths': {
            registry_fqdn: 'foo',
            'another_fqdn.com': 'bar'
        },
        'more_keys': 'and_content'
    }
    with patch('builtins.open', create=True) as mock_open:
        file_handle = mock_open.return_value.__enter__.return_value
        utils.clean_registry_auth(registry_fqdn)
        assert mock_open.call_args_list == [
            call('/etc/containers/config.json', 'r'),
            call('/etc/containers/config.json', 'w')
        ]
        mock_json_dump.assert_called_once_with(
            {
                'auths': {
                    'another_fqdn.com': 'bar'
                },
                'more_keys': 'and_content'
            },
            file_handle
        )
        log_calls = [
            call('Unsetting the auth entry for registry-foo.susecloud.net'),
            call('Registry auth entry unset'),
            call(
                'Credentials for the registry removed '
                'in /etc/containers/config.json'
            )
        ]
        assert mock_logging.info.call_args_list == log_calls


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.get_credentials')
@patch('cloudregister.registerutils.os.path.exists')
@patch('cloudregister.registerutils.json.dump')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.json.load')
def test_clean_registry_auth_content_write_no_smt_token_based(
    mock_json_load, mock_logging, mock_json_dump,
    mock_os_path_exists, mock_get_credentials
):
    mock_json_load.return_value = {
        'auths': {                        # username:pass encoded
            "registry-foo.susecloud.net": 'dXNlcm5hbWU6cGFzcw==',
            'another_fqdn.com': 'bar'
        },
        'more_keys': 'and_content'
    }
    mock_get_credentials.return_value = 'username', 'pass'
    with patch('builtins.open', create=True) as mock_open:
        file_handle = mock_open.return_value.__enter__.return_value
        utils.clean_registry_auth(registry_fqdn='')
        assert mock_open.call_args_list == [
            call('/etc/containers/config.json', 'r'),
            call('/etc/containers/config.json', 'w')
        ]
        mock_json_dump.assert_called_once_with(
            {
                'auths': {
                    'another_fqdn.com': 'bar'
                },
                'more_keys': 'and_content'
            },
            file_handle
        )
        log_calls = [
            call('Unsetting the auth entry based on the token'),
            call('Registry auth entry unset'),
            call(
                'Credentials for the registry removed '
                'in /etc/containers/config.json'
            )
        ]
        assert mock_logging.info.call_args_list == log_calls


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.__generate_registry_auth_token')
@patch('cloudregister.registerutils.os.unlink')
@patch('cloudregister.registerutils.os.path.exists')
@patch('cloudregister.registerutils.json.dump')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.get_smt_from_store')
@patch('cloudregister.registerutils.__get_registered_smt_file_path')
@patch('cloudregister.registerutils.json.load')
def test_clean_registry_auth_content_same_entry_only(
    mock_json_load, mock_get_registered_smt,
    mock_get_smt_from_store, mock_logging, mock_json_dump,
    mock_os_path_exists, mock_os_unlink, mock_generate_auth_token
):
    registry_fqdn = 'registry-foo.susecloud.net'
    mock_json_load.return_value = {
        'auths': {registry_fqdn: 'foo'}
    }
    mock_json_dump.side_effect = Exception('something happened !')
    with patch('builtins.open', create=True) as mock_open:
        utils.clean_registry_auth(registry_fqdn)
        assert mock_open.call_args_list == [
            call('/etc/containers/config.json', 'r')
        ]
        mock_os_unlink.assert_called_once_with('/etc/containers/config.json')


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.__generate_registry_auth_token')
@patch('cloudregister.registerutils.os.unlink')
@patch('cloudregister.registerutils.os.path.exists')
@patch('cloudregister.registerutils.json.dump')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.json.load')
def test_clean_registry_auth_content_same_entry_only_token_based(
    mock_json_load, mock_logging, mock_json_dump,
    mock_os_path_exists, mock_os_unlink, mock_generate_auth_token
):
    mock_json_load.return_value = {'auths': {'foo.susecloud.net': 'foo'}}
    mock_json_dump.side_effect = Exception('something happened !')
    mock_generate_auth_token.return_value = 'foo'
    with patch('builtins.open', create=True) as mock_open:
        utils.clean_registry_auth(registry_fqdn='')
        assert mock_open.call_args_list == [
            call('/etc/containers/config.json', 'r')
        ]
        mock_os_unlink.assert_called_once_with('/etc/containers/config.json')


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.same_registry_auth_content')
@patch('cloudregister.registerutils.os.unlink')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.get_registry_credentials')
def test_clean_registry_auth_content_not_relevant_json(
    mock_get_registry_credentials, mock_logging,
    mock_os_unlink, mock_same_registry_auth_content
):
    mock_get_registry_credentials.return_value = {'auths': {}}, None
    mock_same_registry_auth_content.return_value = False
    assert utils.clean_registry_auth(registry_fqdn='')
    mock_logging.info.called_once_with('JSON content is empty')


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.logging')
def test_update_bashrc_open_file_error(mock_logging):

    with patch('builtins.open', create=True) as mock_open:
        mock_open.side_effect = OSError('oh no !')
        utils.update_bashrc({'foo': 'bar'}, 'a')
        mock_open.assert_called_once_with('/etc/profile.local', 'a')
        mock_logging.error.assert_called_once_with(
            'Could not update /etc/profile.local: oh no !'
        )


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.is_suma_instance')
@patch('cloudregister.registerutils.get_registry_conf_file')
@patch('cloudregister.registerutils.os.path.exists')
def test_set_registries_conf(
    mock_os_path_exists, mock_get_reg_conf_file, mock_is_suma
):
    mock_os_path_exists.return_value = True
    mock_is_suma.return_value = False
    mock_get_reg_conf_file.return_value = {}, True
    assert utils.set_registries_conf('foo') is False


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.get_registry_conf_file')
@patch('cloudregister.registerutils.os.path.exists')
def test__set_registries_conf_podman_OK_content(
    mock_os_path_exists, mock_get_reg_conf_file
):
    mock_os_path_exists.return_value = True
    mock_get_reg_conf_file.return_value = {
        'unqualified-search-registries': [
            'registry-ec2.susecloud.net', 'registry.suse.com'
        ],
        'registry': [
            {'location': 'registry-ec2.susecloud.net', 'insecure': False}
        ]
    }, False
    assert utils.__set_registries_conf_podman(
        'registry-ec2.susecloud.net'
    ) is None


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.toml.dump')
@patch('cloudregister.registerutils.get_registry_conf_file')
@patch('cloudregister.registerutils.os.path.exists')
def test__set_registries_conf_podman_content_setup_private_registry(
    mock_os_path_exists, mock_get_reg_conf_file,
    mock_toml_dump, mock_logging
):
    mock_os_path_exists.return_value = True
    mock_get_reg_conf_file.return_value = {
        'unqualified-search-registries': [
            'foo.com', 'registry.suse.com'
        ],
        'registry': [
            {'location': 'foo', 'insecure': False}
        ]
    }, False
    with patch('builtins.open', create=True) as mock_open:
        file_handle = mock_open.return_value.__enter__.return_value
        assert utils.__set_registries_conf_podman('registry-ec2.susecloud.net')
        mock_toml_dump.assert_called_once_with(
            {
                'unqualified-search-registries': [
                    'registry-ec2.susecloud.net',
                    'foo.com',
                    'registry.suse.com'
                ],
                'registry': [
                    {
                        'location': 'foo',
                        'insecure': False
                    },
                    {
                        'location': 'registry-ec2.susecloud.net',
                        'insecure': False
                    }
                ]
            },
            file_handle
        )
        assert mock_logging.info.call_args_list == [
            call(
                'Content for /etc/containers/registries.conf has changed, '
                'updating the file'
            ),
            call('File /etc/containers/registries.conf updated')
        ]


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.toml.dump')
@patch('cloudregister.registerutils.get_registry_conf_file')
@patch('cloudregister.registerutils.os.path.exists')
def test__set_registries_conf_podman_content_not_OK_order_has_changed(
    mock_os_path_exists, mock_get_reg_conf_file,
    mock_toml_dump, mock_logging
):
    mock_os_path_exists.return_value = True
    mock_get_reg_conf_file.return_value = {
        'unqualified-search-registries': [
            'foo.com', 'registry.suse.com', 'registry-ec2.susecloud.net'
        ],
        'registry': [
            {'location': 'foo', 'insecure': False},
            {'location': 'registry-ec2.susecloud.net', 'insecure': True}
        ]
    }, False
    with patch('builtins.open', create=True):
        # someone has manually modified the registries setup
        # Don't touch it. Users can fix via --clean re-registration
        assert utils.__set_registries_conf_podman(
            'registry-ec2.susecloud.net'
        ) is None


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.toml.load')
@patch('cloudregister.registerutils.os.path.exists')
def test__set_registries_conf_podman_file_open_error(
    mock_os_path_exists, mock_toml_load, mock_logging
):
    mock_os_path_exists.return_value = True
    mock_toml_load.return_value = {
        'unqualified-search-registries': [
            'foo.com', 'registry-ec2.susecloud.net'
        ],
        'registry': [
            {'location': 'foo', 'insecure': True},
            {'location': 'registry-ec2.susecloud.net', 'insecure': False}
        ]
    }
    with patch('builtins.open', create=True) as mock_open:
        mock_open.side_effect = [
            MagicMock(spec=io.IOBase).return_value,
            OSError('oh no !')
        ]
        assert utils.__set_registries_conf_podman(
            'registry-ec2.susecloud.net'
        ) is None
        assert mock_open.call_args_list == [
            call('/etc/containers/registries.conf', 'r'),
            call('/etc/containers/registries.conf', 'w')
        ]
        assert mock_logging.info.call_args_list == [
            call(
                'Content for /etc/containers/registries.conf has changed, '
                'updating the file'
            ),
            call('oh no !')
        ]
        assert mock_logging.error.call_args_list == [
            call('Could not open /etc/containers/registries.conf')
        ]


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.exec_subprocess')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.toml.load')
@patch('cloudregister.registerutils.os.path.exists')
def test__set_registries_conf_podman_content_not_OK_read_error_not_preserved(
    mock_os_path_exists, mock_toml_load, mock_logging, mock_exec_subprocess
):
    mock_os_path_exists.return_value = True
    mock_exec_subprocess.return_value = 1
    with patch('builtins.open', create=True) as mock_open:
        mock_open.side_effect = OSError('oh no !')
        assert utils.__set_registries_conf_podman(
            'registry-ec2.susecloud.net'
        ) is False
        assert mock_open.call_args_list == [
            call('/etc/containers/registries.conf', 'r')
        ]
        assert mock_logging.info.call_args_list == [
            call('oh no !'),
            call(
                'Could not open /etc/containers/registries.conf, '
                'preserving file as /etc/containers/registries.conf.bak'),
            call('File not preserved.')
        ]


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.os.path.exists')
def test_clean_registries_conf_podman_no_file(mock_os_path_exists):
    mock_os_path_exists.return_value = False
    assert utils.clean_registries_conf_podman('some-fqdn.suse.de')


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.get_registry_conf_file')
@patch('cloudregister.registerutils.os.path.exists')
def test_clean_registries_conf_podman_file_error_open(
    mock_os_path_exists, mock_get_registry_conf_file
):
    mock_os_path_exists.return_value = True
    mock_get_registry_conf_file.return_value = {}, 1
    assert utils.clean_registries_conf_podman('foo.com') is False


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.get_registry_conf_file')
@patch('cloudregister.registerutils.os.path.exists')
def test_clean_registries_conf_podman_file_no_error_empty_content(
    mock_os_path_exists, mock_get_registry_conf_file
):
    mock_os_path_exists.return_value = True
    mock_get_registry_conf_file.return_value = {}, 0
    assert utils.clean_registries_conf_podman('foo.com') is True


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.toml.dump')
@patch('cloudregister.registerutils.toml.load')
@patch('cloudregister.registerutils.os.path.exists')
def test_clean_registries_conf_podman_file_clean_content_smt_OK(
    mock_os_path_exists, mock_toml_load, mock_toml_dump, mock_logging
):
    mock_os_path_exists.return_value = True
    registry_fqdn = 'registry-foo.susecloud.net'
    mock_toml_load.return_value = {
        'unqualified-search-registries': [
            'foo.com', 'registry.suse.com', registry_fqdn
        ],
        'registry': [
            {'location': 'foo', 'insecure': False},
            {'location': registry_fqdn, 'insecure': False}
        ]
    }
    with patch('builtins.open', create=True) as mock_open:
        file_handle = mock_open.return_value.__enter__.return_value
        assert utils.clean_registries_conf_podman(registry_fqdn)
        assert mock_open.call_args_list == [
            call('/etc/containers/registries.conf', 'r'),
            call('/etc/containers/registries.conf', 'w')
        ]
        assert mock_logging.info.call_args_list == [
            call(
                'SUSE registry information has been removed '
                'from /etc/containers/registries.conf'
            ),
            call('File /etc/containers/registries.conf updated')
        ]
        mock_toml_dump.assert_called_once_with(
            {
                'unqualified-search-registries': [
                    'foo.com', 'registry.suse.com'
                ],
                'registry': [{'location': 'foo', 'insecure': False}]
            },
            file_handle
        )


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.get_smt_from_store')
@patch('cloudregister.registerutils.__get_registered_smt_file_path')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.toml.dump')
@patch('cloudregister.registerutils.toml.load')
@patch('cloudregister.registerutils.os.path.exists')
def test_clean_registries_conf_podman_file_clean_content_no_smt(
    mock_os_path_exists, mock_toml_load,
    mock_toml_dump, mock_logging, mock_get_registered_smt,
    mock_get_smt_from_store
):
    mock_os_path_exists.return_value = True
    mock_toml_load.return_value = {
        'unqualified-search-registries': [
            'foo.com', 'registry.suse.com', 'registry-foo.susecloud.net'
        ],
        'registry': [
            {'location': 'foo', 'insecure': False},
            {'location': 'registry-foo.susecloud.net', 'insecure': False}
        ]
    }
    with patch('builtins.open', create=True) as mock_open:
        file_handle = mock_open.return_value.__enter__.return_value
        assert utils.clean_registries_conf_podman(private_registry_fqdn='')
        assert mock_open.call_args_list == [
            call('/etc/containers/registries.conf', 'r'),
            call('/etc/containers/registries.conf', 'w')
        ]
        assert mock_logging.info.call_args_list == [
            call(
                'SUSE registry information has been removed from '
                '/etc/containers/registries.conf'
            ),
            call('File /etc/containers/registries.conf updated')
        ]
        mock_toml_dump.assert_called_once_with(
            {
                'unqualified-search-registries': [
                    'foo.com', 'registry.suse.com'
                ],
                'registry': [{'location': 'foo', 'insecure': False}]
            },
            file_handle
        )


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.toml.dump')
@patch('cloudregister.registerutils.get_registry_conf_file')
def test_set_registry_order_search_podman_no_configured(
    mock_get_registry_file, mock_toml_dump
):
    with open('tests/data/unconfigured_registry.conf') as f:
        registry_conf = toml.load(f)
    mock_get_registry_file.return_value = registry_conf, False
    with patch('builtins.open', create=True) as mock_open:
        mock_open_podman_config = MagicMock(spec=io.IOBase)

        def open_file(filename, mode):
            return mock_open_podman_config.return_value

        mock_open.side_effect = open_file
        file_handle = \
            mock_open_podman_config.return_value.__enter__.return_value
        utils.__set_registries_conf_podman('rmt-registry.susecloud.net')
        assert mock_toml_dump.call_args_list == [
            call({
                'search-registries': ['docker.io'],
                'no-registry': [{'location': 'foo'}],
                'unqualified-search-registries': [
                    'rmt-registry.susecloud.net', 'registry.suse.com'
                ],
                'registry': [{
                    'location': 'rmt-registry.susecloud.net',
                    'insecure': False
                }]
            }, file_handle)
        ]


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.toml.dump')
@patch('cloudregister.registerutils.get_registry_conf_file')
def test_set_registry_order_search_podman_conf_missing_suse_registry(
    mock_get_registry_file, mock_toml_dump
):
    with open('tests/data/registry_conf.conf') as f:
        registry_conf = toml.load(f)
    mock_get_registry_file.return_value = registry_conf, False
    with patch('builtins.open', create=True) as mock_open:
        mock_open_podman_config = MagicMock(spec=io.IOBase)

        def open_file(filename, mode):
            return mock_open_podman_config.return_value

        mock_open.side_effect = open_file
        file_handle = \
            mock_open_podman_config.return_value.__enter__.return_value
        utils.__set_registries_conf_podman('rmt-registry.susecloud.net')
        mock_toml_dump.assert_called_once_with({
            'unqualified-search-registries': [
                'rmt-registry.susecloud.net',
                'registry.suse.com',
                'foo.com',
                'bar.registry.com',
                'docker.io',
            ],
            'registry': [
                {'location': 'foo.com', 'insecure': True},
                {
                    'location': 'rmt-registry.susecloud.net',
                    'insecure': False
                }
            ]
        }, file_handle)


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.json.load')
def test_get_registry_config_file_docker(mock_json_load):
    with patch('builtins.open') as mock_open:
        mock_open_podman_config = MagicMock(spec=io.IOBase)

        def open_file(filename, mode):
            return mock_open_podman_config.return_value

        mock_open.side_effect = open_file
        utils.get_registry_conf_file(
            '/etc/docker/daemon.json', 'docker'
        )
        mock_json_load.assert_called_once()


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.get_registry_conf_file')
@patch('cloudregister.registerutils.os.path.exists')
def test_clean_registries_conf_docker_file_no_error_empty_content(
    mock_os_path_exists, mock_get_registry_conf_file
):
    mock_os_path_exists.return_value = True
    mock_get_registry_conf_file.return_value = {}, 0
    assert utils.clean_registries_conf_docker('foo.com') is True


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.get_registry_conf_file')
@patch('cloudregister.registerutils.os.path.exists')
def test_clean_registries_conf_docker_file_error(
    mock_os_path_exists, mock_get_registry_conf_file
):
    mock_os_path_exists.return_value = True
    mock_get_registry_conf_file.return_value = {}, 1
    assert utils.clean_registries_conf_docker('foo.com') is False


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.json.dump')
@patch('cloudregister.registerutils.json.load')
@patch('cloudregister.registerutils.os.path.exists')
def test_clean_registries_conf_docker_file_clean_content_smt_OK(
    mock_os_path_exists, mock_json_load, mock_json_dump, mock_logging
):
    mock_os_path_exists.return_value = True
    mock_json_load.return_value = {
        'registry-mirrors': [
            'foo.com',
            'https://registry.suse.com',
            'https://registry-foo.susecloud.net'
        ]
    }
    with patch('builtins.open', create=True) as mock_open:
        file_handle = mock_open.return_value.__enter__.return_value
        assert utils.clean_registries_conf_docker('registry-foo.susecloud.net')
        assert mock_open.call_args_list == [
            call('/etc/docker/daemon.json', 'r'),
            call('/etc/docker/daemon.json', 'w')
        ]
        assert mock_logging.info.call_args_list == [
            call(
                'SUSE registry information has been removed '
                'from /etc/docker/daemon.json'
            ),
            call('File /etc/docker/daemon.json updated')
        ]
        mock_json_dump.assert_called_once_with(
            {'registry-mirrors': ['foo.com', 'https://registry.suse.com']},
            file_handle
        )


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.json.dump')
@patch('cloudregister.registerutils.json.load')
@patch('cloudregister.registerutils.os.path.exists')
def test_clean_registries_conf_docker_file_clean_content_no_smt(
    mock_os_path_exists, mock_json_load,
    mock_json_dump, mock_logging
):
    mock_os_path_exists.return_value = True
    mock_json_load.return_value = {
        'registry-mirrors': [
            'foo.com', 'registry.suse.com', 'registry-foo.susecloud.net'
        ]
    }
    with patch('builtins.open', create=True) as mock_open:
        file_handle = mock_open.return_value.__enter__.return_value
        assert utils.clean_registries_conf_docker(private_registry_fqdn='')
        assert mock_open.call_args_list == [
            call('/etc/docker/daemon.json', 'r'),
            call('/etc/docker/daemon.json', 'w')
        ]
        print(mock_logging.info.call_args_list)
        assert mock_logging.info.call_args_list == [
            call(
                'SUSE registry information has been removed '
                'from /etc/docker/daemon.json'
            ),
            call('File /etc/docker/daemon.json updated')
        ]
        mock_json_dump.assert_called_once_with(
            {'registry-mirrors': ['foo.com', 'registry.suse.com']},
            file_handle
        )


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.exec_subprocess')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.json.load')
def test_get_registry_config_file_docker_not_parsed(
    mock_json_load, mock_logging, mock_exec_subprocess
):
    mock_json_load.side_effect = json.decoder.JSONDecodeError('a', 'b', 1)
    mock_exec_subprocess.return_value = 0
    with patch('builtins.open'):
        utils.get_registry_conf_file(
            '/etc/docker/daemon.json', 'docker'
        )
        mock_json_load.assert_called_once()
        assert mock_logging.info.call_args_list == [
            call(
                'Could not parse /etc/docker/daemon.json, '
                'preserving file as /etc/docker/daemon.json.bak'
            ),
            call('File preserved.')
        ]
        mock_exec_subprocess.assert_called_once_with(
            ['mv', '-Z',
             '/etc/docker/daemon.json',
             '/etc/docker/daemon.json.bak']
        )


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.get_registry_conf_file')
@patch('cloudregister.registerutils.json.dump')
@patch('os.path.exists')
def test_set_registries_conf_docker_no_matches(
    mock_os_path_exists, mock_json_dump, mock_get_registry_conf_file
):
    mock_os_path_exists.return_value = True
    with patch('builtins.open', create=True) as mock_open:
        mock_open_podman_config = MagicMock(spec=io.IOBase)

        def open_file(filename, mode):
            return mock_open_podman_config.return_value

        mock_open.side_effect = open_file
        file_handle = \
            mock_open_podman_config.return_value.__enter__.return_value
        mock_get_registry_conf_file.return_value = {
            'registry-mirrors': ['foo'],
            'bar': ['bar'],
        }, False
        utils.__set_registries_conf_docker('registry-foo.susecloud.net')
        mock_json_dump.assert_called_once_with(
            {
                'registry-mirrors': [
                    'https://registry-foo.susecloud.net',
                    'https://registry.suse.com',
                    'foo'
                ],
                'bar': ['bar']
            },
            file_handle
        )


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.get_registry_conf_file')
@patch('cloudregister.registerutils.json.dump')
@patch('os.path.exists')
def test_set_registries_conf_docker_not_OK_order_has_changed(
    mock_os_path_exists, mock_json_dump, mock_get_registry_conf_file
):
    mock_os_path_exists.return_value = True
    with patch('builtins.open', create=True) as mock_open:
        mock_open_podman_config = MagicMock(spec=io.IOBase)

        def open_file(filename, mode):
            return mock_open_podman_config.return_value

        mock_open.side_effect = open_file
        mock_get_registry_conf_file.return_value = {
            'registry-mirrors': [
                'foo',
                'https://registry.suse.com',
                'https://registry-foo.susecloud.net'
            ],
            'bar': ['bar'],
        }, False
        utils.__set_registries_conf_docker('registry-foo.susecloud.net')
        # The registry setup contains the entries we care but was
        # modified manually. Don't touch this user modified variant.
        # This can be changed by the user via a --clean re-registration
        assert not mock_json_dump.called


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.get_registry_conf_file')
@patch('cloudregister.registerutils.json.dump')
@patch('os.path.exists')
def test_set_registries_conf_docker_not_key_mirror(
    mock_os_path_exists, mock_json_dump, mock_get_registry_conf_file
):
    mock_os_path_exists.return_value = True
    with patch('builtins.open', create=True) as mock_open:
        mock_open_podman_config = MagicMock(spec=io.IOBase)

        def open_file(filename, mode):
            return mock_open_podman_config.return_value

        mock_open.side_effect = open_file
        file_handle = \
            mock_open_podman_config.return_value.__enter__.return_value
        mock_get_registry_conf_file.return_value = {'foo': ['foo']}, False
        utils.__set_registries_conf_docker('registry-foo.susecloud.net')
        mock_json_dump.assert_called_once_with(
            {
                'foo': ['foo'],
                'registry-mirrors': [
                    'https://registry-foo.susecloud.net',
                    'https://registry.suse.com'
                ]
            },
            file_handle
        )


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.get_registry_conf_file')
@patch('os.path.exists')
def test_set_registries_conf_docker_error_file_not_preserved(
    mock_os_path_exists, mock_get_registry_conf_file
):
    mock_os_path_exists.return_value = True
    mock_get_registry_conf_file.return_value = {}, True
    assert utils.__set_registries_conf_docker(
        'registry-foo.susecloud.net'
    ) is False


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.json.dump')
def test_write_registries_conf(mock_json_dump, mock_logging):
    with patch('builtins.open', create=True) as mock_open:
        file_handle = mock_open.return_value.__enter__.return_value
        assert utils.write_registries_conf('foo', 'docker_path', 'docker')
        assert mock_json_dump.call_args_list == [
            call('foo', file_handle)
        ]
        assert mock_logging.info.call_args_list == [
            call('File docker_path updated')
        ]


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.json.dump')
def test_write_registries_conf_dump_error(mock_json_dump, mock_logging):
    mock_json_dump.side_effect = TypeError('error')
    with patch('builtins.open', create=True) as mock_open:
        file_handle = mock_open.return_value.__enter__.return_value
        assert utils.write_registries_conf(
            'foo', 'docker_path', 'docker'
        ) is None
        assert mock_json_dump.call_args_list == [
            call('foo', file_handle)
        ]
        assert mock_logging.error.call_args_list == [
            call('Could not write docker_path')
        ]


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.__set_registry_fqdn_suma')
@patch('cloudregister.registerutils.__set_registries_conf_docker')
@patch('cloudregister.registerutils.__set_registries_conf_podman')
@patch('cloudregister.registerutils.is_suma_instance')
def test_suma_registry_conf_no_suma_instance(
    mock_is_suma, mock_set_podman, mock_set_docker, mock_fqdn_suma
):
    mock_is_suma.return_value = False
    mock_set_podman.return_value = True
    mock_set_docker.return_value = True
    assert utils.set_registries_conf('foo.com')
    assert mock_fqdn_suma.call_count == 0


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.__set_registry_fqdn_suma')
@patch('cloudregister.registerutils.__set_registries_conf_docker')
@patch('cloudregister.registerutils.__set_registries_conf_podman')
@patch('cloudregister.registerutils.is_suma_instance')
def test_suma_registry_conf_suma_instance(
    mock_is_suma, mock_set_podman, mock_set_docker, mock_fqdn_suma
):
    mock_is_suma.return_value = True
    mock_set_podman.return_value = True
    mock_set_docker.return_value = True
    mock_fqdn_suma.return_value = True
    assert utils.set_registries_conf('registry-fqdn.com')


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.glob.glob')
def test_is_suma_instance_not(mock_glob_glob):
    mock_glob_glob.return_value = ['/etc/products.d/some-product.prod']
    assert utils.is_suma_instance() is False


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.glob.glob')
def test_is_suma_instance(mock_glob_glob):
    mock_glob_glob.return_value = [
        '/etc/products.d/SLE-Micro.prod',
        '/etc/products.d/SUSE-Manager-Server.prod'
    ]
    assert utils.is_suma_instance()


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.get_suma_registry_content')
@patch('cloudregister.registerutils.os.makedirs')
def test_suma_registry_conf_suma_instance_error_get_suma_content(
    _, mock_get_suma_registry_content
):
    mock_get_suma_registry_content.return_value = {}, 1
    assert utils.__set_registry_fqdn_suma('foo.com') is False


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.os.path.exists')
@patch('cloudregister.registerutils.yaml.dump')
@patch('cloudregister.registerutils.yaml.safe_load')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.os.makedirs')
def test_suma_registry_conf_suma_instance_file_exists(
    _, mock_logging, mock_yaml_safe_load, mock_yaml_dump, mock_os_path_exists
):
    mock_os_path_exists.return_value = True
    mock_yaml_safe_load.return_value = {}
    with patch('builtins.open', create=True) as mock_open:
        mock_open.return_value = MagicMock(spec=io.IOBase)
        file_handle = mock_open.return_value.__enter__.return_value
        # mock_open.side_effect = IOError('oh no ! an error')
        assert utils.__set_registry_fqdn_suma('foo.com')
        assert mock_open.call_args_list == [
            call('/etc/uyuni/uyuni-tools.yaml', 'r'),
            call('/etc/uyuni/uyuni-tools.yaml', 'w')
        ]
        assert mock_logging.info.call_args_list == [
            call('/etc/uyuni/uyuni-tools.yaml updated')
        ]
        mock_yaml_dump.assert_called_once_with(
           {'registry': 'foo.com'},
           file_handle,
           default_flow_style=False
        )


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.os.path.exists')
@patch('cloudregister.registerutils.yaml.dump')
@patch('cloudregister.registerutils.yaml.safe_load')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.os.makedirs')
def test_suma_registry_conf_suma_instance_file_exists_different_fqdn(
    _, mock_logging, mock_yaml_safe_load, mock_yaml_dump, mock_os_path_exists
):
    mock_yaml_safe_load.return_value = {'registry': 'not-our-fqdn'}
    mock_os_path_exists.return_value = True
    with patch('builtins.open', create=True) as mock_open:
        # mock_open.return_value = MagicMock(spec=io.IOBase)
        file_handle = mock_open.return_value.__enter__.return_value
        assert utils.__set_registry_fqdn_suma('foo.com')
        assert mock_open.call_args_list == [
            call('/etc/uyuni/uyuni-tools.yaml', 'r'),
            call('/etc/uyuni/uyuni-tools.yaml', 'w')
        ]
        assert mock_logging.info.call_args_list == [
            call('/etc/uyuni/uyuni-tools.yaml updated')
        ]
        mock_yaml_dump.assert_called_once_with(
           {'registry': 'foo.com'},
           file_handle,
           default_flow_style=False
        )


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.os.path.exists')
@patch('cloudregister.registerutils.yaml.safe_load')
@patch('cloudregister.registerutils.os.makedirs')
def test_suma_registry_conf_suma_instance_file_exists_same_fqdn(
    _, mock_yaml_safe_load, mock_os_path_exists
):
    mock_os_path_exists.return_value = True
    mock_yaml_safe_load.return_value = {'registry': 'foo.com'}
    with patch('builtins.open', create=True) as mock_open:
        assert utils.__set_registry_fqdn_suma('foo.com')
        assert mock_open.call_args_list == [
            call('/etc/uyuni/uyuni-tools.yaml', 'r')
        ]


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.os.path.exists')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.yaml.safe_load')
def test_get_suma_registry_content_error_yaml(
    mock_yaml_safe_load, mock_logging, mock_os_path_exists
):
    mock_os_path_exists.return_value = True
    mock_yaml_safe_load.side_effect = yaml.YAMLError('some loading error')
    with patch('builtins.open', create=True) as mock_open:
        result, failed = utils.get_suma_registry_content()
        assert result == {}
        assert failed is True
        assert mock_open.call_args_list == [
            call('/etc/uyuni/uyuni-tools.yaml', 'r')
        ]
        assert mock_logging.info.call_args_list == [
            call('Could not parse /etc/uyuni/uyuni-tools.yaml')
        ]


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.os.path.exists')
@patch('cloudregister.registerutils.logging')
def test_get_suma_registry_content_error_open_file(
    mock_logging, mock_os_path_exists
):
    mock_os_path_exists.return_value = True
    with patch('builtins.open', create=True) as mock_open:
        mock_open.side_effect = IOError('opening file error')
        result, failed = utils.get_suma_registry_content()
        assert result == {}
        assert failed is True
        assert mock_open.call_args_list == [
            call('/etc/uyuni/uyuni-tools.yaml', 'r')
        ]
        assert mock_logging.info.call_args_list == [
            call('opening file error'),
            call('Could not open /etc/uyuni/uyuni-tools.yaml')
        ]


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.os.path.exists')
def test_get_suma_registry_content__no_file(mock_os_path_exists):
    mock_os_path_exists.return_value = False
    result, failed = utils.get_suma_registry_content()
    assert result == {}
    assert failed is False


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.__mv_file_backup')
@patch('cloudregister.registerutils.logging')
def test_write_suma_conf_error_open_file(mock_logging, mock_mv):
    mock_mv.return_value = 0
    with patch('builtins.open', create=True) as mock_open:
        mock_open.side_effect = IOError('opening file error')
        assert utils.__write_suma_conf('foo') is None
        assert mock_open.call_args_list == [
            call('/etc/uyuni/uyuni-tools.yaml', 'w')
        ]
        assert mock_logging.info.call_args_list == [
            call('opening file error'),
            call('Could not open /etc/uyuni/uyuni-tools.yaml')
        ]


# ---------------------------------------------------------------------------
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.yaml.dump')
def test_write_suma_conf_error_yaml(
    mock_yaml_dump, mock_logging
):
    mock_yaml_dump.side_effect = yaml.YAMLError('some loading error')
    with patch('builtins.open', create=True) as mock_open:
        assert utils.__write_suma_conf('foo') is None
        assert mock_open.call_args_list == [
            call('/etc/uyuni/uyuni-tools.yaml', 'w')
        ]
        assert mock_logging.info.call_args_list == [
            call('Could not parse /etc/uyuni/uyuni-tools.yaml')
        ]


# ---------------------------------------------------------------------------
def test__matches_susecloud():
    assert utils.__matches_susecloud(['foo']) == ''
    assert utils.__matches_susecloud(
        ['registry-azure.susecloud.net']
    ) == 'registry-azure.susecloud.net'
    assert utils.__matches_susecloud(
        ['foo', 'registry.susecloud.net', 'registry-azure.susecloud.net']
    ) == 'registry-azure.susecloud.net'


# ---------------------------------------------------------------------------
# Helper functions
class Response():
    """Fake a request response object"""
    def json(self):
        pass


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


def get_test_config():
    """Return a config parser object using the minimum configuration in the
       tests/data directory"""
    return utils.get_config(data_path + '/regionserverclnt.cfg')


class MockServer:
    def get_ipv4(self):
        return '1.1.1.1'

    def get_ipv6(self):
        return '11:22:33:44::00'
