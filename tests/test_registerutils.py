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
import os
import pickle
import sys
import tempfile
from pytest import raises
from textwrap import dedent

from unittest import mock
from unittest.mock import patch, call, MagicMock, Mock
from lxml import etree

test_path = os.path.abspath(
    os.path.dirname(inspect.getfile(inspect.currentframe())))
code_path = os.path.abspath('%s/../lib' % test_path)
config_path = os.path.abspath('%s/../etc' % test_path)
data_path = test_path + os.sep + 'data/'

sys.path.insert(0, code_path)

import cloudregister.registerutils as utils
from cloudregister.smt import SMT

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
    mock_subproc.return_value = (b'Amazon EC2', b'')
    mock_id_path.return_value = data_path + 'framework_info'
    mock_plugin.return_value = True
    mock_srvargs.return_value = 'regionHint=us-east-1'
    mock_srvargs.return_value = 'regionHint=us-east-1'
    mock_json_loads.side_effect = Exception('foo')
    assert utils.has_region_changed(cfg) == False


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
        utils.clean_hosts_file('smt-entry')

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


def test_clean_host_file_raised_exception():
    hosts_content = ""
    expected_cleaned_hosts = """
# simulates hosts file containing the ipv6 we are looking for in the test

1.2.3.4   smt-foo.susecloud.net  smt-foo


4.3.2.1   another_entry.whatever.com another_entry"""
    with mock.patch('builtins.open', mock.mock_open(read_data=hosts_content.encode())) as m:  # noqa: E501
        utils.clean_hosts_file('smt-entry')

    assert m().write.mock_calls == []


@patch('cloudregister.registerutils.has_ipv6_access')
def test_add_hosts_entry(mock_has_ipv6_access):
    """Test hosts entry has a new entry added by us."""
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="fantasy.example.com"
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
        file_content_entry = '{ip}\t{fqdn}\t{name}\n'.format(
            ip=smt_server.get_ipv6(),
            fqdn=smt_server.get_FQDN(),
            name=smt_server.get_name()
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
    api = cfg.get('server', 'api')
    mock_get_framework_plugin.return_value = __import__(
        'cloudregister.amazonec2', fromlist=['']
    )
    mock_generate_region_srv_args.return_value = 'regionHint=eu-central-1'
    expected_args = 'regionInfo?regionHint=eu-central-1'
    assert utils.add_region_server_args_to_URL(api, cfg) == expected_args


@patch('cloudregister.registerutils.__get_framework_plugin')
def test_add_region_server_args_to_URL_no_module(mock_get_framework_plugin):
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


@patch('cloudregister.registerutils.get_credentials')
def test_credentials_files_are_equal(mock_get_credentials):
    mock_get_credentials.side_effect = [('SCC_foo', 'bar'), ('SCC_foo', 'bar')]
    assert utils.credentials_files_are_equal('foo') == True
    assert mock_get_credentials.mock_calls == [
        call('/etc/zypp/credentials.d/SCCcredentials'),
        call('/etc/zypp/credentials.d/foo')
    ]

    mock_get_credentials.side_effect = [('SCC_bar', 'bar'), ('SCC_foo', 'bar')]
    assert utils.credentials_files_are_equal('foo') == False


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
        'stdout'.encode(), 'stderr'.encode()
    )
    assert utils.exec_subprocess(['foo']) == 1


def test_fetch_smt_data():
    pass


@patch.object(SMT, 'is_responsive')
def test_find_equivalent_smt_server(mock_is_responsive):
    """Test hosts entry has a new entry added by us."""
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="fantasy.example.com"
         region="antarctica-1"/>''')
    smt_data_ipv46_2 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.2.1"
         SMTserverIPv6="fc00::2"
         SMTserverName="fantasy.example.net"
         region="antarctica-1"/>''')
    smt_a = SMT(etree.fromstring(smt_data_ipv46))
    smt_b = SMT(etree.fromstring(smt_data_ipv46_2))
    mock_is_responsive.return_value = True

    assert utils.find_equivalent_smt_server(smt_a, [smt_a, smt_b]) == smt_b
    assert utils.find_equivalent_smt_server(smt_a, [smt_a]) == None


@patch('cloudregister.registerutils.glob.glob')
def test_find_repos(mock_glob):
    mock_glob.return_value = ['tests/data/repo_foo.repo']
    assert utils.find_repos('Foo') == ['SLE-Module-Live-Foo15-SP5-Source-Pool']


def test_get_activations():
    pass


@patch('cloudregister.registerutils.configparser.RawConfigParser.read')
def test_get_config(mock_config_parser):
    mock_config_parser.return_value = config_path + '/regionserverclnt.cfg'
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
def test_get_credentials_no_file(mock_logging, mock_glob):
    mock_glob.return_value = []
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="fantasy.example.com"
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
    assert utils.get_current_smt() == None


@patch('cloudregister.registerutils.os.unlink')
@patch('cloudregister.registerutils.get_smt_from_store')
def test_get_current_smt_no_match(mock_get_smt_from_store, mock_os_unlink):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="fantasy.example.com"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_smt_from_store.return_value = smt_server
    utils.get_current_smt()


@patch('cloudregister.registerutils.get_smt_from_store')
def test_get_current_smt_no_registered(mock_get_smt_from_store):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="smt-foo.susecloud.net"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_smt_from_store.return_value = smt_server
    hosts_content = """
    # simulates hosts file containing the ipv4 we are looking for in the test

    192.168.1.1   smt-foo.susecloud.net  smt-foo
    """
    with mock.patch('builtins.open', mock.mock_open(
        read_data=hosts_content.encode()
    )):
        assert utils.get_current_smt() == None


@patch('cloudregister.registerutils.is_registered')
@patch('cloudregister.registerutils.get_smt_from_store')
def test_get_current_smt(mock_get_smt_from_store, mock_is_registered):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="smt-foo.susecloud.net"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_smt_from_store.return_value = smt_server
    mock_is_registered.return_value = True
    hosts_content = """
    # simulates hosts file containing the ipv4 we are looking for in the test

    192.168.1.1   smt-foo.susecloud.net  smt-foo
    """
    with mock.patch('builtins.open', mock.mock_open(
        read_data=hosts_content.encode()
    )):
        assert utils.get_current_smt() == smt_server


def test_get_framework_identifier_path():
    assert utils.get_framework_identifier_path() == \
        '/var/cache/cloudregister/framework_info'


def test_get_instance_data():
    pass


def test_get_installed_products():
    pass


@patch('cloudregister.registerutils.glob.glob')
def test_get_repo_url(mock_glob):
    mock_glob.return_value = ['tests/data/repo_foo.repo']
    assert utils.get_repo_url('SLE-Module-Live-Foo15-SP5-Source-Pool') == \
        'plugin:/susecloud?credentials=SUSE_Linux_Enterprise_Live_Foo_x86_64&' \
        'path=/repo/SUSE/Products/SLE-Module-Live-Foo/15-SP5/x86_64/' \
        'product_source/'


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
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="42.168.1.1"
         SMTserverIPv6="fc00::7"
         SMTserverName="smt-foo.susecloud.net"
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
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="42.168.1.1"
         SMTserverIPv6="fc00::7"
         SMTserverName="smt-foo.susecloud.net"
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
        "Sibling update server, ('42.168.1.1', 'fc00::7'), does not have system credentials "
        "cannot failover. Retaining current, ('192.168.1.1', 'fc00::1'), target update server."
        'Try again later.'
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
    mock_clean_hosts_file.assert_called_once_with('smt-foo.susecloud.net')


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
    assert utils.get_smt_from_store('foo') == None


@patch.object(pickle, 'Unpickler')
def test_get_smt_from_store_raise_exception(mock_unpickler):
    unpick = Mock()
    mock_unpickler.return_value = unpick
    unpick.load.side_effect = pickle.UnpicklingError
    assert utils.get_smt_from_store('tests/data/availableSMTInfo_1.obj') == None


@patch('cloudregister.registerutils.get_available_smt_servers')
def test_get_update_server_name_from_hosts(mock_get_available_smt_servers):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="smt-foo.susecloud.net"
         region="antarctica-1"/>''')
    alternative_smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_available_smt_servers.return_value = [alternative_smt_server]

    hosts_content = """
    # simulates hosts file containing the ipv4 we are looking for in the test

    1.1.1.1   smt-foo.susecloud.net  smt-foo
    """
    with mock.patch(
        'builtins.open', mock.mock_open(read_data=hosts_content.encode())
    ):
        assert utils.get_update_server_name_from_hosts() == \
            'smt-foo.susecloud.net'


@patch('cloudregister.registerutils.get_zypper_pid')
def test_get_zypper_command(mock_zypper_pid):
    mock_zypper_pid.return_value = 42
    with mock.patch(
        'builtins.open', mock.mock_open(read_data='\x00foo')
    ):
        assert utils.get_zypper_command() == ' foo'


@patch('cloudregister.registerutils.subprocess.Popen')
def test_get_zypper_pid(mock_popen):
    mock_process = Mock()
    mock_process.communicate = Mock(
        return_value=[str.encode('pid'), str.encode('stderr')]
    )
    mock_process.returncode = 0
    mock_popen.return_value = mock_process
    assert utils.get_zypper_pid() == 'pid'


def test_has_ipv6_access_no_ipv6_defined():
    smt_data_ipv4 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverName="smt-foo.susecloud.net"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv4))
    assert utils.has_ipv6_access(smt_server) == False


@patch('cloudregister.registerutils.get_config')
@patch('cloudregister.registerutils.requests.get')
@patch('cloudregister.registerutils.https_only')
def test_has_ipv6_access_https(mock_https_only, mock_request, mock_get_config):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="smt-foo.susecloud.net"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    response = Response()
    response.status_code = 200
    response.text = 'such a request !'
    mock_request.return_value = response
    mock_https_only.return_value = True
    assert utils.has_ipv6_access(smt_server)
    mock_request.assert_called_once_with(
        'https://[fc00::1]/smt.crt',
        timeout=3,
        verify=False
    )


@patch('cloudregister.registerutils.get_config')
@patch('cloudregister.registerutils.requests.get')
@patch('cloudregister.registerutils.https_only')
def test_has_ipv6_access_exception(
    mock_https_only,
    mock_request,
    mock_get_config
):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="smt-foo.susecloud.net"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_request.side_effect = Exception("Server's too far, cant be reached")
    mock_https_only.return_value = True
    assert utils.has_ipv6_access(smt_server) == False
    mock_request.assert_called_once_with(
        'https://[fc00::1]/smt.crt',
        timeout=3,
        verify=False
    )


@patch('cloudregister.registerutils.exec_subprocess')
def test_has_nvidia_support(mock_subprocess):
    mock_subprocess.return_value = b'NVIDIA', 'bar'
    assert utils.has_nvidia_support() == True


@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.exec_subprocess')
def test_has_nvidia_support_exception(mock_subprocess, mock_logging):
    mock_subprocess.side_effect = TypeError('foo')
    assert utils.has_nvidia_support() == False
    mock_logging.info.assert_called_once_with(
        'lspci command not found, instance Nvidia support cannot be determined'
    )


@patch('cloudregister.registerutils.exec_subprocess')
def test_has_nvidia_no_support(mock_subprocess):
    mock_subprocess.return_value = b'foo', 'bar'
    assert utils.has_nvidia_support() == False


@patch('cloudregister.registerutils.__get_service_plugins')
def test_has_services_service_plugin(mock_get_service_plugins):
    mock_get_service_plugins.return_value = 'foo'
    assert utils.has_services('foo') == True


@patch('cloudregister.registerutils.glob.glob')
def test_has_services_service(mock_get_service_plugins):
    mock_get_service_plugins.return_value = ['foo']
    content = 'url=plugin:susecloud'
    with mock.patch('builtins.open', mock.mock_open(read_data=content)):
        assert utils.has_services('foo') == True


@patch('cloudregister.registerutils.requests.post')
@patch('cloudregister.registerutils.HTTPBasicAuth')
def test_has_smt_access_unauthorized(mock_http_basic_auth, mock_post):
    response = Response()
    response.reason = 'Unauthorized'
    mock_post.return_value = response
    assert utils.has_smt_access('foo', 'bar', 'foobar') == False


@patch('cloudregister.registerutils.requests.post')
@patch('cloudregister.registerutils.HTTPBasicAuth')
def test_has_smt_access_authorized(mock_http_basic_auth, mock_post):
    response = Response()
    response.reason = 'Super_Authorized'
    mock_post.return_value = response
    assert utils.has_smt_access('foo', 'bar', 'foobar') == True


def test_https_only():
    cfg['instance']['httpsOnly'] = 'true'
    assert utils.https_only(cfg) == True
    del cfg['instance']['httpsOnly']


def test_https_only_no():
    assert utils.https_only(cfg) == False


@patch.object(SMT, 'write_cert')
def test_import_smtcert_12_no_write_cert(mock_smt_write_cert):
    mock_smt_write_cert.return_value = False
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="fantasy.example.com"
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
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))

    assert utils.import_smtcert_12(smt_server) == 1


@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.import_smtcert_12')
def test_import_smt_cert_fail(mock_import_smtcert_12, mockin_logging):
    mock_import_smtcert_12.return_value = False
    assert utils.import_smt_cert('foo') == None
    mockin_logging.error.assert_called_once_with(
        'SMT certificate import failed'
    )


@patch('cloudregister.registerutils.glob.glob')
@patch('cloudregister.registerutils.site.getsitepackages')
@patch('cloudregister.registerutils.logging')
@patch('cloudregister.registerutils.import_smtcert_12')
def test_import_smt_cert_cert_middling(
    mock_import_smtcert_12,
    mockin_logging,
        mockin_getsitepackages,
    mockin_glob
):
    mock_import_smtcert_12.return_value = True
    mockin_getsitepackages.return_value = ['foo']
    mockin_glob.return_value = ['foo/certifi/foo.pem']
    assert utils.import_smt_cert('foo') == 1
    mockin_logging.warning.assert_called_once_with(
        'SMT certificate imported, but "foo/certifi/foo.pem" exist. '
        'This may lead to registration failure'
    )


def test_is_new_registration_not_new():
    assert utils.is_new_registration() == False


def test_is_registration_supported_exception():
    cfg_template = utils.get_config(config_path + '/regionserverclnt.cfg')
    del cfg_template['server']
    del cfg_template['service']
    assert utils.is_registration_supported(cfg_template) == False


def test_is_registration_supported():
    cfg_template = utils.get_config(config_path + '/regionserverclnt.cfg')
    del cfg_template['service']
    assert utils.is_registration_supported(cfg_template) == True


@patch('cloudregister.registerutils.glob.glob')
def test_is_scc_connected(mock_glob):
    mock_glob.return_value = ['tests/data/scc_repo.repo']
    assert utils.is_scc_connected() == True


def test_is_scc_not_connected():
    assert utils.is_scc_connected() == False


def test_is_zypper_running_not():
    assert utils.is_zypper_running() == False


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
         region="antarctica-1"/>''')

    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    with tempfile.TemporaryDirectory() as tmpdirname:
        mock_get_state_dir.return_value = tmpdirname + '/foo'
        utils.set_as_current_smt(smt_server)


@patch.dict(os.environ, {'http_proxy': 'foo', 'https_proxy': 'bar'}, clear=True)
@patch('cloudregister.registerutils.logging')
def test_set_proxy_proxy_set_on_os_env(mock_logging):
    assert utils.set_proxy() == False
    assert mock_logging.info.call_args_list == [
        call('Using proxy settings from execution environment'),
        call('\thttp_proxy: foo'),
        call('\thttps_proxy: bar'),
    ]


@patch('cloudregister.registerutils.os.path.exists')
def test_set_proxy_proxy_set_on_directory(mock_os_path_exists):
    mock_os_path_exists.return_value = False
    assert utils.set_proxy() == False


@patch('cloudregister.registerutils.os.path.exists')
def test_set_proxy(mock_os_path_exists):
    mock_os_path_exists.return_value = True
    proxy_content = """
    HTTP_PROXY="http://proxy.provider.de:3128/"
    HTTPS_PROXY="https://proxy.provider.de:3128/"
    NO_PROXY="localhost, 127.0.0.1"
    """
    with mock.patch('builtins.open', mock.mock_open(read_data=proxy_content)):
        assert utils.set_proxy() == True


@patch.dict(os.environ, {'http_proxy': '', 'https_proxy': ''}, clear=True)
@patch('cloudregister.registerutils.os.path.exists')
def test_proxy_not_enable(mock_os_path_exists):
    mock_os_path_exists.return_value = True
    proxy_content = """
    PROXY_ENABLED="no"
    """
    with mock.patch('builtins.open', mock.mock_open(read_data=proxy_content)):
        assert utils.set_proxy() == False


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
    assert utils.switch_services_to_plugin() == None


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


def test_remove_registration_data():
    pass


@patch('cloudregister.registerutils.add_hosts_entry')
@patch('cloudregister.registerutils.clean_hosts_file')
def test_replace_hosts_entry(mock_clean_hosts_file, mock_add_hosts_entry):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="smt-foo.susecloud.net"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    utils.replace_hosts_entry(smt_server, 'new_smt')
    mock_clean_hosts_file.assert_called_once_with('smt-foo.susecloud.net')
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
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    utils.store_smt_data('foo', smt_server)
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
         region="antarctica-1"/>''')
    new_smt_server = SMT(etree.fromstring(new_smt_data_ipv46))
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="111.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="plugin:/susecloud"
         region="antarctica-1"/>''')
    current_smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_current_smt.return_value = current_smt_server
    mock_glob.return_value = ['tests/data/repo_foo.repo']
    file_azo = ""
    with open('tests/data/repo_foo.repo') as f:
        file_azo = ' '.join(f.readlines())
    open_mock = mock.mock_open(read_data=file_azo)
    def open_f(filename, *args, **kwargs):
        return open_mock()

    with patch('builtins.open', create=True) as mock_open:
           mock_open.side_effect = open_f
           utils.switch_smt_repos(new_smt_server)
           assert mock_open.call_args_list == [
               call('tests/data/repo_foo.repo', 'r'),
               call('tests/data/repo_foo.repo', 'w')
           ]
           expected_content = file_azo.replace(
               'plugin:/susecloud',
               new_smt_server.get_FQDN()
           )
           mock_open(
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
         region="antarctica-1"/>''')
    new_smt_server = SMT(etree.fromstring(new_smt_data_ipv46))
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="111.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="plugin:/susecloud"
         region="antarctica-1"/>''')
    current_smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_current_smt.return_value = current_smt_server
    mock_glob.return_value = ['tests/data/service.service']
    file_azo = ""
    with open('tests/data/repo_foo.repo') as f:
        file_azo = ' '.join(f.readlines())
    open_mock = mock.mock_open(read_data=file_azo)
    def open_f(filename, *args, **kwargs):
        return open_mock()

    with patch('builtins.open', create=True) as mock_open:
           mock_open.side_effect = open_f
           utils.switch_smt_service(new_smt_server)
           assert mock_open.call_args_list == [
               call('tests/data/service.service', 'r'),
               call('tests/data/service.service', 'w')
           ]
           expected_content = file_azo.replace(
               'plugin:/susecloud',
               new_smt_server.get_FQDN()
           )
           mock_open(
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
    assert utils.update_rmt_cert('foo') == None


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
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    smt_xml = dedent('''\
    <regionSMTdata>
      <smtInfo fingerprint="99:88:77:66"
        SMTserverIP="1.2.3.4"
        SMTserverIPv6="fc11::2"
        SMTserverName="foo.susecloud.net"
        />
    </regionSMTdata>''')
    region_smt_data = etree.fromstring(smt_xml)

    mock_is_new_registration.return_value = False
    mock_set_proxy.return_value = True
    mock_fetch_smt_data.return_value = region_smt_data
    assert utils.update_rmt_cert(smt_server) == False
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
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    smt_xml = dedent('''\
    <regionSMTdata>
      <smtInfo fingerprint="99:88:77:66"
        SMTserverIP="111.168.1.1"
        SMTserverIPv6="fc00::1"
        SMTserverName="foo.susecloud.net"
        />
    </regionSMTdata>''')
    region_smt_data = etree.fromstring(smt_xml)

    mock_is_new_registration.return_value = False
    mock_set_proxy.return_value = True
    mock_fetch_smt_data.return_value = region_smt_data
    assert utils.update_rmt_cert(smt_server) == True
    assert mock_logging.info.call_args_list == [
        call('Check for cert update'),
        call('Update server cert updated')
    ]


def test_uses_rmt_as_scc_proxy():
    assert utils.uses_rmt_as_scc_proxy() == False


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
        with patch('builtins.open', create=True) as mock_framework_file:
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
    cfg.set('instance', 'instanceArgs', 'foo')
    assert utils.__get_framework_plugin(cfg) == None
    mock_logging.warning.assert_called_once_with(
        'Configured instanceArgs module could not be loaded. '
        'Continuing without additional arguments.'
    )


def test_get_framework_plugin():
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
    cfg.set('server', 'baseurl', 'bar')
    cfg.set('instance', 'baseurl', 'bar')
    cfg.set('service', 'baseurl', 'bar')
    mock_get_config.return_value = cfg
    assert utils.__get_referenced_credentials('foo') == []
    del cfg['server']['baseurl']
    del cfg['instance']['baseurl']
    del cfg['service']['baseurl']


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
    assert utils.__get_region_server_args(mod) == None
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
    assert utils.__has_credentials('foo') == True


@patch('cloudregister.registerutils.__get_referenced_credentials')
@patch('cloudregister.registerutils.glob.glob')
def test_has_credentials_in_service(mock_glob, mock_get_referenced_creds):
    mock_glob.return_value = ['/etc/zypp/credentials.d/service']
    mock_get_referenced_creds.return_value = ['service']
    assert utils.__has_credentials('foo') == True


@patch('cloudregister.registerutils.__get_referenced_credentials')
@patch('cloudregister.registerutils.glob.glob')
def test_has_credentials_in_service(mock_glob, mock_get_referenced_creds):
    mock_glob.return_value = ['/etc/zypp/credentials.d/service']
    mock_get_referenced_creds.return_value = ['service']
    assert utils.__has_credentials('foo') == True


@patch('cloudregister.registerutils.__get_referenced_credentials')
@patch('cloudregister.registerutils.glob.glob')
def test_has_credentials_not_found(mock_glob, mock_get_referenced_creds):
    mock_glob.return_value = []
    assert utils.__has_credentials('foo') == False


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
    mock_get_config.return_value = cfg
    smt_xml = dedent('''\
    <regionSMTdata>
      <smtInfo fingerprint="99:88:77:66"
        SMTserverIP="1.2.3.4"
        SMTserverIPv6="fc11::2"
        SMTserverName="foo.susecloud.net"
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
    assert utils.__remove_repo_artifacts('foo') == None
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
    assert utils.__remove_repo_artifacts('foo') == None
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


# ---------------------------------------------------------------------------
# Helper functions
class Response():
    """Fake a request response object"""
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


class MockServer:
    def get_ipv4(self):
        return '1.1.1.1'

    def get_ipv6(self):
        return '11:22:33:44::00'
