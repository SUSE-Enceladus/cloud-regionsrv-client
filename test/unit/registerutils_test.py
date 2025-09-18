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

from pytest import fixture
import logging
import configparser
import io
import json
import os
import pickle
import requests
import tempfile
import toml
import yaml
from collections import namedtuple
from ipaddress import IPv6Address
from pytest import raises
from textwrap import dedent

from unittest.mock import patch, call, MagicMock, Mock, mock_open
from lxml import etree

from cloudregister.logger import Logger

import cloudregister.registerutils as utils # noqa
from cloudregister.smt import SMT # noqa

test_path = '..'
data_path = test_path + os.sep + 'data/'

log_instance = Logger()
log = Logger.get_logger()

CACHE_SERVER_IPS = ['54.197.240.216', '54.225.105.144', '107.22.231.220']


class TestRegisterUtils:
    @fixture(autouse=True)
    def inject_fixtures(self, caplog):
        self._caplog = caplog

    def test_dir_constants(self):
        """Make sure our constants that define directory names meet our
           expectations.
           Whenever we add a new constant that defines a directory this test
           should be updated. If this test fails do not modify the test, fix the
           path definition in the code and make sure wherever it is used is
           proper."""
        _check_dir_path(utils.OLD_REGISTRATION_DATA_DIR)
        _check_dir_path(utils.REGISTRATION_DATA_DIR)
        _check_dir_path(utils.ZYPP_CREDENTIALS_PATH)

    def test_file_name_constants(self):
        """Make sure our constants that define file names meet our
           expectations.
           Whenever we add a new constant that defines a file name this test
           should be updated. If this test fails do not modify the test, fix the
           file name definition in the code and make sure wherever it is used is
           proper."""
        _check_file_name(utils.BASE_CREDENTIALS_NAME)
        _check_file_name(utils.AVAILABLE_SMT_SERVER_DATA_FILE_NAME)
        _check_file_name(utils.FRAMEWORK_IDENTIFIER)
        _check_file_name(utils.NEW_REGISTRATION_MARKER)
        _check_file_name(utils.REGISTRATION_COMPLETED_MARKER)
        _check_file_name(utils.REGISTERED_SMT_SERVER_DATA_FILE_NAME)
        _check_file_name(utils.RMT_AS_SCC_PROXY_MARKER)

    def test_get_profile_env_var(self):
        assert utils.get_profile_env_var(
            'some', '{0}/some_env'.format(data_path)
        ) == 'data'

    @patch('os.path.exists')
    def test_is_registry_registered(self, mock_os_path_exists):
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
    def test_get_available_smt_servers_no_cache(self, path_exists):
        path_exists.return_value = False
        available_servers = utils.get_available_smt_servers()
        assert [] == available_servers

    @patch('cloudregister.registerutils.get_state_dir')
    def test_get_available_smt_servers_cache(self, state_dir):
        state_dir.return_value = data_path
        available_servers = utils.get_available_smt_servers()
        assert len(available_servers) == 3
        for srv in available_servers:
            assert srv.get_ipv4() in CACHE_SERVER_IPS

    def test_get_credentials_no_file(self):
        user, passwd = utils.get_credentials(data_path + 'foo')
        assert user is None
        assert passwd is None

    def test_get_credentials(self):
        user, passwd = utils.get_credentials(data_path + 'credentials')
        assert user == 'SCC_1'
        assert passwd == 'a23'

    def test_get_state_dir(self):
        state_dir = utils.get_state_dir()
        assert state_dir == '/var/cache/cloudregister'

    @patch('cloudregister.registerutils.get_state_dir')
    def test_get_zypper_pid_cache_has_cache(self, state_dir):
        state_dir.return_value = data_path
        assert utils.get_zypper_pid_cache() == '28989'

    @patch('os.path.exists')
    def test_get_zypper_pid_cache_no_cache(self, path_exists):
        path_exists.return_value = False
        assert utils.get_zypper_pid_cache() == 0

    @patch('cloudregister.registerutils.get_zypper_command')
    def test_get_zypper_target_root_no_zypper(self, zypp_cmd):
        """Test behavior when zypper is not running"""
        zypp_cmd.return_value = None
        assert utils.get_zypper_target_root() == ''

    @patch('cloudregister.registerutils.get_zypper_command')
    def test_get_zypper_target_root_set_R_short(self, zypp_cmd):
        """Test behavior when zypper is "running" and has root set using -R and no
           other args"""
        zypp_cmd.return_value = '-R /foobar'
        assert utils.get_zypper_target_root() == '/foobar'

    @patch('cloudregister.registerutils.get_zypper_command')
    def test_get_zypper_target_root_set_R_long(self, zypp_cmd):
        """Test behavior when zypper is "running" and has root set using -R and
           other args"""
        zypp_cmd.return_value = '-R /foobar --no-interactive'
        assert utils.get_zypper_target_root() == '/foobar'

    @patch('cloudregister.registerutils.get_zypper_command')
    def test_get_zypper_target_root_set_root_short(self, zypp_cmd):
        """Test behavior when zypper is "running" and has root set using --root
           and no other args"""
        zypp_cmd.return_value = '--root /foobar'
        assert utils.get_zypper_target_root() == '/foobar'

    @patch('cloudregister.registerutils.get_zypper_command')
    def test_get_zypper_target_root_set_root_long(self, zypp_cmd):
        """Test behavior when zypper is "running" and has root set using --root
           and other args"""
        zypp_cmd.return_value = '--root /foobar --no-interactive'
        assert utils.get_zypper_target_root() == '/foobar'

    @patch('cloudregister.registerutils._get_region_server_args')
    @patch('cloudregister.registerutils._get_framework_plugin')
    @patch('cloudregister.registerutils.get_framework_identifier_path')
    @patch('cloudregister.registerutils.exec_subprocess')
    def test_has_region_changed_no_change(self, subproc, id_path, plugin, srvargs):
        subproc.return_value = (b'Google', b'', 0)
        id_path.return_value = data_path + 'framework_info'
        plugin.return_value = True
        srvargs.return_value = 'regionHint=us-central1-d'
        cfg = get_test_config()
        assert utils.has_region_changed(cfg) is False

    @patch('cloudregister.registerutils._get_system_mfg')
    @patch('cloudregister.registerutils._get_framework_plugin')
    def test_has_region_changed_no_dmidecode(self, plugin, mfg):
        plugin.return_value = False
        mfg.return_value = False
        cfg = get_test_config()
        assert utils.has_region_changed(cfg) is False

    @patch('cloudregister.registerutils._get_system_mfg')
    @patch('cloudregister.registerutils._get_framework_plugin')
    def test_has_region_changed_no_plugin(self, plugin, mfg):
        plugin.return_value = False
        mfg.return_value = 'Google'
        cfg = get_test_config()
        assert utils.has_region_changed(cfg) is False

    @patch('cloudregister.registerutils._get_region_server_args')
    @patch('cloudregister.registerutils._get_framework_plugin')
    @patch('cloudregister.registerutils.get_framework_identifier_path')
    @patch('cloudregister.registerutils.exec_subprocess')
    def test_has_region_changed_provider_change(self, subproc, id_path, plugin, srvargs):
        cfg = get_test_config()
        subproc.return_value = (b'Amazon EC2', b'', 0)
        id_path.return_value = data_path + 'framework_info'
        plugin.return_value = True
        srvargs.return_value = 'regionHint=us-central1-d'
        assert utils.has_region_changed(cfg) is True

    @patch('cloudregister.registerutils._get_region_server_args')
    @patch('cloudregister.registerutils._get_framework_plugin')
    @patch('cloudregister.registerutils.get_framework_identifier_path')
    @patch('cloudregister.registerutils.exec_subprocess')
    def test_has_region_changed_provider_and_region_change(
        self, subproc, id_path, plugin, srvargs
    ):
        subproc.return_value = (b'Amazon EC2', b'', 0)
        id_path.return_value = data_path + 'framework_info'
        plugin.return_value = True
        srvargs.return_value = 'regionHint=us-east-1'
        cfg = get_test_config()
        assert utils.has_region_changed(cfg) is True

    @patch('cloudregister.registerutils._get_region_server_args')
    @patch('cloudregister.registerutils._get_framework_plugin')
    @patch('cloudregister.registerutils.get_framework_identifier_path')
    @patch('cloudregister.registerutils.exec_subprocess')
    def test_has_region_changed_region_change(
        self, subproc, id_path, plugin, srvargs
    ):
        subproc.return_value = (b'Google', b'', 0)
        id_path.return_value = data_path + 'framework_info'
        plugin.return_value = True
        srvargs.return_value = 'regionHint=us-east2-f'
        cfg = get_test_config()
        assert utils.has_region_changed(cfg) is True

    @patch('cloudregister.registerutils.json.loads')
    @patch('cloudregister.registerutils._get_region_server_args')
    @patch('cloudregister.registerutils._get_framework_plugin')
    @patch('cloudregister.registerutils.get_framework_identifier_path')
    @patch('cloudregister.registerutils.exec_subprocess')
    def test_has_region_changed_provider_and_region_change_exception(
        self,
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

    def test_is_registration_supported_SUSE_Family(self):
        cfg = get_test_config()
        cfg.add_section('service')
        cfg.set('service', 'packageBackend', 'zypper')
        assert utils.is_registration_supported(cfg) is True

    def test_is_registration_supported_RHEL_Family(self):
        cfg = get_test_config()
        cfg.add_section('service')
        cfg.set('service', 'packageBackend', 'dnf')
        assert utils.is_registration_supported(cfg) is False

    def test_has_rmt_in_hosts(self):
        utils.HOSTSFILE_PATH = '{0}/hosts'.format(data_path)
        server = Mock()

        # The following entry is expected to be found
        server.get_FQDN = Mock(return_value='smt-foo.susecloud.net')
        assert utils.has_rmt_in_hosts(server) is True

        # The following entry is expected to be not found
        server.get_FQDN = Mock(return_value='bogus')
        assert utils.has_rmt_in_hosts(server) is False

        utils.HOSTSFILE_PATH = '/etc/hosts'

    def test_has_registry_in_hosts(self):
        utils.HOSTSFILE_PATH = '{0}/hosts'.format(data_path)
        server = Mock()

        # The following entry is expected to be found
        server.get_registry_FQDN = Mock(return_value='registry-foo.susecloud.net')
        assert utils.has_registry_in_hosts(server) is True

        # The following entry is expected to be not found
        server.get_registry_FQDN = Mock(return_value='bogus')
        assert utils.has_registry_in_hosts(server) is False

        utils.HOSTSFILE_PATH = '/etc/hosts'

    def test_clean_host_file_no_empty_bottom_lines(self):
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

    def test_clean_host_file_no_empty_bottom_lines_user_interfered(self):
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

    def test_clean_host_file_one_empty_bottom_line(self):
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

    def test_clean_host_file_some_empty_bottom_lines(self):
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

    def test_clean_host_file_some_empty_bottom_lines_smt_entry_is_last(self):
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

    def test_clean_host_file_one_empty_bottom_lines_smt_entry_is_last(self):
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

    def test_clean_host_file_no_empty_bottom_lines_smt_entry_is_last(self):
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

    def test_clean_host_file_some_empty_bottom_lines_only_FQDN_not_registry(self):
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

    @patch('cloudregister.registerutils.get_domain_name_from_region_server')
    def test_clean_host_file_no_domain_name_param(
        self, mock_get_domain_name_from_region_server
    ):
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
        mock_get_domain_name_from_region_server.return_value = 'susecloud.net'
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

    def test_clean_host_file_raised_exception(self):
        hosts_content = ""
        with patch('builtins.open', mock_open(read_data=hosts_content.encode())) as m:  # noqa: E501
            utils.clean_hosts_file('susecloud.net')

        assert m().write.mock_calls == []

    @patch('cloudregister.registerutils.has_rmt_ipv6_access')
    def test_add_hosts_entry(self, mock_has_rmt_ipv6_access):
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
    def test_add_hosts_entry_no_registry(self, mock_has_rmt_ipv6_access):
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
    def test_add_hosts_entry_registry_optional_empty(self, mock_has_ipv6_access):
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
    @patch('cloudregister.registerutils._get_framework_plugin')
    def test_add_region_server_args_to_URL(
        self,
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

    @patch('cloudregister.registerutils._get_framework_plugin')
    def test_add_region_server_args_to_URL_no_module(self, mock_get_framework_plugin):
        cfg = get_test_config()
        mock_get_framework_plugin.return_value = None
        utils.add_region_server_args_to_URL(None, cfg)

    @patch('cloudregister.registerutils.os.unlink')
    @patch('cloudregister.registerutils.os.path.exists')
    def test_clean_framework_identifier(
        self,
        mock_os_path_exists,
        mock_os_unlink
    ):
        utils.clean_framework_identifier()
        framework_info_path = '/var/cache/cloudregister/framework_info'
        mock_os_path_exists.assert_called_once_with(framework_info_path)
        mock_os_unlink.assert_called_once_with(framework_info_path)

    @patch('cloudregister.registerutils.glob.glob')
    @patch('cloudregister.registerutils.os.unlink')
    def test_clean_smt_cache(self, mock_os_unlink, mock_glob):
        mock_glob.return_value = ['currentSMTInfo.obj']
        utils.clean_smt_cache()
        mock_os_unlink.assert_called_once_with('currentSMTInfo.obj')

    @patch('cloudregister.registerutils._remove_state_file')
    def test_clear_new_reg_flag(self, mock_remove_state):
        utils.clear_new_registration_flag()
        mock_remove_state.assert_called_once_with(
            '/var/cache/cloudregister/newregistration'
        )

    @patch('cloudregister.registerutils._remove_state_file')
    def test_clear_reg_complete_flag(self, mock_remove_state):
        utils.clear_registration_completed_flag()
        mock_remove_state.assert_called_once_with(
            '/var/cache/cloudregister/registrationcompleted'
        )

    @patch('cloudregister.registerutils._remove_state_file')
    def test_clear_rmt_as_scc_proxy_flag(self, mock_remove_state):
        utils.clear_rmt_as_scc_proxy_flag()
        mock_remove_state.assert_called_once_with(
            '/var/cache/cloudregister/rmt_is_scc_proxy'
        )

    @patch('cloudregister.registerutils.register_product')
    @patch('cloudregister.registerutils.get_installed_products')
    @patch('cloudregister.registerutils.get_credentials')
    @patch('cloudregister.registerutils.get_product_tree')
    @patch('cloudregister.registerutils.get_current_smt')
    @patch('cloudregister.registerutils.requests.get')
    def test_clean_non_free_extensions(
        self,
        mock_requests_get,
        mock_get_current_smt,
        mock_get_product_tree,
        mock_get_creds,
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
        assert 'No credentials entry for "*fantasy_example_com"' in self._caplog.text
        assert 'No credentials entry for "SCC*"' in self._caplog.text
        assert 'Non free extension SLES-LTSS/15.4/x86_64 removed' in self._caplog.text

    @patch('cloudregister.registerutils.is_suma_instance')
    @patch('cloudregister.registerutils.register_product')
    @patch('cloudregister.registerutils.get_installed_products')
    @patch('cloudregister.registerutils.get_credentials')
    @patch('cloudregister.registerutils.get_product_tree')
    @patch('cloudregister.registerutils.get_current_smt')
    @patch('cloudregister.registerutils.requests.get')
    def test_clean_non_free_extensions_should_not_be_removed(
        self,
        mock_requests_get,
        mock_get_current_smt,
        mock_get_product_tree,
        mock_get_creds,
        mock_get_installed_products,
        mock_register_product,
        mock_is_suma_instance
    ):
        mock_get_installed_products.return_value = [
            'Multi-Linux-Manager-Server/5.1/x86_64',
            'SLES-LTSS/15.4/x86_64'
        ]
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
                    'name': 'Multi-Linux-Manager-Server',
                    'identifier': 'Multi-Linux-Manager-Server',
                    'former_identifier': 'Multi-Linux-Manager-Server',
                    'version': '5.1',
                    'release_type': None,
                    'release_stage': 'released',
                    'arch': 'x86_64',
                    'friendly_name':
                    'Multi Linux Manager Server 5.1 x86_64',
                    'product_class': 'SLES15-SP4-LTSS-X86',
                    'free': False,
                    'repositories': [],
                    'product_type': 'extension',
                    'extensions': [],
                    'recommended': False,
                    'available': True
                },
                {
                    'id': 42,
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
              <name>SL-Micro</name>
              <version>6.0</version>
              <baseversion>6</baseversion>
              <patchlevel>0</patchlevel>
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
        mock_is_suma_instance.return_value = True
        utils.clean_non_free_extensions()
        assert mock_register_product.call_args_list == [
            call(
                registration_target=smt_server,
                product='SLES-LTSS/15.4/x86_64',
                de_register=True
            )
        ]
        assert 'No credentials entry for "*fantasy_example_com"' in self._caplog.text
        assert 'No credentials entry for "SCC*"' in self._caplog.text
        assert 'Non free extension SLES-LTSS/15.4/x86_64 removed' in self._caplog.text

    @patch('cloudregister.registerutils.register_product')
    @patch('cloudregister.registerutils.get_installed_products')
    @patch('cloudregister.registerutils.get_credentials')
    @patch('cloudregister.registerutils.get_product_tree')
    @patch('cloudregister.registerutils.get_current_smt')
    @patch('cloudregister.registerutils.requests.get')
    def test_clean_non_free_extensions_failed(
        self,
        mock_requests_get,
        mock_get_current_smt,
        mock_get_product_tree,
        mock_get_creds,
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
        assert 'No credentials entry for "*fantasy_example_com"' in self._caplog.text
        assert 'No credentials entry for "SCC*"' in self._caplog.text
        assert 'Non free extension SLES-LTSS/15.4/x86_64 failed to be removed' in self._caplog.text

    @patch('cloudregister.registerutils.os.unlink')
    @patch('cloudregister.registerutils.get_credentials')
    @patch('cloudregister.registerutils.get_product_tree')
    @patch('cloudregister.registerutils.get_current_smt')
    @patch('cloudregister.registerutils.requests.get')
    def test_clean_non_free_extensions_request_failed(
        self,
        mock_requests_get,
        mock_get_current_smt,
        mock_get_product_tree,
        mock_get_creds,
        mock_os_unlink
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
        assert 'No matching credentials file found' in self._caplog.text
        assert 'Unable to obtain product information' in self._caplog.text

    @patch('cloudregister.registerutils.os.unlink')
    @patch('cloudregister.registerutils.get_credentials')
    @patch('cloudregister.registerutils.get_product_tree')
    @patch('cloudregister.registerutils.get_current_smt')
    @patch('cloudregister.registerutils.requests.get')
    def test_clean_non_free_extensions_no_credentials(
        self,
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
    @patch('cloudregister.registerutils.os.access')
    @patch('cloudregister.registerutils.os.path.exists')
    @patch('cloudregister.registerutils.subprocess.Popen')
    def test_register_product_no_transactional_ok(
        self,
        mock_popen, mock_os_path_exists,
        mock_os_access, mock_get_register_cmd
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
        assert '/usr/sbin/SUSEConnect' in self._caplog.text
        assert '--url https://foo-ec2.susecloud.net' in self._caplog.text

    @patch('cloudregister.registerutils.get_register_cmd')
    @patch('cloudregister.registerutils.os.access')
    @patch('cloudregister.registerutils.os.path.exists')
    @patch('cloudregister.registerutils.subprocess.Popen')
    def test_register_product_no_transactional_de_register_ok(
        self,
        mock_popen, mock_os_path_exists,
        mock_os_access, mock_get_register_cmd
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
        assert '--de-register' in self._caplog.text

    @patch('cloudregister.registerutils.get_register_cmd')
    @patch('cloudregister.registerutils.os.access')
    @patch('cloudregister.registerutils.os.path.exists')
    @patch('cloudregister.registerutils.subprocess.Popen')
    def test_register_product_no_transactional_de_register_missing_product(
        self,
        mock_popen, mock_os_path_exists,
        mock_os_access, mock_get_register_cmd
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
        assert 'De-register the system is not allowed for SUSEConnect' in self._caplog.text

    @patch('cloudregister.registerutils.get_register_cmd')
    @patch('cloudregister.registerutils.os.access')
    @patch('cloudregister.registerutils.os.path.exists')
    @patch('cloudregister.registerutils.subprocess.Popen')
    def test_register_product_transactional_ok(
        self,
        mock_popen, mock_os_path_exists,
        mock_os_access, mock_get_register_cmd
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
        assert '/usr/sbin/transactional' in self._caplog.text

    @patch('cloudregister.registerutils.get_register_cmd')
    @patch('cloudregister.registerutils.os.access')
    @patch('cloudregister.registerutils.os.path.exists')
    @patch('cloudregister.registerutils.subprocess.Popen')
    def test_register_product_no_exists(
        self,
        mock_popen, mock_os_path_exists,
        mock_os_access, mock_get_register_cmd
    ):
        mock_os_path_exists.return_value = False
        with raises(SystemExit) as sys_exit:
            utils.register_product('foo')
        assert sys_exit.value.code == 1
        assert 'No registration executable found' in self._caplog.text

    @patch('cloudregister.registerutils.os.path.exists')
    @patch('cloudregister.registerutils.os.unlink')
    def test_remove_state_flag(self, mock_os_unlink, mock_file_exist):
        mock_os_unlink.side_effect = FileNotFoundError
        mock_file_exist.return_value = True
        utils._remove_state_file('foo')
        mock_os_unlink.assert_called_once_with('foo')

    @patch('cloudregister.registerutils.subprocess.Popen')
    def test_get_register_cmd_error(self, mock_popen):
        mock_process = Mock()
        mock_process.communicate = Mock(
            return_value=[str.encode(''), str.encode('')]
        )
        mock_process.returncode = 1
        mock_popen.return_value = mock_process
        assert utils.get_register_cmd() == '/usr/sbin/SUSEConnect'
        assert 'Unable to find filesystem information for "/"' in self._caplog.text

    @patch('cloudregister.registerutils.os.path.exists')
    @patch('cloudregister.registerutils.json.loads')
    @patch('cloudregister.registerutils.subprocess.Popen')
    def test_get_register_cmd_path_not_exist(
        self, mock_popen, mock_json_loads, mock_os_path_exists
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
        assert 'transactional-update command not found' in self._caplog.text

    @patch('cloudregister.registerutils.os.path.exists')
    @patch('cloudregister.registerutils.json.loads')
    @patch('cloudregister.registerutils.subprocess.Popen')
    def test_get_register_cmd_ok(
        self, mock_popen, mock_json_loads, mock_os_path_exists
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
        self, mock_popen, mock_json_loads, mock_os_path_exists
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
    def test_get_product_tree(self, mock_path_isfile):
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
    def test_credentials_files_are_equal(self, mock_get_credentials):
        mock_get_credentials.side_effect = [('SCC_foo', 'bar'), ('SCC_foo', 'bar')]
        assert utils.credentials_files_are_equal('foo') is True
        assert mock_get_credentials.mock_calls == [
            call('/etc/zypp/credentials.d/SCCcredentials'),
            call('/etc/zypp/credentials.d/foo')
        ]

        mock_get_credentials.side_effect = [('SCC_bar', 'bar'), ('SCC_foo', 'bar')]
        assert utils.credentials_files_are_equal('foo') is False

    def test_credentials_files_are_equal_no_credentials(self):
        assert utils.credentials_files_are_equal(None) is False

    def test_credentials_files_are_equal_no_valid_credentials(self):
        assert utils.credentials_files_are_equal('foo'.encode('utf-8')) is False
        assert utils.credentials_files_are_equal([]) is False
        assert utils.credentials_files_are_equal(['foo']) is False
        assert utils.credentials_files_are_equal('') is False

    @patch('cloudregister.registerutils.exec_subprocess')
    def test_enable_repository(self, mock_exec_subprocess):
        utils.enable_repository('super_repo')
        mock_exec_subprocess.assert_called_once_with(
            ['zypper', 'mr', '-e', 'super_repo']
        )

    def test_exec_subprocess_exception(self):
        assert utils.exec_subprocess(['aa']) == -1

    @patch('cloudregister.registerutils.subprocess.Popen')
    def test_exec_subprocess(self, mock_popen):
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

    @patch('cloudregister.registerutils.requests.get')
    def test_fetch_smt_data_not_200_exception(
        self,
        mock_request_get,
    ):
        cfg = get_test_config()
        response = Response()
        response.status_code = 422
        mock_request_get.return_value = response
        with raises(SystemExit):
            utils.fetch_smt_data(cfg, None)
        assert 'Metadata server returned 422' in self._caplog.text
        assert 'Unable to obtain update server information, exiting' in self._caplog.text

    @patch('cloudregister.registerutils.requests.get')
    def test_fetch_smt_data_no_response_text(
        self,
        mock_request_get,
    ):
        cfg = get_test_config()
        response = Response()
        response.status_code = 200
        response.text = "{}"
        mock_request_get.return_value = response
        with raises(SystemExit):
            utils.fetch_smt_data(cfg, None)
        assert 'Metadata server did not supply a value for "fingerprint"' in \
            self._caplog.text

    @patch('cloudregister.registerutils.requests.get')
    def test_fetch_smt_data_metadata_server(
        self,
        mock_request_get,
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

    @patch('cloudregister.registerutils.has_ipv6_access')
    @patch('cloudregister.registerutils.time.sleep')
    def test_fetch_smt_data_api_no_answer(
        self,
        mock_time_sleep,
        mock_has_ipv6_access
    ):
        cfg = get_test_config()
        del cfg['server']['metadata_server']
        cfg.set('server', 'regionsrv', '1.1.1.1')
        mock_has_ipv6_access.return_value = True
        with raises(SystemExit):
            utils.fetch_smt_data(cfg, None)
        assert 'No cert found' in self._caplog.text
        assert 'Waiting 20 seconds before next attempt' in self._caplog.text
        assert 'Request not answered by any server after 3 attempts' in self._caplog.text

    @patch('cloudregister.registerutils.has_ipv6_access')
    @patch('cloudregister.registerutils.requests.get')
    @patch('cloudregister.registerutils.os.path.isfile')
    @patch('cloudregister.registerutils.time.sleep')
    def test_fetch_smt_data_api_answered(
        self,
        mock_time_sleep,
        mock_os_path_isfile,
        mock_request_get,
        mock_has_ipv6_access
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
        mock_has_ipv6_access.return_value = False
        utils.fetch_smt_data(cfg, None)
        assert 'Getting update server information, attempt 1' in self._caplog.text
        assert 'Using region server: 1.1.1.1' in self._caplog.text

    @patch('cloudregister.registerutils.has_ipv6_access')
    @patch('cloudregister.registerutils.requests.get')
    @patch('cloudregister.registerutils.os.path.isfile')
    @patch('cloudregister.registerutils.time.sleep')
    def test_fetch_smt_data_api_answered_from_server_with_name(
        self,
        mock_time_sleep,
        mock_os_path_isfile,
        mock_request_get,
        mock_has_ipv6_access
    ):
        cfg = get_test_config()
        del cfg['server']['metadata_server']
        cfg.set('server', 'regionsrv', 'localhost:1234')
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
        mock_has_ipv6_access.return_value = False
        utils.fetch_smt_data(cfg, None)
        assert 'Using region server: localhost:1234' in self._caplog.text

    @patch('cloudregister.registerutils._get_region_server_ips')
    @patch('socket.create_connection')
    @patch('cloudregister.registerutils.ipaddress.ip_address')
    @patch('cloudregister.registerutils.requests.get')
    @patch('cloudregister.registerutils.os.path.isfile')
    @patch('cloudregister.registerutils.time.sleep')
    def test_fetch_smt_data_api_no_valid_ip(
        self,
        mock_time_sleep,
        mock_os_path_isfile,
        mock_request_get,
        mock_ipaddress_ip_address,
        mock_socket_create_connection,
        mock_get_region_server_ips
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
        mock_ipaddress_ip_address.side_effect = [
            ValueError, ValueError, IPv6Address
        ]
        mock_socket_create_connection.side_effect = OSError
        mock_get_region_server_ips.return_value = \
            ['1.1.1.1'], ['fc11::2'], ['foo']
        smt_data = utils.fetch_smt_data(cfg, None)
        assert etree.tostring(smt_data, encoding='utf-8') == smt_xml.encode()

    @patch('cloudregister.registerutils.has_ipv6_access')
    @patch('cloudregister.registerutils.requests.get')
    @patch('cloudregister.registerutils.os.path.isfile')
    @patch('cloudregister.registerutils.time.sleep')
    def test_fetch_smt_data_api_error_response(
        self,
        mock_time_sleep,
        mock_os_path_isfile,
        mock_request_get,
        mock_has_ipv6_access
    ):
        cfg = get_test_config()
        del cfg['server']['metadata_server']
        cfg.set('server', 'regionsrv', '1.1.1.1')
        mock_os_path_isfile.return_value = True
        response = Response()
        response.status_code = 422
        response.reason = 'well, you shall not pass'
        mock_request_get.return_value = response
        mock_has_ipv6_access.return_value = False
        with raises(SystemExit):
            utils.fetch_smt_data(cfg, None)
        assert 'Server returned: 422' in self._caplog.text
        assert 'Server error: "well, you shall not pass"' in self._caplog.text

    @patch('cloudregister.registerutils.has_ipv6_access')
    @patch('cloudregister.registerutils.requests.get')
    @patch('cloudregister.registerutils.os.path.isfile')
    @patch('cloudregister.registerutils.time.sleep')
    def test_fetch_smt_data_api_exception(
        self,
        mock_time_sleep,
        mock_os_path_isfile,
        mock_request_get,
        mock_has_ipv6_access
    ):
        cfg = get_test_config()
        del cfg['server']['metadata_server']
        cfg.set('server', 'regionsrv', 'fc00::11')
        mock_os_path_isfile.return_value = True
        response = Response()
        response.status_code = 422
        response.reason = 'well, you shall not pass'
        mock_request_get.side_effect = requests.exceptions.RequestException('foo')
        mock_has_ipv6_access.return_value = True
        with raises(SystemExit):
            utils.fetch_smt_data(cfg, None)

    @patch('cloudregister.registerutils.has_ipv6_access')
    @patch('cloudregister.registerutils.requests.get')
    @patch('cloudregister.registerutils.os.path.isfile')
    @patch('cloudregister.registerutils.time.sleep')
    def test_fetch_smt_data_api_exception_quiet(
        self,
        mock_time_sleep,
        mock_os_path_isfile,
        mock_request_get,
        mock_has_ipv6_access
    ):
        cfg = get_test_config()
        del cfg['server']['metadata_server']
        cfg.set('server', 'regionsrv', '1.1.1.1')
        mock_os_path_isfile.return_value = True
        response = Response()
        response.status_code = 422
        response.reason = 'well, you shall not pass'
        mock_request_get.side_effect = requests.exceptions.RequestException('foo')
        mock_has_ipv6_access.return_value = True
        with raises(SystemExit):
            utils.fetch_smt_data(cfg, 'foo', quiet=True)
        assert 'Waiting 20 seconds before next attempt' in self._caplog.text
        assert 'Waiting 10 seconds before next attempt' in self._caplog.text
        assert 'Exiting without registration' in self._caplog.text

    @patch.object(SMT, 'is_responsive')
    def test_find_equivalent_smt_server(self, mock_is_responsive):
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
    def test_find_repos(self, mock_glob):
        mock_glob.return_value = ['../data/repo_foo.repo']
        assert utils.find_repos('Foo') == ['SLE-Module-Live-Foo15-SP5-Source-Pool']

    @patch('cloudregister.registerutils.get_credentials_file')
    @patch('cloudregister.registerutils.get_credentials')
    @patch('cloudregister.registerutils.get_smt')
    def test_get_activations_no_user_pass(
        self,
        mock_get_smt,
        mock_get_creds,
        mock_get_creds_file
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
        assert 'Unable to extract username and password for "fantasy.example.com"' in \
            self._caplog.text

    @patch('cloudregister.registerutils.requests.get')
    @patch('cloudregister.registerutils.get_instance_data')
    @patch('cloudregister.registerutils.get_config')
    @patch('cloudregister.registerutils.HTTPBasicAuth')
    @patch('cloudregister.registerutils.get_credentials_file')
    @patch('cloudregister.registerutils.get_credentials')
    @patch('cloudregister.registerutils.get_smt')
    def test_get_activations_request_wrong(
        self,
        mock_get_smt,
        mock_get_creds,
        mock_get_creds_file,
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
        assert 'Unable to get product info from update server:' in self._caplog.text
        mock_request_get.assert_called_once_with(
            'https://fantasy.example.com/connect/systems/activations',
            auth='foobar',
            headers={'X-Instance-Data': b'c3VwZXJfaW5zdGFuY2VfZGF0YQ=='}
        )

    @patch('cloudregister.registerutils.requests.get')
    @patch('cloudregister.registerutils.get_instance_data')
    @patch('cloudregister.registerutils.get_config')
    @patch('cloudregister.registerutils.HTTPBasicAuth')
    @patch('cloudregister.registerutils.get_credentials_file')
    @patch('cloudregister.registerutils.get_credentials')
    @patch('cloudregister.registerutils.get_smt')
    def test_get_activations_request_OK(
        self,
        mock_get_smt,
        mock_get_creds,
        mock_get_creds_file,
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
        mock_request_get.assert_called_once_with(
            'https://fantasy.example.com/connect/systems/activations',
            auth='foobar',
            headers={'X-Instance-Data': b'c3VwZXJfaW5zdGFuY2VfZGF0YQ=='}
        )

    @patch('cloudregister.registerutils.configparser.RawConfigParser.read')
    def test_get_config(self, mock_config_parser):
        mock_config_parser.return_value = data_path + '/regionserverclnt.cfg'
        assert type(utils.get_config()) == configparser.RawConfigParser

    @patch('cloudregister.registerutils.sys.exit')
    def test_get_config_not_parsed(self, mock_sys_exit):
        utils.get_config('bogus')
        mock_sys_exit.assert_called_once_with(1)

    @patch('cloudregister.registerutils.configparser.RawConfigParser.read')
    def test_get_config_exception(self, mock_configparser):
        mock_configparser.side_effect = configparser.Error
        with raises(SystemExit) as pytest_wrapped_e:
            utils.get_config()

        assert pytest_wrapped_e.type == SystemExit
        assert pytest_wrapped_e.value.code == 1

    @patch('cloudregister.registerutils.glob.glob')
    def test_get_credentials_file_no_file(self, mock_glob):
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
        assert 'No credentials entry for "*bar*"' in self._caplog.text
        assert 'No credentials entry for "*fantasy_example_com"' in self._caplog.text
        assert 'No credentials entry for "SCC*"' in self._caplog.text
        assert 'No matching credentials file found' in self._caplog.text

    @patch('cloudregister.registerutils.glob.glob')
    def test_get_credentials_two_files(self, mock_glob):
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
        assert 'Found multiple credentials for "None" entry' in self._caplog.text

    @patch('cloudregister.registerutils.get_smt_from_store')
    def test_get_current_smt_no_smt(self, mock_get_smt_from_store):
        mock_get_smt_from_store.return_value = None
        assert utils.get_current_smt() is None

    @patch('cloudregister.registerutils.os.unlink')
    @patch('cloudregister.registerutils.get_smt_from_store')
    def test_get_current_smt_no_match(self, mock_get_smt_from_store, mock_os_unlink):
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

    @patch('cloudregister.registerutils.is_registered')
    @patch('cloudregister.registerutils.get_smt_from_store')
    @patch('re.search')
    def test_get_current_smt_no_registered(
        self, mock_re_search, mock_get_smt_from_store, mock_is_registered
    ):
        smt = Mock()
        mock_re_search.return_value = True
        mock_is_registered.return_value = False
        mock_get_smt_from_store.return_value = smt

        with patch('builtins.open'):
            assert utils.get_current_smt() is None

    @patch('cloudregister.registerutils.is_registered')
    @patch('cloudregister.registerutils.get_smt_from_store')
    def test_get_current_smt(self, mock_get_smt_from_store, mock_is_registered):
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

    def test_get_framework_identifier_path(self):
        assert utils.get_framework_identifier_path() == \
            '/var/cache/cloudregister/framework_info'

    def test_get_instance_no_instance_section(self):
        """The configuration has no instance section configured"""
        cfg = get_test_config()
        expected_data = '<repoformat>plugin:susecloud</repoformat>\n'
        assert utils.get_instance_data(cfg) == expected_data

    def test_get_instance_no_data_provider_option(self):
        """The configuration has no dataProvider configured"""
        cfg = get_test_config()
        cfg.add_section('instance')
        expected_data = '<repoformat>plugin:susecloud</repoformat>\n'
        assert utils.get_instance_data(cfg) == expected_data

    def test_get_instance_data_provider_option_none(self):
        """The configuration has a dataProvider option but it is set to none"""
        cfg = get_test_config()
        cfg.add_section('instance')
        cfg.set('instance', 'dataProvider', 'none')
        expected_data = '<repoformat>plugin:susecloud</repoformat>\n'
        assert utils.get_instance_data(cfg) == expected_data

    def test_get_instance_data_cmd_not_found(self):
        cfg = get_test_config()
        cfg.add_section('instance')
        # Let's assume we run on a system where the fussball command does not exist
        cfg.set('instance', 'dataProvider', 'fussball')
        expected_data = '<repoformat>plugin:susecloud</repoformat>\n'
        assert utils.get_instance_data(cfg) == expected_data
        assert 'Could not find configured dataProvider: fussball' in self._caplog.text

    @patch('cloudregister.registerutils.os.access')
    @patch('cloudregister.registerutils.exec_subprocess')
    def test_get_instance_data_cmd_error(
        self,
        mock_exec_sub,
        mock_access
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
        assert 'Data collected from stderr for instance data collection "bar"' in \
            self._caplog.text

    @patch('cloudregister.registerutils.os.access')
    @patch('cloudregister.registerutils.exec_subprocess')
    def test_get_instance_data_no_data(
        self,
        mock_exec_sub,
        mock_access
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
        assert 'Possible issue accessing the metadata service. Metadata is empty' in \
            self._caplog.text

    @patch('cloudregister.registerutils.os.access')
    @patch('cloudregister.registerutils.exec_subprocess')
    def test_get_instance_data_instance_data(
        self,
        mock_exec_sub,
        mock_access
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
    @patch('cloudregister.registerutils.is_zypper_running')
    def test_get_installed_products_no_zypper_lock(
        self,
        mock_is_zypper_running,
        mock_time_sleep
    ):
        mock_is_zypper_running.return_value = True
        assert utils.get_installed_products() == []
        assert 'Wait time expired could not acquire zypper lock file' in self._caplog.text
        assert mock_time_sleep.call_args_list == [
            call(0),
            call(5),
            call(10),
            call(15)
        ]

    @patch('cloudregister.registerutils.subprocess.Popen')
    @patch('cloudregister.registerutils.time.sleep')
    @patch('cloudregister.registerutils.is_zypper_running')
    def test_get_installed_products_cmd_error(
        self,
        mock_is_zypper_running,
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
        assert 'zypper product query returned with zypper code 1' in self._caplog.text

    @patch('cloudregister.registerutils.subprocess.Popen')
    @patch('cloudregister.registerutils.time.sleep')
    @patch('cloudregister.registerutils.is_zypper_running')
    def test_get_installed_products_cmd_oserror_exception(
        self,
        mock_is_zypper_running,
        mock_time_sleep,
        mock_popen
    ):
        mock_is_zypper_running.side_effect = [True, False]
        mock_popen.side_effect = OSError('No such file or directory')
        assert utils.get_installed_products() == []
        assert 'Could not get product list' in self._caplog.text

    @patch('cloudregister.registerutils.os.path.realpath')
    @patch('cloudregister.registerutils.os.path.islink')
    @patch('cloudregister.registerutils.subprocess.Popen')
    @patch('cloudregister.registerutils.time.sleep')
    @patch('cloudregister.registerutils.is_zypper_running')
    def test_get_installed_products_OK(
        self,
        mock_is_zypper_running,
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

    @patch('cloudregister.registerutils.os.path.realpath')
    @patch('cloudregister.registerutils.os.path.islink')
    @patch('cloudregister.registerutils.subprocess.Popen')
    @patch('cloudregister.registerutils.time.sleep')
    @patch('cloudregister.registerutils.is_zypper_running')
    def test_get_installed_products_baseprod(
        self,
        mock_is_zypper_running,
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

    @patch('cloudregister.registerutils.os.path.realpath')
    @patch('cloudregister.registerutils.os.path.islink')
    @patch('cloudregister.registerutils.subprocess.Popen')
    @patch('cloudregister.registerutils.time.sleep')
    @patch('cloudregister.registerutils.is_zypper_running')
    def test_get_installed_products_no_link(
        self,
        mock_is_zypper_running,
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
        assert 'No baseproduct installed system cannot be registered' in self._caplog.text

    @patch('cloudregister.registerutils.glob.glob')
    def test_get_repo_url(self, mock_glob):
        mock_glob.return_value = ['../data/repo_foo.repo']
        assert utils.get_repo_url('SLE-Module-Live-Foo15-SP5-Source-Pool') == (
            'plugin:/susecloud?credentials=SUSE_Linux_Enterprise_Live_Foo_x86_64&'
            'path=/repo/SUSE/Products/SLE-Module-Live-Foo/15-SP5/x86_64/'
            'product_source/')

    @patch('cloudregister.registerutils.glob.glob')
    def test_get_repo_url_no_repos(self, mock_glob):
        mock_glob.return_value = []
        assert utils.get_repo_url('') == ''

    @patch('cloudregister.registerutils.time.sleep')
    @patch.object(SMT, 'is_responsive')
    @patch('cloudregister.registerutils.is_registered')
    @patch('cloudregister.registerutils.get_available_smt_servers')
    @patch('cloudregister.registerutils.get_current_smt')
    def test_get_smt_network_issue(
        self,
        mock_get_current_smt,
        mock_get_available_smt_servers,
        mock_is_registered,
        mock_smt_is_responsive,
        mock_time_sleep
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
        assert 'Waiting for current server to show up for 5 s' in self._caplog.text
        assert 'No failover needed, system access recovered' in self._caplog.text
        assert mock_time_sleep.call_args_list == [call(5)]

    @patch.object(SMT, 'is_responsive')
    @patch('cloudregister.registerutils.is_registered')
    @patch('cloudregister.registerutils.get_available_smt_servers')
    @patch('cloudregister.registerutils.get_current_smt')
    def test_get_smt_registered_no_network(
        self,
        mock_get_current_smt,
        mock_get_available_smt_servers,
        mock_is_registered,
        mock_smt_is_responsive
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
        assert 'Current update server will be used: "(\'192.168.1.1\', \'fc00::1\')"' in \
            self._caplog.text

    @patch('cloudregister.registerutils.time.sleep')
    @patch('cloudregister.registerutils.set_as_current_smt')
    @patch('cloudregister.registerutils.replace_hosts_entry')
    @patch('cloudregister.registerutils.has_smt_access')
    @patch('cloudregister.registerutils.get_credentials')
    @patch('cloudregister.registerutils.get_credentials_file')
    @patch('cloudregister.registerutils.import_smt_cert')
    @patch.object(SMT, 'is_responsive')
    @patch('cloudregister.registerutils.find_equivalent_smt_server')
    @patch('cloudregister.registerutils.is_registered')
    @patch('cloudregister.registerutils.get_available_smt_servers')
    @patch('cloudregister.registerutils.get_current_smt')
    def test_get_smt_find_equivalent(
        self,
        mock_get_current_smt,
        mock_get_available_smt_servers,
        mock_is_registered,
        mock_find_equivalent_smt_server,
        mock_smt_is_responsive,
        mock_import_smt_cert,
        mock_get_credentials_file,
        mock_get_credentials,
        mock_has_smt_access,
        mock_replace_hosts_entry,
        mock_set_as_current_smt,
        mock_time_sleep
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
        assert 'Using equivalent update server: "(\'42.168.1.1\', \'fc00::7\')"' in \
            self._caplog.text

    @patch('cloudregister.registerutils.time.sleep')
    @patch('cloudregister.registerutils.set_as_current_smt')
    @patch('cloudregister.registerutils.replace_hosts_entry')
    @patch('cloudregister.registerutils.has_smt_access')
    @patch('cloudregister.registerutils.get_credentials')
    @patch('cloudregister.registerutils.get_credentials_file')
    @patch('cloudregister.registerutils.import_smt_cert')
    @patch.object(SMT, 'is_responsive')
    @patch('cloudregister.registerutils.find_equivalent_smt_server')
    @patch('cloudregister.registerutils.is_registered')
    @patch('cloudregister.registerutils.get_available_smt_servers')
    @patch('cloudregister.registerutils.get_current_smt')
    def test_get_smt_equivalent_smt_no_access(
        self,
        mock_get_current_smt,
        mock_get_available_smt_servers,
        mock_is_registered,
        mock_find_equivalent_smt_server,
        mock_smt_is_responsive,
        mock_import_smt_cert,
        mock_get_credentials_file,
        mock_get_credentials,
        mock_has_smt_access,
        mock_replace_hosts_entry,
        mock_set_as_current_smt,
        mock_time_sleep
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
        assert 'Using equivalent update server: "(\'42.168.1.1\', \'fc00::7\')"' in \
            self._caplog.text
        assert "Sibling update server, ('42.168.1.1', 'fc00::7'), does not have " in \
            self._caplog.text
        assert 'system credentials cannot failover. Retaining current, ' in \
            self._caplog.text
        assert "('192.168.1.1', 'fc00::1'), target update server.Try again later." in \
            self._caplog.text

    @patch('cloudregister.registerutils.set_as_current_smt')
    @patch('cloudregister.registerutils.add_hosts_entry')
    @patch('cloudregister.registerutils.import_smt_cert')
    @patch.object(SMT, 'is_responsive')
    @patch('cloudregister.registerutils.clean_hosts_file')
    @patch('cloudregister.registerutils.get_available_smt_servers')
    @patch('cloudregister.registerutils.get_current_smt')
    def test_get_smt_alternative_server(
        self,
        mock_get_current_smt,
        mock_get_available_smt_servers,
        mock_clean_hosts_file,
        mock_smt_is_responsive,
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
        assert 'Found alternate update server: "(\'192.168.1.1\', \'fc00::1\')"' in \
            self._caplog.text
        mock_add_hosts_entry.assert_called_once_with(alternative_smt_server)
        mock_set_as_current_smt.assert_called_once_with(alternative_smt_server)
        mock_set_as_current_smt.assert_called_once_with(alternative_smt_server)
        mock_clean_hosts_file.assert_called_once_with('susecloud.net')

    @patch('cloudregister.registerutils._populate_srv_cache')
    @patch('cloudregister.registerutils.clean_smt_cache')
    @patch.object(SMT, 'is_responsive')
    @patch('cloudregister.registerutils.clean_hosts_file')
    @patch('cloudregister.registerutils.get_available_smt_servers')
    @patch('cloudregister.registerutils.get_current_smt')
    def test_get_smt_refresh_cache(
        self,
        mock_get_current_smt,
        mock_get_available_smt_servers,
        mock_clean_hosts_file,
        mock_smt_is_responsive,
        mock_clean_smt_cache,
        mock_populate_srv_cache
    ):
        mock_get_available_smt_servers.return_value = []
        mock_get_current_smt.return_value = None
        utils.get_smt()
        mock_clean_smt_cache.assert_called_once()
        mock_populate_srv_cache.assert_called_once()

    @patch('cloudregister.registerutils.os.path.exists')
    def test_get_smt_from_store_non_existing_path(self, mock_os_path_exists):
        mock_os_path_exists.return_value = False
        assert utils.get_smt_from_store('foo') is None

    @patch.object(pickle, 'Unpickler')
    def test_get_smt_from_store_raise_exception(self, mock_unpickler):
        unpick = Mock()
        mock_unpickler.return_value = unpick
        unpick.load.side_effect = pickle.UnpicklingError
        assert utils.get_smt_from_store(
            '../data/availableSMTInfo_1.obj'
        ) is None

    @patch('cloudregister.registerutils.get_available_smt_servers')
    def test_get_update_server_name_from_hosts(self, mock_get_available_smt_servers):
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
    def test_get_zypper_command(self, mock_zypper_pid):
        mock_zypper_pid.return_value = 42
        with patch(
            'builtins.open', mock_open(read_data='\x00foo')
        ):
            assert utils.get_zypper_command() == ' foo'

    @patch('cloudregister.registerutils.subprocess.Popen')
    def test_get_zypper_pid_one_pid(self, mock_popen):
        mock_process = Mock()
        mock_process.communicate = Mock(
            return_value=[str.encode('12345 '), str.encode('stderr')]
        )
        mock_process.returncode = 0
        mock_popen.return_value = mock_process
        assert utils.get_zypper_pid() == '12345'

    @patch('cloudregister.registerutils.subprocess.Popen')
    def test_get_zypper_pid_with_child_pid(self, mock_popen):
        mock_process = Mock()
        mock_process.communicate = Mock(
            return_value=[str.encode('12345\n    6789\n'), str.encode('stderr')]
        )
        mock_process.returncode = 0
        mock_popen.return_value = mock_process
        assert utils.get_zypper_pid() == '12345'

    @patch('cloudregister.registerutils.has_ipv6_access')
    def test_has_rmt_ipv6_access_no_ipv6_defined(self, mock_ipv6_access):
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
        self,
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
        self,
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
    def test_has_nvidia_support(self, mock_subprocess):
        mock_subprocess.return_value = b'NVIDIA', 'bar', 0
        assert utils.has_nvidia_support() is True

    @patch('cloudregister.registerutils.exec_subprocess')
    def test_has_nvidia_support_exception(self, mock_subprocess):
        mock_subprocess.side_effect = TypeError('foo')
        assert utils.has_nvidia_support() is False
        assert 'lspci command not found, instance Nvidia support cannot be determined' in \
            self._caplog.text

    @patch('cloudregister.registerutils.exec_subprocess')
    def test_has_nvidia_no_support(self, mock_subprocess):
        mock_subprocess.return_value = b'foo', 'bar', 0
        assert utils.has_nvidia_support() is False

    @patch('cloudregister.registerutils.has_services')
    @patch('cloudregister.registerutils._has_credentials')
    def test_is_registered(self, mock_has_credentials, mock_has_services):
        mock_has_credentials.return_value = True
        mock_has_services.return_value = True
        assert utils.is_registered('some_smt_server') is True

    @patch('cloudregister.registerutils._get_service_plugins')
    def test_has_services_service_no_service(self, mock_get_service_plugins):
        mock_get_service_plugins.return_value = None
        assert utils.has_services('foo') is False

    @patch('cloudregister.registerutils._get_service_plugins')
    def test_has_services_service_plugin(self, mock_get_service_plugins):
        mock_get_service_plugins.return_value = 'foo'
        assert utils.has_services('foo') is True

    @patch('cloudregister.registerutils.glob.glob')
    def test_has_services_service(self, mock_get_service_plugins):
        mock_get_service_plugins.return_value = ['foo']
        content = 'url=plugin:susecloud'
        with patch('builtins.open', mock_open(read_data=content)):
            assert utils.has_services('foo') is True

    @patch('cloudregister.registerutils.requests.post')
    @patch('cloudregister.registerutils.HTTPBasicAuth')
    def test_has_smt_access_unauthorized(self, mock_http_basic_auth, mock_post):
        response = Response()
        response.reason = 'Unauthorized'
        mock_post.return_value = response
        assert utils.has_smt_access('foo', 'bar', 'foobar') is False

    @patch('cloudregister.registerutils.requests.post')
    @patch('cloudregister.registerutils.HTTPBasicAuth')
    def test_has_smt_access_authorized(self, mock_http_basic_auth, mock_post):
        response = Response()
        response.reason = 'Super_Authorized'
        mock_post.return_value = response
        assert utils.has_smt_access('foo', 'bar', 'foobar') is True

    def test_https_only(self):
        cfg = get_test_config()
        cfg.add_section('instance')
        cfg.set('instance', 'httpsOnly', 'true')
        assert utils.https_only(cfg) is True

    def test_https_only_no(self):
        cfg = get_test_config()
        assert utils.https_only(cfg) is False

    @patch.object(SMT, 'write_cert')
    def test_import_smtcert_12_no_write_cert(self, mock_smt_write_cert):
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
        self,
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
        self,
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

    @patch('cloudregister.registerutils.import_smtcert_12')
    def test_import_smt_cert_fail(self, mock_import_smtcert_12):
        mock_import_smtcert_12.return_value = False
        assert utils.import_smt_cert('foo') is None
        assert 'SMT certificate import failed' in self._caplog.text

    @patch('cloudregister.registerutils.glob.glob')
    @patch('cloudregister.registerutils.site')
    @patch('cloudregister.registerutils.import_smtcert_12')
    def test_import_smt_cert_cert_middling(
        self,
        mock_import_smtcert_12,
        mockin_site,
        mockin_glob
    ):
        mock_import_smtcert_12.return_value = True
        mockin_site.getsitepackages.return_value = ['foo']
        mockin_glob.return_value = ['foo/certifi/foo.pem']
        assert utils.import_smt_cert('foo') == 1
        assert 'SMT certificate imported, but "foo/certifi/foo.pem" exist' in self._caplog.text

    @patch('cloudregister.registerutils.get_state_dir')
    def test_is_new_registration_not_new(self, mock_state_dir):
        mock_state_dir.return_value = data_path
        assert utils.is_new_registration() is False

    def test_is_registration_supported_exception(self):
        cfg_template = get_test_config()
        del cfg_template['server']
        assert utils.is_registration_supported(cfg_template) is False

    @patch('cloudregister.registerutils.get_state_dir')
    def test_registration_completed(self, mock_state_dir):
        mock_state_dir.return_value = data_path
        assert utils.is_registration_completed() is False

    def test_is_registration_supported(self):
        cfg_template = get_test_config()
        assert utils.is_registration_supported(cfg_template) is True

    @patch('cloudregister.registerutils.glob.glob')
    def test_is_scc_connected(self, mock_glob):
        mock_glob.return_value = ['../data/scc_repo.repo']
        assert utils.is_scc_connected() is True

    @patch('cloudregister.registerutils.glob.glob')
    def test_is_scc_not_connected(self, mock_glob):
        mock_glob.return_value = []
        assert utils.is_scc_connected() is False

    @patch('cloudregister.registerutils.get_zypper_pid')
    def test_is_zypper_running_not(self, mock_get_zypper_pid):
        mock_get_zypper_pid.return_value = ''
        assert utils.is_zypper_running() is False

    @patch('cloudregister.registerutils.get_zypper_pid')
    def test_is_zypper_running(self, mock_get_zypper_pid):
        mock_get_zypper_pid.return_value = 42
        assert utils.is_zypper_running()

    @patch('cloudregister.registerutils.get_state_dir')
    def test_refresh_zypper_pid_cache(self, mock_get_state_dir):
        with tempfile.TemporaryDirectory() as tmpdirname:
            mock_get_state_dir.return_value = tmpdirname
            utils.refresh_zypper_pid_cache()

    @patch('cloudregister.registerutils.get_state_dir')
    def test_set_as_current_smt(self, mock_get_state_dir):
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
    def test_set_proxy_proxy_set_on_os_env(self):
        assert utils.set_proxy() is False
        assert 'Using proxy settings from execution environment' in self._caplog.text

    @patch('cloudregister.registerutils.os.path.exists')
    def test_set_proxy_proxy_set_on_directory(self, mock_os_path_exists):
        mock_os_path_exists.return_value = False
        assert utils.set_proxy() is False

    @patch('cloudregister.registerutils.os.path.exists')
    def test_set_proxy(self, mock_os_path_exists):
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
    def test_proxy_not_enable(self, mock_os_path_exists):
        mock_os_path_exists.return_value = True
        proxy_content = """
        PROXY_ENABLED="no"
        """
        with patch('builtins.open', mock_open(read_data=proxy_content)):
            assert utils.set_proxy() is False

    @patch('cloudregister.registerutils._set_state_file')
    def test_new_registration_flag(self, mock_set_flag):
        utils.set_new_registration_flag()
        mock_set_flag.assert_called_once_with(
            '/var/cache/cloudregister/newregistration'
        )

    @patch('cloudregister.registerutils._set_state_file')
    def test_rmt_as_scc_proxy_flag(self, mock_set_flag):
        utils.set_rmt_as_scc_proxy_flag()
        mock_set_flag.assert_called_once_with(
            '/var/cache/cloudregister/rmt_is_scc_proxy'
        )

    @patch('cloudregister.registerutils._set_state_file')
    def test_registration_completed_flag(self, mock_set_flag):
        utils.set_registration_completed_flag()
        mock_set_flag.assert_called_once_with(
            '/var/cache/cloudregister/registrationcompleted'
        )

    @patch('cloudregister.registerutils.Path')
    def test_set_flag(self, mock_path):
        utils._set_state_file('foo')
        mock_path.assert_called_once_with('foo')

    @patch('cloudregister.registerutils.get_available_smt_servers')
    def test_switch_services_to_plugin_no_servers(self, mock_get_available_smt_servers):
        mock_get_available_smt_servers.return_value = []
        assert utils.switch_services_to_plugin() is None

    @patch('cloudregister.registerutils.configparser.RawConfigParser.read')
    @patch('cloudregister.registerutils.glob.glob')
    @patch('cloudregister.registerutils.get_available_smt_servers')
    def test_switch_services_to_plugin_config_parse_error(
        self,
        mock_get_available_smt_servers,
        mock_glob,
        mock_raw_config_parser_read
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
        assert 'Unable to parse "foo" skipping' in self._caplog.text

    @patch('cloudregister.registerutils.os.path.exists')
    @patch('cloudregister.registerutils.os.unlink')
    @patch('cloudregister.registerutils.os.symlink')
    @patch('cloudregister.registerutils.glob.glob')
    @patch('cloudregister.registerutils.get_available_smt_servers')
    def test_switch_services_to_plugin_unlink_service(
        self,
        mock_get_available_smt_servers,
        mock_glob,
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
        mock_glob.return_value = ['../data/service.service']
        mock_os_path_exists.return_value = True
        utils.switch_services_to_plugin()
        mock_os_symlink.assert_called_once_with(
            '/usr/sbin/cloudguest-repo-service',
            '/usr/lib/zypp/plugins/services/Public_Cloud_Module_x86_64'
        )
        assert mock_os_unlink.call_args_list == [
            call('/usr/lib/zypp/plugins/services/Public_Cloud_Module_x86_64'),
            call('../data/service.service')
        ]

    @patch('cloudregister.registerutils.fetch_smt_data')
    @patch('cloudregister.registerutils.get_config')
    def test_get_domain_name_from_region_server(
        self, mock_get_config, mock_fetch_smt_data
    ):
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
        assert utils.get_domain_name_from_region_server() == 'susecloud.net'

    @patch('cloudregister.registerutils.get_domain_name_from_region_server')
    @patch('cloudregister.registerutils.get_credentials')
    @patch('cloudregister.registerutils._get_registered_smt_file_path')
    def test_remove_registration_data_no_user(
        self,
        mock_get_registered_smt_file_path,
        mock_get_creds,
        mock_get_domain_name_from_region_server
    ):
        mock_get_creds.return_value = None, None
        mock_get_domain_name_from_region_server.return_value = 'foo'
        assert utils.remove_registration_data() is None
        assert 'No credentials, nothing to do server side' in self._caplog.text

    @patch('cloudregister.registerutils._remove_credentials')
    @patch('cloudregister.registerutils.get_domain_name_from_region_server')
    @patch('cloudregister.registerutils.os.path.exists')
    @patch('cloudregister.registerutils.is_scc_connected')
    @patch('cloudregister.registerutils.get_credentials')
    @patch('cloudregister.registerutils._get_registered_smt_file_path')
    def test_remove_registration_data_no_registration(
        self,
        mock_get_registered_smt_file_path,
        mock_get_creds,
        mock_is_scc_connected,
        mock_os_path_exists,
        mock_get_domain_name_from_region_server,
        mock_remove_credentials
    ):
        mock_get_creds.return_value = 'foo', 'bar'
        mock_is_scc_connected.return_value = False
        mock_os_path_exists.return_value = False
        mock_get_domain_name_from_region_server.return_value = 'foo'
        assert utils.remove_registration_data() is None
        assert 'No current registration server set.' in self._caplog.text
        mock_remove_credentials.assert_called_once_with([])

    @patch('cloudregister.registerutils._remove_credentials')
    @patch('cloudregister.registerutils.is_scc_connected')
    @patch('cloudregister.registerutils.os.unlink')
    @patch('cloudregister.registerutils._remove_repo_artifacts')
    @patch('cloudregister.registerutils.clean_hosts_file')
    @patch('cloudregister.registerutils.requests.delete')
    @patch('cloudregister.registerutils.get_smt_from_store')
    @patch('cloudregister.registerutils.os.path.exists')
    @patch('cloudregister.registerutils.HTTPBasicAuth')
    @patch('cloudregister.registerutils.get_credentials')
    @patch('cloudregister.registerutils._get_registered_smt_file_path')
    def test_remove_registration_data(
        self,
        mock_get_registered_smt_file_path,
        mock_get_creds,
        mock_http_basic_auth,
        mock_os_path_exists,
        mock_get_smt_from_store,
        mock_request_delete,
        mock_clean_hosts_file,
        mock_remove_repo_artifacts,
        mock_os_unlink,
        mock_is_scc_connected,
        mock_remove_credentials
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
        assert "Clean current registration server: ('192.168.1.1', 'fc00::1')" in self._caplog.text
        assert 'System successfully removed from update infrastructure' in self._caplog.text
        assert 'System successfully removed from SCC' in self._caplog.text
        assert 'Removing repository artifacts' in self._caplog.text

    @patch('cloudregister.registerutils._remove_credentials')
    @patch('cloudregister.registerutils.is_scc_connected')
    @patch('cloudregister.registerutils.os.unlink')
    @patch('cloudregister.registerutils._remove_repo_artifacts')
    @patch('cloudregister.registerutils.clean_hosts_file')
    @patch('cloudregister.registerutils.requests.delete')
    @patch('cloudregister.registerutils.get_smt_from_store')
    @patch('cloudregister.registerutils.os.path.exists')
    @patch('cloudregister.registerutils.HTTPBasicAuth')
    @patch('cloudregister.registerutils.get_credentials')
    @patch('cloudregister.registerutils._get_registered_smt_file_path')
    def test_remove_registration_data_request_not_OK(
        self,
        mock_get_registered_smt_file_path,
        mock_get_creds,
        mock_http_basic_auth,
        mock_os_path_exists,
        mock_get_smt_from_store,
        mock_request_delete,
        mock_clean_hosts_file,
        mock_remove_repo_artifacts,
        mock_os_unlink,
        mock_is_scc_connected,
        mock_remove_credentials
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
        assert 'System unknown to update infrastructure' in self._caplog.text
        assert 'System not found in SCC. The system may still be tracked' in self._caplog.text
        assert 'Removing repository artifacts' in self._caplog.text

    @patch('cloudregister.registerutils._remove_credentials')
    @patch('cloudregister.registerutils.is_scc_connected')
    @patch('cloudregister.registerutils.os.unlink')
    @patch('cloudregister.registerutils._remove_repo_artifacts')
    @patch('cloudregister.registerutils.clean_hosts_file')
    @patch('cloudregister.registerutils.requests.delete')
    @patch('cloudregister.registerutils.get_smt_from_store')
    @patch('cloudregister.registerutils.os.path.exists')
    @patch('cloudregister.registerutils.HTTPBasicAuth')
    @patch('cloudregister.registerutils.get_credentials')
    @patch('cloudregister.registerutils._get_registered_smt_file_path')
    def test_remove_registration_data_request_exception(
        self,
        mock_get_registered_smt_file_path,
        mock_get_creds,
        mock_http_basic_auth,
        mock_os_path_exists,
        mock_get_smt_from_store,
        mock_request_delete,
        mock_clean_hosts_file,
        mock_remove_repo_artifacts,
        mock_os_unlink,
        mock_is_scc_connected,
        mock_remove_credentials
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
        assert 'Unable to remove client registration from SCC. ' in self._caplog.text

    @patch('cloudregister.registerutils.add_hosts_entry')
    @patch('cloudregister.registerutils.clean_hosts_file')
    def test_replace_hosts_entry(self, mock_clean_hosts_file, mock_add_hosts_entry):
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

    @patch('cloudregister.registerutils.pickle.dump')
    @patch('cloudregister.registerutils.pickle')
    @patch('cloudregister.registerutils.os.fchmod')
    def test_store_smt_data(self, mock_os_fchmod, mock_pickle, mock_dump):
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
        mock_os_fchmod.assert_called
        mock_pickle.Pickler.assert_called_once()

    @patch('cloudregister.registerutils.glob.glob')
    @patch('cloudregister.registerutils.get_current_smt')
    def test_switch_smt_repos(self, mock_get_current_smt, mock_glob):
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
        mock_glob.return_value = ['../data/repo_foo.repo']
        file_azo = ""
        with open('../data/repo_foo.repo') as f:
            file_azo = ' '.join(f.readlines())
        open_mock = mock_open(read_data=file_azo)

        def open_f(self, filename, *args, **kwargs):
            return open_mock()

        with patch('builtins.open', create=True) as m_open:
            m_open.side_effect = open_f
            utils.switch_smt_repos(new_smt_server)
            assert m_open.call_args_list == [
                call('../data/repo_foo.repo', 'r'),
                call('../data/repo_foo.repo', 'w')
            ]
            expected_content = file_azo.replace(
               'plugin:/susecloud',
               new_smt_server.get_FQDN()
            )
            m_open(
                '../data/repo_foo.repo', 'w'
            ).write.assert_called_once_with(expected_content)

    @patch('cloudregister.registerutils.glob.glob')
    @patch('cloudregister.registerutils.get_current_smt')
    def test_switch_smt_service(self, mock_get_current_smt, mock_glob):
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
        mock_glob.return_value = ['../data/service.service']
        file_azo = ""
        with open('../data/repo_foo.repo') as f:
            file_azo = ' '.join(f.readlines())
        open_mock = mock_open(read_data=file_azo)

        def open_f(self, filename, *args, **kwargs):
            return open_mock()

        with patch('builtins.open', create=True) as m_open:
            m_open.side_effect = open_f
            utils.switch_smt_service(new_smt_server)
            assert m_open.call_args_list == [
                call('../data/service.service', 'r'),
                call('../data/service.service', 'w')
            ]
            expected_content = file_azo.replace(
                'plugin:/susecloud',
                new_smt_server.get_FQDN()
            )
            m_open(
                '../data/repo_foo.repo', 'w'
            ).write.assert_called_once_with(expected_content)

    @patch('cloudregister.registerutils.time.sleep')
    @patch('cloudregister.registerutils.exec_subprocess')
    def test_update_ca_chain(self, mock_exec_subprocess, mock_time_sleep):
        mock_exec_subprocess.return_value = 314
        utils.update_ca_chain(['cmd']) == 1
        assert 'Certificate update failed attempt 1' in self._caplog.text
        assert 'Certificate update failed attempt 2' in self._caplog.text
        assert 'Certificate update failed attempt 3' in self._caplog.text
        assert mock_time_sleep.call_args_list == [
            call(5),
            call(5),
            call(5)
        ]

    @patch('cloudregister.registerutils.exec_subprocess')
    def test_update_ca_chain_failed(self, mock_exec_subprocess):
        mock_exec_subprocess.return_value = 0
        utils.update_ca_chain(['cmd']) == 1

    @patch('cloudregister.registerutils.is_new_registration')
    def test_update_rmt_cert_new_registration(self, mock_is_new_registration):
        mock_is_new_registration.return_value = True
        assert utils.update_rmt_cert('foo') is None

    @patch('cloudregister.registerutils.get_config')
    @patch('cloudregister.registerutils.import_smt_cert')
    @patch('cloudregister.registerutils.fetch_smt_data')
    @patch('cloudregister.registerutils.set_proxy')
    @patch('cloudregister.registerutils.is_new_registration')
    def test_update_rmt_cert_no_cert_change(
        self,
        mock_is_new_registration,
        mock_set_proxy,
        mock_fetch_smt_data,
        mock_import_smt_cert,
        mock_config
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
        assert 'Check for cert update' in self._caplog.text
        assert 'No cert change' in self._caplog.text

    @patch('cloudregister.registerutils.get_config')
    @patch('cloudregister.registerutils.import_smt_cert')
    @patch('cloudregister.registerutils.fetch_smt_data')
    @patch('cloudregister.registerutils.set_proxy')
    @patch('cloudregister.registerutils.is_new_registration')
    def test_update_rmt_cert(
        self,
        mock_is_new_registration,
        mock_set_proxy,
        mock_fetch_smt_data,
        mock_import_smt_cert,
        mock_config
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
        assert 'Update server cert updated' in self._caplog.text

    def test_uses_rmt_as_scc_proxy(self):
        assert utils.uses_rmt_as_scc_proxy() is False

    @patch('cloudregister.registerutils.json.dumps')
    @patch('cloudregister.registerutils.get_framework_identifier_path')
    @patch('cloudregister.registerutils._get_region_server_args')
    @patch('cloudregister.registerutils._get_framework_plugin')
    @patch('cloudregister.registerutils._get_system_mfg')
    def test_write_framework_identifier(
        self,
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
    @patch('cloudregister.registerutils._get_region_server_args')
    @patch('cloudregister.registerutils._get_framework_plugin')
    @patch('cloudregister.registerutils._get_system_mfg')
    def test_write_framework_identifier_no_region(
        self,
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
    @patch('cloudregister.registerutils._get_region_server_args')
    @patch('cloudregister.registerutils._get_framework_plugin')
    @patch('cloudregister.registerutils._get_system_mfg')
    def test_write_framework_identifier_non_existing_path(
        self,
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

    def test_get_framework_plugin_no_existing(self):
        cfg = get_test_config()
        cfg.add_section('instance')
        cfg.set('instance', 'instanceArgs', 'foo')
        assert utils._get_framework_plugin(cfg) is None
        assert 'Configured instanceArgs module could not be loaded. ' in self._caplog.text
        assert 'Continuing without additional arguments.' in self._caplog.text

    def test_get_framework_plugin(self):
        cfg = get_test_config()
        cfg.add_section('instance')
        cfg.set('instance', 'instanceArgs', 'amazonec2')
        expected_mod = __import__('cloudregister.amazonec2', fromlist=[''])
        assert utils._get_framework_plugin(cfg) == expected_mod
        cfg.set('instance', 'instanceArgs', 'none')

    @patch('cloudregister.registerutils.glob.glob')
    def test_get_referenced_credentials(self, mock_glob):
        mock_glob.return_value = ['../data/repo_foo.repo']
        assert utils._get_referenced_credentials('foo') == [
            'SUSE_Linux_Enterprise_Live_Foo_x86_64'
        ]

    @patch('cloudregister.registerutils.get_config')
    @patch('cloudregister.registerutils.glob.glob')
    def test_get_referenced_credentials_not_found(self, mock_glob, mock_get_config):
        mock_glob.return_value = ['../data/repo_foo.repo']
        cfg = get_test_config()
        cfg.set('server', 'baseurl', 'bar')
        mock_get_config.return_value = cfg
        assert utils._get_referenced_credentials('foo') == []

    def test_get_region_server_args_exception(self):
        mod = __import__('cloudregister.smt', fromlist=[''])
        assert utils._get_region_server_args(mod) == ''
        assert 'Configured and loaded module '
        '"/home/ms/Project/cloud-regionsrv-client/cloudregister/smt.py" '
        'does not provide the required generateRegionSrvArgs function' in \
            self._caplog.text

    @patch('cloudregister.registerutils.time.sleep')
    @patch('cloudregister.amazonec2.generateRegionSrvArgs')
    def test_get_region_server_args_not_region_srv_args(
        self,
        mock_amazon_generate_region_args,
        mock_time_sleep
    ):
        mock_amazon_generate_region_args.return_value = None
        mod = __import__('cloudregister.amazonec2', fromlist=[''])
        assert utils._get_region_server_args(mod) is None
        assert mock_time_sleep.call_args_list == [
            call(1),
            call(1),
            call(1),
            call(1),
            call(1)
        ]

    @patch('cloudregister.registerutils.os.path.basename')
    @patch('cloudregister.registerutils.glob.glob')
    def test_get_service_plugins(self, mock_glob, mock_os_path_basename):
        mock_glob.return_value = ['../data/service.service']
        mock_os_path_basename.return_value = 'cloudguest-repo-service'
        assert utils._get_service_plugins() == ['../data/service.service']

    @patch('cloudregister.registerutils.exec_subprocess')
    def test_get_system_mfg(self, mock_exec_subprocess):
        mock_exec_subprocess.side_effect = TypeError('foo')
        assert utils._get_system_mfg() == 'unknown'

    @patch('cloudregister.registerutils._get_referenced_credentials')
    @patch('cloudregister.registerutils.glob.glob')
    def test_has_credentials_in_system(self, mock_glob, mock_get_referenced_creds):
        mock_glob.return_value = ['/etc/zypp/credentials.d/SCCcredentials']
        assert utils._has_credentials('foo') is True

    @patch('cloudregister.registerutils._get_referenced_credentials')
    @patch('cloudregister.registerutils.glob.glob')
    def test_has_credentials_in_service(self, mock_glob, mock_get_referenced_creds):
        mock_glob.return_value = ['/etc/zypp/credentials.d/service']
        mock_get_referenced_creds.return_value = ['service']
        assert utils._has_credentials('foo') is True

    @patch('cloudregister.registerutils._get_referenced_credentials')
    @patch('cloudregister.registerutils.glob.glob')
    def test_has_credentials_not_found(self, mock_glob, mock_get_referenced_creds):
        mock_glob.return_value = []
        assert utils._has_credentials('foo') is False

    @patch('cloudregister.registerutils.store_smt_data')
    @patch('cloudregister.registerutils.fetch_smt_data')
    @patch('cloudregister.registerutils.get_config')
    @patch('cloudregister.registerutils.set_proxy')
    def test_populate_srv_cache(
        self,
        mock_set_proxy,
        mock_get_config,
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
        utils._populate_srv_cache()
        assert 'Populating server cache' in self._caplog.text
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
    @patch('cloudregister.registerutils._get_referenced_credentials')
    @patch('cloudregister.registerutils.glob.glob')
    def test_remove_credentials(
        self,
        mock_glob,
        mock_get_referenced_creds,
        mock_os_unlink
    ):
        mock_glob.return_value = ['/etc/zypp/credentials.d/SCCcredentials']
        mock_get_referenced_creds.return_value = ['SCCcredentials']
        assert utils._remove_credentials('foo') == 1
        assert 'Deleting locally stored credentials' in self._caplog.text
        assert 'Removing credentials: /etc/zypp/credentials.d/SCCcredentials' in self._caplog.text
        mock_os_unlink.assert_called_once_with(
            '/etc/zypp/credentials.d/SCCcredentials'
        )

    @patch('cloudregister.registerutils.os.unlink')
    @patch('cloudregister.registerutils.os.path.exists')
    @patch('cloudregister.registerutils._remove_service')
    @patch('cloudregister.registerutils._remove_repos')
    def test_remove_artifacts(
        self,
        mock_remove_repos,
        mock_remove_service,
        mock_os_path_exists,
        mock_os_unlink
    ):
        mock_os_path_exists.return_value = True
        assert utils._remove_repo_artifacts(['foo']) is None
        mock_remove_repos.assert_called_once_with(['foo'])
        mock_remove_service.assert_called_once_with(['foo'])
        mock_os_path_exists.assert_called_once_with('/etc/SUSEConnect')

    @patch('cloudregister.registerutils.glob.glob')
    @patch('cloudregister.registerutils._get_referenced_credentials')
    @patch('cloudregister.registerutils.os.unlink')
    def test_remove_credentials_no_remove_etc_scccreds(
        self,
        mock_os_unlink,
        mock_get_referenced_creds,
        mock_glob
    ):
        mock_glob.return_value = ['foo']
        mock_get_referenced_creds.return_value = []
        assert utils._remove_credentials('') == 1
        mock_os_unlink.assert_not_called

    @patch('cloudregister.registerutils.glob.glob')
    @patch('cloudregister.registerutils.os.unlink')
    def test_remove_repos(self, mock_os_unlink, mock_glob):
        mock_glob.return_value = ['../data/repo_foo.repo']
        assert utils._remove_repos(['foo']) == 1
        mock_os_unlink.assert_called_once_with('../data/repo_foo.repo')
        assert 'Removing repo: repo_foo.repo' in self._caplog.text

    @patch('cloudregister.registerutils.glob.glob')
    @patch('cloudregister.registerutils.os.unlink')
    def test_remove_repos_removed_nothing(self, mock_os_unlink, mock_glob):
        mock_glob.return_value = ['../data/scc_repo.repo']
        assert utils._remove_repos(['foo']) == 1
        mock_os_unlink.assert_not_called()

    @patch('cloudregister.registerutils._get_service_plugins')
    @patch('cloudregister.registerutils.glob.glob')
    @patch('cloudregister.registerutils.os.unlink')
    def test_remove_service_not_plugins(
        self,
        mock_os_unlink,
        mock_glob,
        mock_get_service_plugin
    ):
        mock_glob.return_value = ['../data/service.service']
        mock_get_service_plugin.return_value = []
        assert utils._remove_service(['192']) == 1
        mock_os_unlink.assert_called_once_with('../data/service.service')
        assert 'Removing service: service.service' in self._caplog.text

    @patch('cloudregister.registerutils._get_service_plugins')
    @patch('cloudregister.registerutils.glob.glob')
    @patch('cloudregister.registerutils.os.unlink')
    def test_remove_service(
        self,
        mock_os_unlink,
        mock_glob,
        mock_get_service_plugins
    ):
        mock_glob.return_value = []
        mock_get_service_plugins.return_value = ['foo']
        assert utils._remove_service('192') == 1
        mock_os_unlink.assert_called_once_with('foo')

    @patch('cloudregister.registerutils._get_region_server_ips')
    @patch('cloudregister.registerutils.has_network_access_by_ip_address')
    def test_has_ipv4_access(
        self,
        mock_has_network_access,
        mock_get_region_server_ips,
    ):
        mock_has_network_access.return_value = True
        mock_get_region_server_ips.return_value = \
            ['1.1.1.1'], ['fc11::2'], ['foo']

        assert utils.has_ipv4_access()
        mock_has_network_access.assert_called_once_with('1.1.1.1')

    @patch('cloudregister.registerutils._get_region_server_ips')
    @patch('cloudregister.registerutils.has_network_access_by_ip_address')
    def test_has_ipv6_access(
        self,
        mock_has_network_access,
        mock_get_region_server_ips
    ):
        mock_has_network_access.return_value = True
        mock_get_region_server_ips.return_value = \
            ['1.1.1.1'], ['fc11::2'], ['foo']

        assert utils.has_ipv6_access()
        mock_has_network_access.assert_called_once_with('fc11::2')

    @patch('cloudregister.registerutils._get_region_server_ips')
    def test_has_no_ipv4_ipv6_servers(self, mock_get_region_server_ips):
        mock_get_region_server_ips.return_value = [], [], []
        assert utils.has_ipv4_access() is False
        assert utils.has_ipv6_access() is False

    @patch('cloudregister.registerutils.has_network_access_by_ip_address')
    @patch('cloudregister.registerutils._get_region_server_ips')
    def test_has_no_ipv4_ipv6_access(
        self,
        mock_get_region_server_ips,
        mock_has_network_access_by_ip_address
    ):
        mock_get_region_server_ips.return_value = ['foo'], ['bar'], []
        mock_has_network_access_by_ip_address.return_value = False
        assert utils.has_ipv4_access() is False
        assert utils.has_ipv6_access() is False

    @patch('cloudregister.registerutils.add_region_server_args_to_URL')
    @patch('cloudregister.registerutils.get_config')
    def test_get_region_server_ips(
        self,
        mock_get_config,
        mock_add_region_server_args_to_URL
    ):
        cfg = configparser.RawConfigParser()
        cfg.read(data_path + '/regionserverclnt.cfg')
        cfg.set('server', 'api', 'bar')
        cfg.set('server', 'regionsrv', '1.1.1.1,2.2.2.2,fc11::2,foo')
        mock_get_config.return_value = cfg
        assert utils._get_region_server_ips() == \
            (
                ['1.1.1.1', '2.2.2.2'],
                ['fc11::2'],
                ['foo']
            )

    @patch('cloudregister.registerutils.socket.create_connection')
    def test_has_network_access_by_ip_address(self, mock_socket_create_connection):
        assert utils.has_network_access_by_ip_address('1.1.1.1')

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.socket.create_connection')
    def test_has_network_access_by_ip_address_no_connection(
        self, mock_socket_create_connection
    ):
        mock_socket_create_connection.side_effect = OSError
        with self._caplog.at_level(logging.INFO):
            has_access = utils.has_network_access_by_ip_address('FFF::0')
            assert not has_access
            assert 'Skipping IPv6 protocol version, no network configuration' in \
                self._caplog.text

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.set_registry_fqdn_suma')
    @patch('cloudregister.registerutils.set_registries_conf_docker')
    @patch('cloudregister.registerutils.set_registries_conf_podman')
    @patch('cloudregister.registerutils.is_suma_instance')
    @patch('cloudregister.registerutils.set_container_engines_env_vars')
    @patch('cloudregister.registerutils.os.path.exists')
    @patch('cloudregister.registerutils.os.makedirs')
    @patch('cloudregister.registerutils.json.dump')
    @patch('cloudregister.registerutils.json.load')
    def test_setup_registry_empty_file(
        self,
        mock_json_load, mock_json_dump, mock_os_makedirs,
        mock_os_path_exists, mock_set_container_engines_env_vars,
        mock_is_suma_instance, mock_set_registries_conf_podman,
        mock_set_registries_conf_docker, mock_set_registry_fqdn_suma
    ):
        mock_os_path_exists.return_value = [False, True]
        mock_json_load.return_value = {}
        with patch('builtins.open', create=True) as mock_open:
            file_handle = mock_open.return_value.__enter__.return_value
            utils.prepare_registry_setup(
                'registry-supercloud.susecloud.net', 'login', 'pass'
            )
            utils.set_registries_conf_podman('registry-supercloud.susecloud.net')
            utils.set_registries_conf_docker('registry-supercloud.susecloud.net')
            utils.set_registry_fqdn_suma('registry-supercloud.susecloud.net')
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
    @patch('cloudregister.registerutils.set_registry_fqdn_suma')
    @patch('cloudregister.registerutils.set_registries_conf_docker')
    @patch('cloudregister.registerutils.set_registries_conf_podman')
    @patch('cloudregister.registerutils.is_suma_instance')
    @patch('cloudregister.registerutils.set_container_engines_env_vars')
    @patch('cloudregister.registerutils.os.path.exists')
    @patch('cloudregister.registerutils.os.makedirs')
    @patch('cloudregister.registerutils.json.dump')
    def test_setup_registry_file_not_exists(
        self,
        mock_json_dump, _mock_os_makedirs, mock_os_path_exists,
        mock_set_container_env_vars, mock_is_suma_instance,
        mock_set_registries_conf_podman, mock_set_registries_conf_docker,
        mock_set_registry_fqdn_suma
    ):
        mock_os_path_exists.side_effect = [False, False]
        with patch('builtins.open', create=True) as mock_open:
            file_handle = mock_open.return_value.__enter__.return_value
            utils.prepare_registry_setup(
                'registry-supercloud.susecloud.net', 'login', 'pass'
            )
            utils.set_registries_conf_podman('registry-supercloud.susecloud.net')
            utils.set_registries_conf_docker('registry-supercloud.susecloud.net')
            utils.set_registry_fqdn_suma('registry-supercloud.susecloud.net')
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
    @patch('cloudregister.registerutils.set_registry_fqdn_suma')
    @patch('cloudregister.registerutils.set_registries_conf_docker')
    @patch('cloudregister.registerutils.set_registries_conf_podman')
    @patch('cloudregister.registerutils.is_suma_instance')
    @patch('cloudregister.registerutils.set_container_engines_env_vars')
    @patch('cloudregister.registerutils.os.path.exists')
    @patch('cloudregister.registerutils.os.makedirs')
    @patch('cloudregister.registerutils.json.dump')
    @patch('cloudregister.registerutils.json.load')
    def test_setup_registry_content(
        self,
        mock_json_load, mock_json_dump,
        mock_os_makedirs, mock_os_path_exists,
        mock_set_env_vars, mock_is_suma_instance,
        mock_set_registries_conf_podman, mock_set_registries_conf_docker,
        mock_set_registry_fqdn_suma
    ):
        mock_os_path_exists.return_value = True
        mock_json_load.return_value = {
            'auths': {
                'some-domain.com': {'auth': 'foo'}
            }
        }
        with patch('builtins.open', create=True) as mock_open:
            file_handle = mock_open.return_value.__enter__.return_value
            utils.prepare_registry_setup(
                'registry-supercloud.susecloud.net', 'login', 'pass'
            )
            utils.set_registries_conf_podman('registry-supercloud.susecloud.net')
            utils.set_registries_conf_docker('registry-supercloud.susecloud.net')
            utils.set_registry_fqdn_suma('registry-supercloud.susecloud.net')
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
    @patch('cloudregister.registerutils.json.load')
    @patch('cloudregister.registerutils.toml.load')
    def test_setup_registry_content_json_error_preserve_fail(
        self,
        mock_toml_load, mock_json_load, mock_os_makedirs,
        mock_os_path_exists, mock_exec_subprocess
    ):
        mock_os_path_exists.return_value = [False, True]
        mock_toml_load.side_effect = toml.decoder.TomlDecodeError('msg', 'doc', 0)
        mock_json_load.side_effect = json.decoder.JSONDecodeError('msg', 'doc', 0)
        mock_exec_subprocess.return_value = 1
        with patch('builtins.open', create=True) as mock_open:
            mock_exec_subprocess.return_value = 1
            assert utils.prepare_registry_setup(
                'registry-supercloud.susecloud.net', 'login', 'pass'
            ) is False
            mock_open.assert_called_once_with('/etc/containers/config.json', 'r')
            assert 'Unable to parse existing /etc/containers/config.json' in self._caplog.text
            assert 'File not preserved.' in self._caplog.text
            mock_exec_subprocess.assert_called_once_with(
                ['mv', '-Z',
                 '/etc/containers/config.json',
                 '/etc/containers/config.json.bak']
            )

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.exec_subprocess')
    @patch('cloudregister.registerutils.os.path.exists')
    @patch('cloudregister.registerutils.os.makedirs')
    def test_setup_registry_content_open_file_error(
        self, mock_os_makedirs,
        mock_os_path_exists, mock_exec_subprocess
    ):
        mock_os_path_exists.return_value = True
        with patch('builtins.open', create=True) as mock_open:
            mock_open.side_effect = OSError('oh no ! an error')
            mock_exec_subprocess.return_value = 1
            assert utils.prepare_registry_setup(
                'registry-supercloud.susecloud.net',
                'login',
                'pass'
            ) is False
            mock_open.assert_called_once_with('/etc/containers/config.json', 'r')
            assert 'Unable to open existing /etc/containers/config.json' in self._caplog.text
            assert 'writing new credentials' in self._caplog.text
            assert 'File not preserved' in self._caplog.text
            mock_exec_subprocess.assert_called_once_with(
                ['mv', '-Z',
                 '/etc/containers/config.json',
                 '/etc/containers/config.json.bak']
            )

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.os.path.exists')
    @patch('cloudregister.registerutils.os.makedirs')
    @patch('cloudregister.registerutils.json.dump')
    @patch('cloudregister.registerutils.json.load')
    def test_setup_registry_content_write_error(
        self,
        mock_json_load, mock_json_dump,
        mock_os_makedirs, mock_os_path_exists
    ):
        mock_os_path_exists.side_effect = [False, False]
        mock_os_path_exists.return_value = False
        mock_json_dump.side_effect = Exception('something happened !')
        with patch('builtins.open', create=True) as mock_open:
            utils.prepare_registry_setup(
                'registry-supercloud.susecloud.net',
                'login',
                'pass'
            )
            mock_open.assert_called_once_with(
                '/etc/containers/config.json', 'w'
            )
            assert 'Could not add the registry credentials: something happened !' in \
                self._caplog.text

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.update_bashrc')
    @patch('cloudregister.registerutils.os.path.exists')
    def test_set_container_engines_env_vars_new(
        self, mock_os_path_exists, mock_up_bashrc
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
    @patch('cloudregister.registerutils.os.path.exists')
    def test_set_container_engines_env_vars_no_update(
        self, mock_os_path_exists
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
    @patch('cloudregister.registerutils._mv_file_backup')
    @patch('cloudregister.registerutils.os.path.exists')
    def test_set_container_engines_env_vars_file_error(
        self, mock_os_path_exists, mock_mv
    ):
        mock_os_path_exists.return_value = True
        with patch('builtins.open', create=True) as mock_open:
            mock_open.side_effect = OSError('an error !')
            assert utils.set_container_engines_env_vars() is False
            assert 'Could not open /etc/profile.local' in self._caplog.text

    # ---------------------------------------------------------------------------
    def test_update_bashrc_open_file_OK(self):
        with patch('builtins.open', create=True) as mock_open:
            assert utils.update_bashrc({'foo': 'bar'}, 'w')
            mock_open.assert_called_once_with('/etc/profile.local', 'w')
            assert '/etc/profile.local updated' in self._caplog.text

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.clean_bashrc_local')
    @patch('cloudregister.registerutils.os.path.exists')
    def test_unset_env_vars_no_env_vars_in_file(
        self, mock_os_path_exists, mock_clean_bashrc_local
    ):
        mock_os_path_exists.return_value = True
        mock_clean_bashrc_local.return_value = [], False, False, False
        assert utils.unset_env_vars() is True
        assert 'Environment variables not present in /etc/profile.local' in self._caplog.text

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.clean_bashrc_local')
    @patch('cloudregister.registerutils.os.path.exists')
    def test_unset_env_vars_no_file_access_no_backup(
        self, mock_os_path_exists, mock_clean_bashrc_local
    ):
        mock_os_path_exists.return_value = True
        mock_clean_bashrc_local.return_value = [], False, True, True
        assert utils.unset_env_vars() is False

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.update_bashrc')
    @patch('cloudregister.registerutils.clean_bashrc_local')
    @patch('cloudregister.registerutils.os.path.exists')
    def test_unset_env_vars_modified_content(
        self, mock_os_path_exists, mock_clean_bashrc_local, mock_update_bashrc
    ):
        mock_os_path_exists.return_value = True
        mock_clean_bashrc_local.return_value = ['no-registry'], True, False, False
        mock_update_bashrc.return_value = True
        assert utils.unset_env_vars() is True
        mock_update_bashrc.assert_called_once_with('no-registry', 'w')

    # ---------------------------------------------------------------------------
    def test_clean_bashrc_local(self):
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
    @patch('cloudregister.registerutils._mv_file_backup')
    def test_clean_bashrc_local_open_error(self, mock_mv_file_backup):
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
            assert 'Could not open /etc/profile.local: oh no !' in self._caplog.text

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.os.unlink')
    @patch('cloudregister.registerutils.os.path.exists')
    def test_clean_registry_content_no_file(self, mock_os_path_exists, mock_os_unlink):
        mock_os_path_exists.return_value = False
        assert utils.clean_registry_setup() is None

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.get_smt_from_store')
    @patch('cloudregister.registerutils._get_registered_smt_file_path')
    @patch('cloudregister.registerutils.clean_registries_conf')
    @patch('cloudregister.registerutils.clean_registry_auth')
    @patch('cloudregister.registerutils.os.path.exists')
    def test_clean_registry_content_file_exists(
        self,
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
    @patch('cloudregister.registerutils.json.load')
    def test_clean_registry_auth_empty_file(
        self,
        mock_json_load, mock_os_path_exists, mock_os_unlink
    ):
        mock_json_load.return_value = {}
        mock_os_path_exists.return_value = True
        with patch('builtins.open', create=True) as mock_open:
            assert utils.clean_registry_auth('registry-foo.susecloud.net')
            mock_open.assert_called_once_with(
                '/etc/containers/config.json', 'r'
            )
            assert 'JSON content is empty' in self._caplog.text

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils._generate_registry_auth_token')
    @patch('cloudregister.registerutils.os.path.exists')
    @patch('cloudregister.registerutils.json.load')
    def test_clean_registry_auth_no_registry_entry_in_file(
        self,
        mock_json_load, mock_os_path_exists,
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
            assert 'Unsetting the auth entry for registry-foo.susecloud.net' in self._caplog.text

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.set_registry_fqdn_suma')
    @patch('cloudregister.registerutils.set_registries_conf_docker')
    @patch('cloudregister.registerutils.set_registries_conf_podman')
    @patch('cloudregister.registerutils.is_suma_instance')
    @patch('cloudregister.registerutils.exec_subprocess')
    @patch('cloudregister.registerutils._generate_registry_auth_token')
    @patch('cloudregister.registerutils.os.path.exists')
    @patch('cloudregister.registerutils.json.load')
    def test_clean_registry_auth_no_registry_entry_in_file_wrong_dict_content(
        self,
        mock_json_load, mock_os_path_exists,
        mock_generate_registry_auth_token, mock_exec_subprocess,
        mock_is_suma_instance, mock_set_registries_conf_podman,
        mock_set_registries_conf_docker, mock_set_registry_fqdn_suma
    ):
        mock_generate_registry_auth_token.return_value = 'auth_token'
        mock_json_load.return_value = {'auths': 'bar'}
        mock_exec_subprocess.return_value = 0
        with patch('builtins.open', create=True) as mock_open:
            assert utils.clean_registry_auth('registry-foo.susecloud.net') is None
            mock_open.assert_called_once_with('/etc/containers/config.json', 'r')
            assert 'Preserving file /etc/containers/config.json' in self._caplog.text
            assert 'File preserved' in self._caplog.text
            assert 'The entry for "auths" key is not a dictionary' in self._caplog.text

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.exec_subprocess')
    @patch('cloudregister.registerutils.get_credentials')
    @patch('cloudregister.registerutils.os.path.exists')
    @patch('cloudregister.registerutils.json.load')
    def test_clean_registry_content_json_error(
        self,
        mock_json_load, mock_os_path_exists,
        mock_get_credentials, mock_exec_subprocess
    ):
        mock_json_load.side_effect = json.decoder.JSONDecodeError('a', 'b', 1)
        mock_get_credentials.return_value = ('SCC_login', 'password')
        mock_exec_subprocess.return_value = 1
        with patch('builtins.open', create=True) as mock_open:
            utils.clean_registry_auth('registry-foo.susecloud.net')
            mock_open.assert_called_once_with('/etc/containers/config.json', 'r')
            assert 'Unable to parse existing /etc/containers/config.json' in self._caplog.text

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils._generate_registry_auth_token')
    @patch('cloudregister.registerutils.os.path.exists')
    @patch('cloudregister.registerutils.json.dump')
    @patch('cloudregister.registerutils.get_smt_from_store')
    @patch('cloudregister.registerutils._get_registered_smt_file_path')
    @patch('cloudregister.registerutils.json.load')
    def test_clean_registry_auth_content_write(
        self,
        mock_json_load, mock_get_registered_smt,
        mock_get_smt_from_store, mock_json_dump,
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
            assert 'Unsetting the auth entry for registry-foo.susecloud.net' in self._caplog.text

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.get_credentials')
    @patch('cloudregister.registerutils.os.path.exists')
    @patch('cloudregister.registerutils.json.dump')
    @patch('cloudregister.registerutils.json.load')
    def test_clean_registry_auth_content_write_no_smt_token_based(
        self,
        mock_json_load, mock_json_dump,
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
            assert 'Credentials for the registry removed' in self._caplog.text

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils._generate_registry_auth_token')
    @patch('cloudregister.registerutils.os.unlink')
    @patch('cloudregister.registerutils.os.path.exists')
    @patch('cloudregister.registerutils.json.dump')
    @patch('cloudregister.registerutils.get_smt_from_store')
    @patch('cloudregister.registerutils._get_registered_smt_file_path')
    @patch('cloudregister.registerutils.json.load')
    def test_clean_registry_auth_content_same_entry_only(
        self,
        mock_json_load, mock_get_registered_smt,
        mock_get_smt_from_store, mock_json_dump,
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
    @patch('cloudregister.registerutils._generate_registry_auth_token')
    @patch('cloudregister.registerutils.os.unlink')
    @patch('cloudregister.registerutils.os.path.exists')
    @patch('cloudregister.registerutils.json.dump')
    @patch('cloudregister.registerutils.json.load')
    def test_clean_registry_auth_content_same_entry_only_token_based(
        self,
        mock_json_load, mock_json_dump,
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
    @patch('cloudregister.registerutils.get_registry_credentials')
    @patch('os.path.exists')
    def test_clean_registry_auth_content_not_relevant_json(
        self,
        mock_os_path_exists, mock_get_registry_credentials,
        mock_os_unlink, mock_same_registry_auth_content
    ):
        mock_os_path_exists.return_value = True
        mock_get_registry_credentials.return_value = {'auths': {}}, None
        mock_same_registry_auth_content.return_value = False
        with self._caplog.at_level(logging.INFO):
            assert utils.clean_registry_auth(registry_fqdn='')
            assert 'JSON content is empty' in self._caplog.text

    # ---------------------------------------------------------------------------
    def test_update_bashrc_open_file_error(self):
        with patch('builtins.open', create=True) as mock_open:
            mock_open.side_effect = OSError('oh no !')
            utils.update_bashrc({'foo': 'bar'}, 'a')
            mock_open.assert_called_once_with('/etc/profile.local', 'a')
            assert 'Could not update /etc/profile.local: oh no !' in self._caplog.text

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.get_registry_conf_file')
    @patch('cloudregister.registerutils.os.path.exists')
    def test_set_registries_conf_podman_OK_content(
        self, mock_os_path_exists, mock_get_reg_conf_file
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
        assert utils.set_registries_conf_podman(
            'registry-ec2.susecloud.net'
        ) is None

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.toml.dump')
    @patch('cloudregister.registerutils.get_registry_conf_file')
    @patch('cloudregister.registerutils.os.path.exists')
    def test_set_registries_conf_podman_content_setup_private_registry(
        self,
        mock_os_path_exists, mock_get_reg_conf_file,
        mock_toml_dump
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
            assert utils.set_registries_conf_podman('registry-ec2.susecloud.net')
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
            assert 'Content for /etc/containers/registries.conf has changed' in self._caplog.text
            assert 'File /etc/containers/registries.conf updated' in self._caplog.text

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.toml.dump')
    @patch('cloudregister.registerutils.get_registry_conf_file')
    @patch('cloudregister.registerutils.os.path.exists')
    def test_set_registries_conf_podman_content_not_OK_order_has_changed(
        self,
        mock_os_path_exists, mock_get_reg_conf_file,
        mock_toml_dump
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
            assert utils.set_registries_conf_podman(
                'registry-ec2.susecloud.net'
            ) is None

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.toml.load')
    @patch('cloudregister.registerutils.os.path.exists')
    def test_set_registries_conf_podman_file_open_error(
        self, mock_os_path_exists, mock_toml_load
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
            assert utils.set_registries_conf_podman(
                'registry-ec2.susecloud.net'
            ) is False
            assert mock_open.call_args_list == [
                call('/etc/containers/registries.conf', 'r'),
                call('/etc/containers/registries.conf', 'w')
            ]
            assert 'Could not open /etc/containers/registries.conf' in self._caplog.text

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.exec_subprocess')
    @patch('cloudregister.registerutils.toml.load')
    @patch('cloudregister.registerutils.os.path.exists')
    def test_set_registries_conf_podman_content_not_OK_read_error_not_preserved(
        self,
        mock_os_path_exists, mock_toml_load, mock_exec_subprocess
    ):
        mock_os_path_exists.return_value = True
        mock_exec_subprocess.return_value = 1
        with patch('builtins.open', create=True) as mock_open:
            mock_open.side_effect = OSError('oh no !')
            assert utils.set_registries_conf_podman(
                'registry-ec2.susecloud.net'
            ) is False
            assert mock_open.call_args_list == [
                call('/etc/containers/registries.conf', 'r')
            ]
            assert 'File not preserved' in self._caplog.text

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.os.path.exists')
    def test_clean_registries_conf_podman_no_file(self, mock_os_path_exists):
        mock_os_path_exists.return_value = False
        assert utils.clean_registries_conf_podman('some-fqdn.suse.de')

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.get_registry_conf_file')
    @patch('cloudregister.registerutils.os.path.exists')
    def test_clean_registries_conf_podman_file_error_open(
        self,
        mock_os_path_exists, mock_get_registry_conf_file
    ):
        mock_os_path_exists.return_value = True
        mock_get_registry_conf_file.return_value = {}, 1
        assert utils.clean_registries_conf_podman('foo.com') is False

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.get_registry_conf_file')
    @patch('cloudregister.registerutils.os.path.exists')
    def test_clean_registries_conf_podman_file_no_error_empty_content(
        self, mock_os_path_exists, mock_get_registry_conf_file
    ):
        mock_os_path_exists.return_value = True
        mock_get_registry_conf_file.return_value = {}, 0
        assert utils.clean_registries_conf_podman('foo.com') is True

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.toml.dump')
    @patch('cloudregister.registerutils.toml.load')
    @patch('cloudregister.registerutils.os.path.exists')
    def test_clean_registries_conf_podman_file_clean_content_smt_OK(
        self,
        mock_os_path_exists, mock_toml_load, mock_toml_dump
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
            assert 'SUSE registry information has been removed' in self._caplog.text
            assert 'File /etc/containers/registries.conf updated' in self._caplog.text
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
    @patch('cloudregister.registerutils._get_registered_smt_file_path')
    @patch('cloudregister.registerutils.toml.dump')
    @patch('cloudregister.registerutils.toml.load')
    @patch('cloudregister.registerutils.os.path.exists')
    def test_clean_registries_conf_podman_file_clean_content_no_smt(
        self,
        mock_os_path_exists,
        mock_toml_load,
        mock_toml_dump, mock_get_registered_smt,
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
            assert 'SUSE registry information has been removed from' in self._caplog.text
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
    @patch('toml.dump')
    @patch('cloudregister.registerutils.get_registry_conf_file')
    def test_set_registry_order_search_podman_no_configured(
        self, mock_get_registry_file, mock_toml_dump
    ):
        with open('../data/unconfigured_registry.conf') as f:
            registry_conf = toml.load(f)
        mock_get_registry_file.return_value = registry_conf, False
        with patch('builtins.open', create=True) as mock_open:
            mock_open.return_value = MagicMock(spec=io.IOBase)
            file_handle = mock_open.return_value.__enter__.return_value

            utils.set_registries_conf_podman('rmt-registry.susecloud.net')

            mock_toml_dump.assert_called_once_with(
                {
                    'search-registries': ['docker.io'],
                    'no-registry': [{'location': 'foo'}],
                    'unqualified-search-registries': [
                        'rmt-registry.susecloud.net', 'registry.suse.com'
                    ],
                    'registry': [
                        {
                            'location': 'rmt-registry.susecloud.net',
                            'insecure': False
                        }
                    ]
                }, file_handle
            )

    # ---------------------------------------------------------------------------
    @patch('toml.dump')
    @patch('cloudregister.registerutils.get_registry_conf_file')
    def test_set_registry_order_search_podman_conf_missing_suse_registry(
        self, mock_get_registry_file, mock_toml_dump
    ):
        with open('../data/registry_conf.conf') as f:
            registry_conf = toml.load(f)
        mock_get_registry_file.return_value = registry_conf, False
        with patch('builtins.open', create=True) as mock_open:
            mock_open.return_value = MagicMock(spec=io.IOBase)
            file_handle = mock_open.return_value.__enter__.return_value

            utils.set_registries_conf_podman('rmt-registry.susecloud.net')

            mock_toml_dump.assert_called_once_with(
                {
                    'unqualified-search-registries': [
                        'rmt-registry.susecloud.net',
                        'registry.suse.com',
                        'foo.com',
                        'bar.registry.com',
                        'docker.io',
                    ],
                    'registry': [
                        {
                            'location': 'foo.com', 'insecure': True
                        },
                        {
                            'location': 'rmt-registry.susecloud.net',
                            'insecure': False
                        }
                    ]
                }, file_handle
            )

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.json.load')
    def test_get_registry_config_file_docker(self, mock_json_load):
        with patch('builtins.open') as mock_open:
            mock_open.return_value = MagicMock(spec=io.IOBase)
            utils.get_registry_conf_file(
                '/etc/docker/daemon.json', 'docker'
            )
            mock_json_load.assert_called_once()

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.get_registry_conf_file')
    @patch('cloudregister.registerutils.os.path.exists')
    def test_clean_registries_conf_docker_file_no_error_empty_content(
        self, mock_os_path_exists, mock_get_registry_conf_file
    ):
        mock_os_path_exists.return_value = True
        mock_get_registry_conf_file.return_value = {}, 0
        assert utils.clean_registries_conf_docker('foo.com') is True

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.get_registry_conf_file')
    @patch('cloudregister.registerutils.os.path.exists')
    def test_clean_registries_conf_docker_file_error(
        self,
        mock_os_path_exists, mock_get_registry_conf_file
    ):
        mock_os_path_exists.return_value = True
        mock_get_registry_conf_file.return_value = {}, 1
        assert utils.clean_registries_conf_docker('foo.com') is False

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.json.dump')
    @patch('cloudregister.registerutils.json.load')
    @patch('cloudregister.registerutils.os.path.exists')
    def test_clean_registries_conf_docker_file_clean_content_smt_OK(
        self,
        mock_os_path_exists, mock_json_load, mock_json_dump
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
            assert 'File /etc/docker/daemon.json updated' in self._caplog.text
            mock_json_dump.assert_called_once_with(
                {'registry-mirrors': ['foo.com', 'https://registry.suse.com']},
                file_handle
            )

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.json.dump')
    @patch('cloudregister.registerutils.json.load')
    @patch('cloudregister.registerutils.os.path.exists')
    def test_clean_registries_conf_docker_file_clean_content_no_smt(
        self,
        mock_os_path_exists, mock_json_load,
        mock_json_dump
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
            mock_json_dump.assert_called_once_with(
                {'registry-mirrors': ['foo.com', 'registry.suse.com']},
                file_handle
            )

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.exec_subprocess')
    @patch('cloudregister.registerutils.json.load')
    def test_get_registry_config_file_docker_not_parsed(
        self,
        mock_json_load, mock_exec_subprocess
    ):
        mock_json_load.side_effect = json.decoder.JSONDecodeError('a', 'b', 1)
        mock_exec_subprocess.return_value = 0
        with patch('builtins.open'):
            utils.get_registry_conf_file(
                '/etc/docker/daemon.json', 'docker'
            )
            mock_json_load.assert_called_once()
            assert 'Could not parse /etc/docker/daemon.json' in self._caplog.text
            assert 'preserving file as /etc/docker/daemon.json.bak' in self._caplog.text
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
        self, mock_os_path_exists, mock_json_dump, mock_get_registry_conf_file
    ):
        mock_os_path_exists.return_value = True
        with patch('builtins.open', create=True) as mock_open:
            mock_open.return_value = MagicMock(spec=io.IOBase)
            file_handle = mock_open.return_value.__enter__.return_value
            mock_get_registry_conf_file.return_value = {
                'registry-mirrors': ['foo'],
                'bar': ['bar'],
            }, False
            utils.set_registries_conf_docker('registry-foo.susecloud.net')
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
        self, mock_os_path_exists, mock_json_dump, mock_get_registry_conf_file
    ):
        mock_os_path_exists.return_value = True
        with patch('builtins.open', create=True) as mock_open:
            mock_open.return_value = MagicMock(spec=io.IOBase)
            mock_get_registry_conf_file.return_value = {
                'registry-mirrors': [
                    'foo',
                    'https://registry.suse.com',
                    'https://registry-foo.susecloud.net'
                ],
                'bar': ['bar'],
            }, False
            utils.set_registries_conf_docker('registry-foo.susecloud.net')
            # The registry setup contains the entries we care but was
            # modified manually. Don't touch this user modified variant.
            # This can be changed by the user via a --clean re-registration
            mock_json_dump.assert_not_called

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.get_registry_conf_file')
    @patch('cloudregister.registerutils.json.dump')
    @patch('os.path.exists')
    def test_set_registries_conf_docker_not_key_mirror(
        self, mock_os_path_exists, mock_json_dump, mock_get_registry_conf_file
    ):
        mock_os_path_exists.return_value = True
        with patch('builtins.open', create=True) as mock_open:
            mock_open.return_value = MagicMock(spec=io.IOBase)
            file_handle = mock_open.return_value.__enter__.return_value

            mock_get_registry_conf_file.return_value = {'foo': ['foo']}, False

            utils.set_registries_conf_docker('registry-foo.susecloud.net')

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
        self, mock_os_path_exists, mock_get_registry_conf_file
    ):
        mock_os_path_exists.return_value = True
        mock_get_registry_conf_file.return_value = {}, True
        assert utils.set_registries_conf_docker(
            'registry-foo.susecloud.net'
        ) is False

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.json.dump')
    def test_write_registries_conf(self, mock_json_dump):
        with patch('builtins.open', create=True) as mock_open:
            file_handle = mock_open.return_value.__enter__.return_value
            assert utils.write_registries_conf('foo', 'docker_path', 'docker')
            assert mock_json_dump.call_args_list == [
                call('foo', file_handle)
            ]
            assert 'File docker_path updated' in self._caplog.text

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.json.dump')
    def test_write_registries_conf_dump_error(self, mock_json_dump):
        mock_json_dump.side_effect = TypeError('error')
        with patch('builtins.open', create=True) as mock_open:
            file_handle = mock_open.return_value.__enter__.return_value
            assert utils.write_registries_conf(
                'foo', 'docker_path', 'docker'
            ) is False
            assert mock_json_dump.call_args_list == [
                call('foo', file_handle)
            ]
            assert 'Could not write docker_path' in self._caplog.text

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.glob.glob')
    def test_is_suma_instance_not(self, mock_glob_glob):
        mock_glob_glob.return_value = ['/etc/products.d/some-product.prod']
        assert utils.is_suma_instance() is False

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.glob.glob')
    def test_is_suma_instance(self, mock_glob_glob):
        mock_glob_glob.return_value = [
            '/etc/products.d/SLE-Micro.prod',
            '/etc/products.d/SUSE-Manager-Server.prod'
        ]
        assert utils.is_suma_instance()

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.get_suma_registry_content')
    @patch('cloudregister.registerutils.os.makedirs')
    def test_suma_registry_conf_suma_instance_error_get_suma_content(
        self,
        _, mock_get_suma_registry_content
    ):
        mock_get_suma_registry_content.return_value = {}, 1
        assert utils.set_registry_fqdn_suma('foo.com') is False

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.os.path.exists')
    @patch('cloudregister.registerutils.yaml.dump')
    @patch('cloudregister.registerutils.yaml.safe_load')
    @patch('cloudregister.registerutils.os.makedirs')
    def test_suma_registry_conf_suma_instance_file_exists(
        self,
        _, mock_yaml_safe_load, mock_yaml_dump, mock_os_path_exists
    ):
        mock_os_path_exists.return_value = True
        mock_yaml_safe_load.return_value = {}
        with patch('builtins.open', create=True) as mock_open:
            mock_open.return_value = MagicMock(spec=io.IOBase)
            file_handle = mock_open.return_value.__enter__.return_value
            # mock_open.side_effect = IOError('oh no ! an error')
            assert utils.set_registry_fqdn_suma('foo.com')
            assert mock_open.call_args_list == [
                call('/etc/uyuni/uyuni-tools.yaml', 'r'),
                call('/etc/uyuni/uyuni-tools.yaml', 'w')
            ]
            assert '/etc/uyuni/uyuni-tools.yaml updated' in self._caplog.text
            mock_yaml_dump.assert_called_once_with(
               {'registry': 'foo.com'},
               file_handle,
               default_flow_style=False
            )

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.os.path.exists')
    @patch('cloudregister.registerutils.yaml.dump')
    @patch('cloudregister.registerutils.yaml.safe_load')
    @patch('cloudregister.registerutils.os.makedirs')
    def test_suma_registry_conf_suma_instance_file_exists_different_fqdn(
        self,
        _, mock_yaml_safe_load, mock_yaml_dump, mock_os_path_exists
    ):
        mock_yaml_safe_load.return_value = {'registry': 'not-our-fqdn'}
        mock_os_path_exists.return_value = True
        with patch('builtins.open', create=True) as mock_open:
            # mock_open.return_value = MagicMock(spec=io.IOBase)
            file_handle = mock_open.return_value.__enter__.return_value
            assert utils.set_registry_fqdn_suma('foo.com')
            assert mock_open.call_args_list == [
                call('/etc/uyuni/uyuni-tools.yaml', 'r'),
                call('/etc/uyuni/uyuni-tools.yaml', 'w')
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
        self,
        _, mock_yaml_safe_load, mock_os_path_exists
    ):
        mock_os_path_exists.return_value = True
        mock_yaml_safe_load.return_value = {'registry': 'foo.com'}
        with patch('builtins.open', create=True) as mock_open:
            assert utils.set_registry_fqdn_suma('foo.com')
            assert mock_open.call_args_list == [
                call('/etc/uyuni/uyuni-tools.yaml', 'r')
            ]

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.os.path.exists')
    @patch('cloudregister.registerutils.yaml.safe_load')
    def test_get_suma_registry_content_error_yaml(
        self,
        mock_yaml_safe_load, mock_os_path_exists
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
            assert 'Could not parse /etc/uyuni/uyuni-tools.yaml' in self._caplog.text

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.os.path.exists')
    def test_get_suma_registry_content_error_open_file(
        self, mock_os_path_exists
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
            assert 'opening file error' in self._caplog.text
            assert 'Could not open /etc/uyuni/uyuni-tools.yaml' in self._caplog.text

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.os.path.exists')
    def test_get_suma_registry_content_no_file(self, mock_os_path_exists):
        mock_os_path_exists.return_value = False
        result, failed = utils.get_suma_registry_content()
        assert result == {}
        assert failed is False

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils._mv_file_backup')
    def test_write_suma_conf_error_open_file(self, mock_mv):
        mock_mv.return_value = 0
        with patch('builtins.open', create=True) as mock_open:
            mock_open.side_effect = IOError('opening file error')
            assert utils._write_suma_conf('foo') is None
            assert mock_open.call_args_list == [
                call('/etc/uyuni/uyuni-tools.yaml', 'w')
            ]

    # ---------------------------------------------------------------------------
    @patch('cloudregister.registerutils.yaml.dump')
    def test_write_suma_conf_error_yaml(
        self, mock_yaml_dump
    ):
        mock_yaml_dump.side_effect = yaml.YAMLError('some loading error')
        with patch('builtins.open', create=True) as mock_open:
            assert utils._write_suma_conf('foo') is None
            assert mock_open.call_args_list == [
                call('/etc/uyuni/uyuni-tools.yaml', 'w')
            ]
            assert 'Could not parse /etc/uyuni/uyuni-tools.yaml' in self._caplog.text

    # ---------------------------------------------------------------------------
    def test_matches_susecloud(self):
        assert utils._matches_susecloud(['foo']) == ''
        assert utils._matches_susecloud(
            ['registry-azure.susecloud.net']
        ) == 'registry-azure.susecloud.net'
        assert utils._matches_susecloud(
            ['foo', 'registry.susecloud.net', 'registry-azure.susecloud.net']
        ) == 'registry-azure.susecloud.net'


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


def get_test_config():
    """Return a config parser object using the minimum configuration in the
       ../data directory"""
    return utils.get_config(data_path + '/regionserverclnt.cfg')


def _check_dir_path(dir_name):
    """A directory path is expected to start with a '/' and will _not_ have
       a '/' at the end"""
    assert (dir_name[0] == '/')
    assert (dir_name[-1] != '/')


def _check_file_name(file_name):
    """A name that identifies a file is expected to _not_ start or end with
       a '/'"""
    assert (file_name[0] != '/')
    assert (file_name[-1] != '/')


class Response():
    """Fake a request response object"""

    def json(self):
        pass


class MockServer:
    def get_ipv4(self):
        return '1.1.1.1'

    def get_ipv6(self):
        return '11:22:33:44::00'
