import json
import requests
import logging
import tempfile

from collections import namedtuple
from lxml import etree
from textwrap import dedent
from urllib.parse import ParseResult

from pytest import raises, fixture
from types import SimpleNamespace
from unittest.mock import patch, Mock, mock_open

from tempfile import NamedTemporaryFile
from cloudregister.smt import SMT  # noqa
import cloudregister.registerutils as utils  # noqa

import cloudregister.registercloudguest as register_cloud_guest

temp_log = NamedTemporaryFile()
register_cloud_guest.LOG_FILE = temp_log.name


# Helper functions
class Response:
    """Fake a request response object"""

    def json(self):
        pass


class TestRegisterCloudGuest:
    @fixture(autouse=True)
    def inject_fixtures(self, caplog):
        self._caplog = caplog

    def test_register_cloud_guest_missing_param(self):
        fake_args = SimpleNamespace(
            user_smt_ip='fc00::1',
            user_smt_fqdn='foo.susecloud.net',
            user_smt_fp=None,
        )
        with raises(SystemExit):
            assert register_cloud_guest.main(fake_args) is None

    @patch('cloudregister.registerutils.has_network_access_by_ip_address')
    def test_register_cloud_guest_no_connection_ip(self, mock_has_network):
        mock_has_network.return_value = False
        fake_args = SimpleNamespace(
            user_smt_ip='1.2.3.5',
            user_smt_fqdn='foo.susecloud.net',
            user_smt_fp='AA:BB:CC:DD',
        )
        with raises(SystemExit):
            assert register_cloud_guest.main(fake_args) is None

    def test_register_cloud_guest_non_ip_value(self):
        fake_args = SimpleNamespace(
            user_smt_ip='Not.an.IP.Address',
            user_smt_fqdn='foo.susecloud.net',
            user_smt_fp='AA:BB:CC',
        )
        with raises(SystemExit):
            assert register_cloud_guest.main(fake_args) is None

    def test_register_cloud_guest_mixed_param(self):
        fake_args = SimpleNamespace(
            clean_up=True,
            force_new_registration=True,
            user_smt_ip=None,
            user_smt_fqdn=None,
            user_smt_fp=None,
            debug=True,
        )
        with raises(SystemExit):
            assert register_cloud_guest.main(fake_args) is None

    def test_register_cloud_guest_no_regcode_email(self):
        fake_args = SimpleNamespace(
            clean_up=False,
            force_new_registration=False,
            user_smt_ip=None,
            user_smt_fqdn=None,
            user_smt_fp=None,
            email='foo',
            reg_code=None,
            debug=True,
        )
        with raises(SystemExit):
            assert register_cloud_guest.main(fake_args) is None

    @patch('cloudregister.registerutils.clean_hosts_file')
    @patch('cloudregister.registerutils.deregister_non_free_extensions')
    @patch('time.sleep')
    @patch('cloudregister.registerutils.get_config')
    @patch('cloudregister.registerutils.clean_framework_identifier')
    @patch('cloudregister.registerutils.clear_new_registration_flag')
    @patch('cloudregister.registerutils.clean_smt_cache')
    def test_register_cloud_guest_cleanup(
        self,
        mock_clean_smt_cache,
        mock_clear_reg_flag,
        mock_framework_id,
        mock_get_config,
        mock_time_sleep,
        mock_deregister_non_free_extensions,
        mock_clean_hosts_file,
    ):
        fake_args = SimpleNamespace(
            clean_up=True,
            force_new_registration=False,
            user_smt_ip=None,
            user_smt_fqdn=None,
            user_smt_fp=None,
            email=None,
            reg_code=None,
            delay_time=1,
            config_file='config_file',
            debug=False,
        )
        with raises(SystemExit):
            register_cloud_guest.main(fake_args)

    @patch('cloudregister.registerutils.set_registration_completed_flag')
    @patch('cloudregister.registerutils.set_new_registration_flag')
    @patch('cloudregister.registerutils.has_network_access_by_ip_address')
    @patch('cloudregister.registerutils.is_zypper_running')
    @patch('cloudregister.registerutils.clear_new_registration_flag')
    @patch('cloudregister.registerutils.get_available_smt_servers')
    @patch('os.makedirs')
    @patch('os.path.isdir')
    @patch('time.sleep')
    @patch('cloudregister.registerutils.get_state_dir')
    @patch('cloudregister.registerutils.get_config')
    @patch('cloudregister.registercloudguest.cleanup')
    def test_register_cloud_guest_force_reg_zypper_running(
        self,
        mock_cleanup,
        mock_get_config,
        mock_get_state_dir,
        mock_time_sleep,
        mock_os_path_isdir,
        mock_os_makedirs,
        mock_get_available_smt_servers,
        mock_clear_reg_flag,
        mock_is_zypper_running,
        mock_has_network_access,
        mock_set_new_registration_flag,
        mock_set_registration_completed_flag,
    ):
        fake_args = SimpleNamespace(
            clean_up=False,
            force_new_registration=True,
            user_smt_ip='1.2.3.5',
            user_smt_fqdn='foo.susecloud.net',
            user_smt_fp='AA:BB:CC:DD',
            email=None,
            reg_code=None,
            delay_time=1,
            config_file='config_file',
            debug=True,
        )
        mock_os_path_isdir.return_value = False
        mock_is_zypper_running.return_value = True
        mock_get_available_smt_servers.return_value = ['some', 'smt', 'servers']
        mock_has_network_access.return_value = True
        with tempfile.TemporaryDirectory(suffix='foo') as tdir:
            mock_get_state_dir.return_value = tdir
        with raises(SystemExit) as sys_exit:
            register_cloud_guest.main(fake_args)
        assert sys_exit.value.code == 1

    @patch('cloudregister.registerutils.set_new_registration_flag')
    @patch('cloudregister.registerutils.has_network_access_by_ip_address')
    @patch('cloudregister.registerutils.is_zypper_running')
    @patch('cloudregister.registerutils.write_framework_identifier')
    @patch('cloudregister.registerutils.get_available_smt_servers')
    @patch('os.makedirs')
    @patch('os.path.isdir')
    @patch('time.sleep')
    @patch('cloudregister.registerutils.get_state_dir')
    @patch('cloudregister.registerutils.get_config')
    @patch('cloudregister.registercloudguest.cleanup')
    def test_register_cloud_guest_force_reg_zypper_runnning_write_config(
        self,
        mock_cleanup,
        mock_get_config,
        mock_get_state_dir,
        mock_time_sleep,
        mock_os_path_isdir,
        mock_os_makedirs,
        mock_get_available_smt_servers,
        mock_write_framework_id,
        mock_is_zypper_running,
        mock_has_network_access,
        mock_set_new_registration_flag,
    ):
        fake_args = SimpleNamespace(
            clean_up=False,
            force_new_registration=True,
            user_smt_ip='1.2.3.5',
            user_smt_fqdn='foo.susecloud.net',
            user_smt_fp='AA:BB:CC:DD',
            email=None,
            reg_code=None,
            delay_time=1,
            config_file='config_file',
            debug=True,
        )
        mock_os_path_isdir.return_value = False
        mock_is_zypper_running.return_value = True
        mock_get_available_smt_servers.return_value = []
        mock_has_network_access.return_value = True
        with tempfile.TemporaryDirectory(suffix='foo') as tdir:
            mock_get_state_dir.return_value = tdir
        with raises(SystemExit) as sys_exit:
            register_cloud_guest.main(fake_args)
        assert sys_exit.value.code == 1

    @patch.object(SMT, 'is_equivalent')
    @patch.object(SMT, 'is_responsive')
    @patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
    @patch('cloudregister.registerutils.has_region_changed')
    @patch('cloudregister.registerutils.store_smt_data')
    @patch('cloudregister.registerutils.get_current_smt')
    @patch('cloudregister.registerutils.set_new_registration_flag')
    @patch('cloudregister.registerutils.has_network_access_by_ip_address')
    @patch('cloudregister.registerutils.is_zypper_running')
    @patch('cloudregister.registerutils.write_framework_identifier')
    @patch('cloudregister.registerutils.get_available_smt_servers')
    @patch('os.makedirs')
    @patch('os.path.isdir')
    @patch('time.sleep')
    @patch('cloudregister.registerutils.get_state_dir')
    @patch('cloudregister.registerutils.get_config')
    @patch('cloudregister.registercloudguest.cleanup')
    @patch('cloudregister.registercloudguest.get_update_servers')
    @patch('cloudregister.registerutils.fetch_smt_data')
    def test_register_cloud_guest_force_reg_zypper_not_running_region_changed(
        self,
        mock_utils_fetch_smt_data,
        mock_get_update_servers,
        mock_cleanup,
        mock_get_config,
        mock_get_state_dir,
        mock_time_sleep,
        mock_os_path_isdir,
        mock_os_makedirs,
        mock_get_available_smt_servers,
        mock_write_framework_id,
        mock_is_zypper_running,
        mock_has_network_access,
        mock_set_new_registration_flag,
        mock_get_current_smt,
        mock_store_smt_data,
        mock_has_region_changed,
        mock_uses_rmt_as_scc_proxy,
        mock_smt_is_responsive,
        mock_smt_is_equivalent,
    ):
        smt_data_ipv46 = dedent(
            '''\
            <smtInfo fingerprint="AA:BB:CC:DD"
             SMTserverIP="1.2.3.5"
             SMTserverIPv6="fc00::1"
             SMTserverName="foo-ec2.susecloud.net"
             SMTregistryName="registry-ec2.susecloud.net"
             region="antarctica-1"/>'''
        )

        child = etree.fromstring(smt_data_ipv46)

        smt_server = SMT(child)

        mock_get_current_smt.return_value = smt_server
        fake_args = SimpleNamespace(
            clean_up=False,
            force_new_registration=True,
            user_smt_ip='1.2.3.5',
            user_smt_fqdn='foo-ec2.susecloud.net',
            user_smt_fp='AA:BB:CC:DD',
            email=None,
            reg_code=None,
            delay_time=1,
            config_file='config_file',
            debug=True,
        )
        mock_os_path_isdir.return_value = False
        mock_is_zypper_running.return_value = False
        mock_get_available_smt_servers.return_value = []
        mock_has_network_access.return_value = True
        mock_has_region_changed.return_value = True
        mock_uses_rmt_as_scc_proxy.return_value = True
        mock_smt_is_responsive.side_effect = [False, True]
        mock_smt_is_equivalent.return_value = False
        mock_get_update_servers.return_value = [smt_server]
        mock_utils_fetch_smt_data.return_value = [child]
        with tempfile.TemporaryDirectory(suffix='foo') as tdir:
            mock_get_state_dir.return_value = tdir
        with raises(SystemExit) as sys_exit:
            with self._caplog.at_level(logging.DEBUG):
                register_cloud_guest.main(fake_args)
        assert sys_exit.value.code == 1
        assert 'Configured update server is unresponsive' in self._caplog.text

    @patch('cloudregister.registerutils.set_proxy')
    @patch('cloudregister.registerutils.update_rmt_cert')
    @patch('cloudregister.registerutils.has_registry_in_hosts')
    @patch('cloudregister.registerutils.add_hosts_entry')
    @patch('cloudregister.registerutils.clean_hosts_file')
    @patch('cloudregister.registerutils.has_rmt_in_hosts')
    @patch('cloudregister.registerutils.os.path.exists')
    @patch.object(SMT, 'is_responsive')
    @patch('cloudregister.registercloudguest.setup_ltss_registration')
    @patch('cloudregister.registercloudguest.setup_registry')
    @patch('cloudregister.registerutils.get_instance_data')
    @patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
    @patch('cloudregister.registerutils.has_region_changed')
    @patch('cloudregister.registerutils.store_smt_data')
    @patch('cloudregister.registerutils.get_current_smt')
    @patch('cloudregister.registerutils.set_new_registration_flag')
    @patch('cloudregister.registerutils.has_network_access_by_ip_address')
    @patch('cloudregister.registerutils.is_zypper_running')
    @patch('cloudregister.registerutils.write_framework_identifier')
    @patch('cloudregister.registerutils.get_available_smt_servers')
    @patch('os.makedirs')
    @patch('os.path.isdir')
    @patch('time.sleep')
    @patch('cloudregister.registerutils.get_state_dir')
    @patch('cloudregister.registerutils.get_config')
    @patch('cloudregister.registercloudguest.cleanup')
    def test_register_cloud_guest_force_reg_zypper_not_running_region_not_changed(
        self,
        mock_cleanup,
        mock_get_config,
        mock_get_state_dir,
        mock_time_sleep,
        mock_os_path_isdir,
        mock_os_makedirs,
        mock_get_available_smt_servers,
        mock_write_framework_id,
        mock_is_zypper_running,
        mock_has_network_access,
        mock_set_new_registration_flag,
        mock_get_current_smt,
        mock_store_smt_data,
        mock_has_region_changed,
        mock_uses_rmt_as_scc_proxy,
        mock_get_instance_data,
        mock_setup_registry,
        mock_setup_ltss_registration,
        mock_smt_is_responsive,
        mock_os_path_exists,
        mock_has_rmt_in_hosts,
        mock_clean_hosts_file,
        mock_add_hosts_entry,
        mock_has_registry_in_hosts,
        mock_update_rmt_cert,
        mock_set_proxy,
    ):
        smt_data_ipv46 = dedent(
            '''\
            <smtInfo fingerprint="AA:BB:CC:DD"
             SMTserverIP="1.2.3.5"
             SMTserverIPv6="fc00::1"
             SMTserverName="foo-ec2.susecloud.net"
             SMTregistryName="registry-ec2.susecloud.net"
             region="antarctica-1"/>'''
        )

        smt_server = SMT(etree.fromstring(smt_data_ipv46))
        mock_get_current_smt.return_value = smt_server
        fake_args = SimpleNamespace(
            clean_up=False,
            force_new_registration=True,
            user_smt_ip='1.2.3.5',
            user_smt_fqdn='foo-ec2.susecloud.net',
            user_smt_fp='AA:BB:CC:DD',
            email=None,
            reg_code='super_reg_code',
            delay_time=1,
            config_file='config_file',
            debug=True,
        )
        mock_os_path_isdir.return_value = False
        mock_is_zypper_running.return_value = False
        mock_get_available_smt_servers.return_value = []
        mock_has_network_access.return_value = True
        mock_has_region_changed.return_value = True
        mock_uses_rmt_as_scc_proxy.return_value = True
        mock_get_instance_data.return_value = None
        mock_smt_is_responsive.return_value = True
        mock_os_path_exists.return_value = True
        mock_update_rmt_cert.return_value = True
        mock_has_rmt_in_hosts.return_value = False
        mock_has_registry_in_hosts.return_value = False
        with tempfile.TemporaryDirectory(suffix='foo') as tdir:
            mock_get_state_dir.return_value = tdir
        with raises(SystemExit) as sys_exit:
            register_cloud_guest.main(fake_args)
            assert sys_exit.value.code == 0

    @patch('cloudregister.registerutils.set_proxy')
    @patch('cloudregister.registerutils.update_rmt_cert')
    @patch('cloudregister.registerutils.has_registry_in_hosts')
    @patch('cloudregister.registerutils.add_hosts_entry')
    @patch('cloudregister.registerutils.clean_hosts_file')
    @patch('cloudregister.registerutils.has_rmt_in_hosts')
    @patch('cloudregister.registerutils.os.path.exists')
    @patch.object(SMT, 'is_responsive')
    @patch('cloudregister.registercloudguest.setup_ltss_registration')
    @patch('cloudregister.registercloudguest.setup_registry')
    @patch('cloudregister.registerutils.get_instance_data')
    @patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
    @patch('cloudregister.registerutils.has_region_changed')
    @patch('cloudregister.registerutils.store_smt_data')
    @patch('cloudregister.registerutils.get_current_smt')
    @patch('cloudregister.registerutils.set_new_registration_flag')
    @patch('cloudregister.registerutils.has_network_access_by_ip_address')
    @patch('cloudregister.registerutils.is_zypper_running')
    @patch('cloudregister.registerutils.write_framework_identifier')
    @patch('cloudregister.registerutils.get_available_smt_servers')
    @patch('os.makedirs')
    @patch('os.path.isdir')
    @patch('time.sleep')
    @patch('cloudregister.registerutils.get_state_dir')
    @patch('cloudregister.registerutils.get_config')
    @patch('cloudregister.registercloudguest.cleanup')
    @patch('cloudregister.registerutils.clean_registry_setup')
    def test_register_cloud_guest_registry_setup_failed(
        self,
        mock_clean_registry_setup,
        mock_cleanup,
        mock_get_config,
        mock_get_state_dir,
        mock_time_sleep,
        mock_os_path_isdir,
        mock_os_makedirs,
        mock_get_available_smt_servers,
        mock_write_framework_id,
        mock_is_zypper_running,
        mock_has_network_access,
        mock_set_new_registration_flag,
        mock_get_current_smt,
        mock_store_smt_data,
        mock_has_region_changed,
        mock_uses_rmt_as_scc_proxy,
        mock_get_instance_data,
        mock_setup_registry,
        mock_setup_ltss_registration,
        mock_smt_is_responsive,
        mock_os_path_exists,
        mock_has_rmt_in_hosts,
        mock_clean_hosts_file,
        mock_add_hosts_entry,
        mock_has_registry_in_hosts,
        mock_update_rmt_cert,
        mock_set_proxy,
    ):
        mock_set_proxy.return_value = True
        smt_data_ipv46 = dedent(
            '''\
            <smtInfo fingerprint="AA:BB:CC:DD"
             SMTserverIP="1.2.3.5"
             SMTserverIPv6="fc00::1"
             SMTserverName="foo-ec2.susecloud.net"
             SMTregistryName="registry-ec2.susecloud.net"
             region="antarctica-1"/>'''
        )

        smt_server = SMT(etree.fromstring(smt_data_ipv46))
        mock_get_current_smt.return_value = smt_server
        fake_args = SimpleNamespace(
            clean_up=False,
            force_new_registration=True,
            user_smt_ip='1.2.3.5',
            user_smt_fqdn='foo-ec2.susecloud.net',
            user_smt_fp='AA:BB:CC:DD',
            email=None,
            reg_code='super_reg_code',
            delay_time=1,
            config_file='config_file',
            debug=True,
        )
        mock_os_path_isdir.return_value = False
        mock_is_zypper_running.return_value = False
        mock_get_available_smt_servers.return_value = []
        mock_has_network_access.return_value = True
        mock_has_region_changed.return_value = True
        mock_uses_rmt_as_scc_proxy.return_value = True
        mock_get_instance_data.return_value = None
        mock_smt_is_responsive.return_value = True
        mock_os_path_exists.return_value = True
        mock_update_rmt_cert.return_value = True
        mock_has_rmt_in_hosts.return_value = False
        mock_has_registry_in_hosts.return_value = False
        mock_setup_registry.return_value = False
        with tempfile.TemporaryDirectory(suffix='foo') as tdir:
            mock_get_state_dir.return_value = tdir
        with raises(SystemExit) as sys_exit:
            register_cloud_guest.main(fake_args)
            assert sys_exit.value.code == 1

    @patch('cloudregister.registerutils.set_proxy')
    @patch('cloudregister.registerutils.update_rmt_cert')
    @patch('cloudregister.registerutils.has_registry_in_hosts')
    @patch('cloudregister.registerutils.add_hosts_entry')
    @patch('cloudregister.registerutils.clean_hosts_file')
    @patch('cloudregister.registerutils.has_rmt_in_hosts')
    @patch('cloudregister.registerutils.os.path.exists')
    @patch.object(SMT, 'is_responsive')
    @patch('cloudregister.registercloudguest.setup_ltss_registration')
    @patch('cloudregister.registercloudguest.setup_registry')
    @patch('cloudregister.registerutils.get_instance_data')
    @patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
    @patch('cloudregister.registerutils.has_region_changed')
    @patch('cloudregister.registerutils.store_smt_data')
    @patch('cloudregister.registerutils.get_current_smt')
    @patch('cloudregister.registerutils.set_new_registration_flag')
    @patch('cloudregister.registerutils.has_network_access_by_ip_address')
    @patch('cloudregister.registerutils.is_zypper_running')
    @patch('cloudregister.registerutils.write_framework_identifier')
    @patch('cloudregister.registerutils.get_available_smt_servers')
    @patch('os.makedirs')
    @patch('os.path.isdir')
    @patch('time.sleep')
    @patch('cloudregister.registerutils.get_state_dir')
    @patch('cloudregister.registerutils.get_config')
    @patch('cloudregister.registercloudguest.cleanup')
    def test_register_cloud_guest_region_not_changed_proxy_ok(
        self,
        mock_cleanup,
        mock_get_config,
        mock_get_state_dir,
        mock_time_sleep,
        mock_os_path_isdir,
        mock_os_makedirs,
        mock_get_available_smt_servers,
        mock_write_framework_id,
        mock_is_zypper_running,
        mock_has_network_access,
        mock_set_new_registration_flag,
        mock_get_current_smt,
        mock_store_smt_data,
        mock_has_region_changed,
        mock_uses_rmt_as_scc_proxy,
        mock_get_instance_data,
        mock_setup_registry,
        mock_setup_ltss_registration,
        mock_smt_is_responsive,
        mock_os_path_exists,
        mock_has_rmt_in_hosts,
        mock_clean_hosts_file,
        mock_add_hosts_entry,
        mock_has_registry_in_hosts,
        mock_update_rmt_cert,
        mock_set_proxy,
    ):
        mock_set_proxy.return_value = True
        smt_data_ipv46 = dedent(
            '''\
            <smtInfo fingerprint="AA:BB:CC:DD"
             SMTserverIP="1.2.3.5"
             SMTserverIPv6="fc00::1"
             SMTserverName="foo-ec2.susecloud.net"
             SMTregistryName="registry-ec2.susecloud.net"
             region="antarctica-1"/>'''
        )

        smt_server = SMT(etree.fromstring(smt_data_ipv46))
        mock_get_current_smt.return_value = smt_server
        fake_args = SimpleNamespace(
            clean_up=False,
            force_new_registration=True,
            user_smt_ip='1.2.3.5',
            user_smt_fqdn='foo-ec2.susecloud.net',
            user_smt_fp='AA:BB:CC:DD',
            email=None,
            reg_code='super_reg_code',
            delay_time=1,
            config_file='config_file',
            debug=True,
        )
        mock_os_path_isdir.return_value = False
        mock_is_zypper_running.return_value = False
        mock_get_available_smt_servers.return_value = []
        mock_has_network_access.return_value = True
        mock_has_region_changed.return_value = True
        mock_uses_rmt_as_scc_proxy.return_value = True
        mock_get_instance_data.return_value = None
        mock_smt_is_responsive.return_value = True
        mock_os_path_exists.return_value = True
        mock_update_rmt_cert.return_value = True
        mock_has_rmt_in_hosts.return_value = False
        mock_has_registry_in_hosts.return_value = False
        with tempfile.TemporaryDirectory(suffix='foo') as tdir:
            mock_get_state_dir.return_value = tdir
        with raises(SystemExit) as sys_exit:
            register_cloud_guest.main(fake_args)
            assert sys_exit.value.code == 0

    @patch('cloudregister.registerutils.replace_hosts_entry')
    @patch('cloudregister.registerutils.has_rmt_ipv6_access')
    @patch.object(SMT, 'is_equivalent')
    @patch('cloudregister.registerutils.set_proxy')
    @patch('cloudregister.registerutils.update_rmt_cert')
    @patch('cloudregister.registerutils.has_registry_in_hosts')
    @patch('cloudregister.registerutils.add_hosts_entry')
    @patch('cloudregister.registerutils.clean_hosts_file')
    @patch('cloudregister.registerutils.has_rmt_in_hosts')
    @patch('cloudregister.registerutils.os.path.exists')
    @patch.object(SMT, 'is_responsive')
    @patch('cloudregister.registercloudguest.setup_ltss_registration')
    @patch('cloudregister.registercloudguest.setup_registry')
    @patch('cloudregister.registerutils.get_instance_data')
    @patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
    @patch('cloudregister.registerutils.has_region_changed')
    @patch('cloudregister.registerutils.store_smt_data')
    @patch('cloudregister.registerutils.get_current_smt')
    @patch('cloudregister.registerutils.set_new_registration_flag')
    @patch('cloudregister.registerutils.has_network_access_by_ip_address')
    @patch('cloudregister.registerutils.is_zypper_running')
    @patch('cloudregister.registerutils.write_framework_identifier')
    @patch('cloudregister.registerutils.get_available_smt_servers')
    @patch('os.makedirs')
    @patch('os.path.isdir')
    @patch('time.sleep')
    @patch('cloudregister.registerutils.get_state_dir')
    @patch('cloudregister.registerutils.get_config')
    @patch('cloudregister.registercloudguest.cleanup')
    def test_register_cloud_guest_region_not_responsive_proxy_ok(
        self,
        mock_cleanup,
        mock_get_config,
        mock_get_state_dir,
        mock_time_sleep,
        mock_os_path_isdir,
        mock_os_makedirs,
        mock_get_available_smt_servers,
        mock_write_framework_id,
        mock_is_zypper_running,
        mock_has_network_access,
        mock_set_new_registration_flag,
        mock_get_current_smt,
        mock_store_smt_data,
        mock_has_region_changed,
        mock_uses_rmt_as_scc_proxy,
        mock_get_instance_data,
        mock_setup_registry,
        mock_setup_ltss_registration,
        mock_smt_is_responsive,
        mock_os_path_exists,
        mock_has_rmt_in_hosts,
        mock_clean_hosts_file,
        mock_add_hosts_entry,
        mock_has_registry_in_hosts,
        mock_update_rmt_cert,
        mock_set_proxy,
        mock_smt_is_equivalent,
        mock_has_ipv6_access,
        mock_replace_hosts_entry,
    ):
        mock_set_proxy.return_value = True
        smt_data_ipv46 = dedent(
            '''\
            <smtInfo fingerprint="AA:BB:CC:DD"
             SMTserverIP="1.2.3.5"
             SMTserverIPv6="fc00::1"
             SMTserverName="foo-ec2.susecloud.net"
             SMTregistryName="registry-ec2.susecloud.net"
             region="antarctica-1"/>'''
        )

        smt_server = SMT(etree.fromstring(smt_data_ipv46))
        mock_get_current_smt.return_value = smt_server
        fake_args = SimpleNamespace(
            clean_up=False,
            force_new_registration=True,
            user_smt_ip='1.2.3.5',
            user_smt_fqdn='foo-ec2.susecloud.net',
            user_smt_fp='AA:BB:CC:DD',
            email=None,
            reg_code='super_reg_code',
            delay_time=1,
            config_file='config_file',
            debug=True,
        )
        mock_os_path_isdir.return_value = False
        mock_is_zypper_running.return_value = False
        mock_get_available_smt_servers.return_value = []
        mock_has_network_access.return_value = True
        mock_has_region_changed.return_value = True
        mock_uses_rmt_as_scc_proxy.return_value = True
        mock_get_instance_data.return_value = None
        mock_smt_is_responsive.side_effect = [False, True]
        mock_smt_is_equivalent.return_value = True
        mock_os_path_exists.return_value = True
        mock_update_rmt_cert.return_value = True
        mock_has_rmt_in_hosts.return_value = False
        mock_has_registry_in_hosts.return_value = False
        mock_has_ipv6_access.return_value = True
        with tempfile.TemporaryDirectory(suffix='foo') as tdir:
            mock_get_state_dir.return_value = tdir
        with raises(SystemExit) as sys_exit:
            register_cloud_guest.main(fake_args)
            assert sys_exit.value.code == 0

    @patch('cloudregister.registerutils.set_proxy')
    @patch('cloudregister.registerutils.update_rmt_cert')
    @patch('cloudregister.registerutils.has_registry_in_hosts')
    @patch('cloudregister.registerutils.add_hosts_entry')
    @patch('cloudregister.registerutils.clean_hosts_file')
    @patch('cloudregister.registerutils.has_rmt_in_hosts')
    @patch('cloudregister.registerutils.os.path.exists')
    @patch.object(SMT, 'is_responsive')
    @patch('cloudregister.registercloudguest.setup_ltss_registration')
    @patch('cloudregister.registercloudguest.setup_registry')
    @patch('cloudregister.registerutils.get_instance_data')
    @patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
    @patch('cloudregister.registerutils.has_region_changed')
    @patch('cloudregister.registerutils.store_smt_data')
    @patch('cloudregister.registerutils.get_current_smt')
    @patch('cloudregister.registerutils.set_new_registration_flag')
    @patch('cloudregister.registerutils.has_network_access_by_ip_address')
    @patch('cloudregister.registerutils.is_zypper_running')
    @patch('cloudregister.registerutils.write_framework_identifier')
    @patch('cloudregister.registerutils.get_available_smt_servers')
    @patch('os.makedirs')
    @patch('os.path.isdir')
    @patch('time.sleep')
    @patch('cloudregister.registerutils.get_state_dir')
    @patch('cloudregister.registerutils.get_config')
    @patch('cloudregister.registercloudguest.cleanup')
    def test_register_cloud_guest_force_reg_rmt_scc_as_proxy(
        self,
        mock_cleanup,
        mock_get_config,
        mock_get_state_dir,
        mock_time_sleep,
        mock_os_path_isdir,
        mock_os_makedirs,
        mock_get_available_smt_servers,
        mock_write_framework_id,
        mock_is_zypper_running,
        mock_has_network_access,
        mock_set_new_registration_flag,
        mock_get_current_smt,
        mock_store_smt_data,
        mock_has_region_changed,
        mock_uses_rmt_as_scc_proxy,
        mock_get_instance_data,
        mock_setup_registry,
        mock_setup_ltss_registration,
        mock_smt_is_responsive,
        mock_os_path_exists,
        mock_has_rmt_in_hosts,
        mock_clean_hosts_file,
        mock_add_hosts_entry,
        mock_has_registry_in_hosts,
        mock_update_rmt_cert,
        mock_set_proxy,
    ):
        smt_data_ipv46 = dedent(
            '''\
            <smtInfo fingerprint="AA:BB:CC:DD"
             SMTserverIP="1.2.3.5"
             SMTserverIPv6="fc00::1"
             SMTserverName="foo-ec2.susecloud.net"
             SMTregistryName="registry-ec2.susecloud.net"
             region="antarctica-1"/>'''
        )

        smt_server = SMT(etree.fromstring(smt_data_ipv46))
        mock_get_current_smt.return_value = smt_server
        fake_args = SimpleNamespace(
            clean_up=False,
            force_new_registration=True,
            user_smt_ip='1.2.3.5',
            user_smt_fqdn='foo-ec2.susecloud.net',
            user_smt_fp='AA:BB:CC:DD',
            email=None,
            reg_code='super_reg_code',
            delay_time=1,
            config_file='config_file',
            debug=True,
        )
        mock_os_path_isdir.return_value = False
        mock_is_zypper_running.return_value = False
        mock_get_available_smt_servers.return_value = []
        mock_has_network_access.return_value = True
        mock_has_region_changed.return_value = True
        mock_uses_rmt_as_scc_proxy.side_effect = [False, True]
        mock_get_instance_data.return_value = None
        mock_smt_is_responsive.return_value = True
        mock_os_path_exists.return_value = True
        mock_update_rmt_cert.return_value = True
        mock_has_rmt_in_hosts.return_value = False
        mock_has_registry_in_hosts.return_value = False
        with tempfile.TemporaryDirectory(suffix='foo') as tdir:
            mock_get_state_dir.return_value = tdir
        with raises(SystemExit) as sys_exit:
            register_cloud_guest.main(fake_args)
            assert sys_exit.value.code == 0

    @patch('cloudregister.registerutils.set_proxy')
    @patch('cloudregister.registerutils.set_as_current_smt')
    @patch('os.access')
    @patch('cloudregister.registerutils.get_register_cmd')
    @patch('cloudregister.registerutils.update_rmt_cert')
    @patch('cloudregister.registerutils.has_registry_in_hosts')
    @patch('cloudregister.registerutils.add_hosts_entry')
    @patch('cloudregister.registerutils.clean_hosts_file')
    @patch('cloudregister.registerutils.has_rmt_in_hosts')
    @patch('cloudregister.registerutils.os.path.exists')
    @patch.object(SMT, 'is_responsive')
    @patch('cloudregister.registercloudguest.setup_ltss_registration')
    @patch('cloudregister.registercloudguest.setup_registry')
    @patch('cloudregister.registerutils.get_instance_data')
    @patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
    @patch('cloudregister.registerutils.has_region_changed')
    @patch('cloudregister.registerutils.store_smt_data')
    @patch('cloudregister.registerutils.get_current_smt')
    @patch('cloudregister.registerutils.set_new_registration_flag')
    @patch('cloudregister.registerutils.has_network_access_by_ip_address')
    @patch('cloudregister.registerutils.is_zypper_running')
    @patch('cloudregister.registerutils.write_framework_identifier')
    @patch('cloudregister.registerutils.get_available_smt_servers')
    @patch('os.makedirs')
    @patch('os.path.isdir')
    @patch('time.sleep')
    @patch('cloudregister.registerutils.get_state_dir')
    @patch('cloudregister.registerutils.get_config')
    @patch('cloudregister.registercloudguest.cleanup')
    def test_register_cloud_guest_force_reg_no_executable_found(
        self,
        mock_cleanup,
        mock_get_config,
        mock_get_state_dir,
        mock_time_sleep,
        mock_os_path_isdir,
        mock_os_makedirs,
        mock_get_available_smt_servers,
        mock_write_framework_id,
        mock_is_zypper_running,
        mock_has_network_access,
        mock_set_new_registration_flag,
        mock_get_current_smt,
        mock_store_smt_data,
        mock_has_region_changed,
        mock_uses_rmt_as_scc_proxy,
        mock_get_instance_data,
        mock_setup_registry,
        mock_setup_ltss_registration,
        mock_smt_is_responsive,
        mock_os_path_exists,
        mock_has_rmt_in_hosts,
        mock_clean_hosts_file,
        mock_add_hosts_entry,
        mock_has_registry_in_hosts,
        mock_update_rmt_cert,
        mock_get_register_cmd,
        mock_os_access,
        mock_set_as_current_smt,
        mock_set_proxy,
    ):
        smt_data_ipv46 = dedent(
            '''\
            <smtInfo fingerprint="AA:BB:CC:DD"
             SMTserverIP="1.2.3.5"
             SMTserverIPv6="fc00::1"
             SMTserverName="foo-ec2.susecloud.net"
             SMTregistryName="registry-ec2.susecloud.net"
             region="antarctica-1"/>'''
        )

        smt_server = SMT(etree.fromstring(smt_data_ipv46))
        mock_get_current_smt.return_value = smt_server
        fake_args = SimpleNamespace(
            clean_up=False,
            force_new_registration=True,
            user_smt_ip='1.2.3.5',
            user_smt_fqdn='foo-ec2.susecloud.net',
            user_smt_fp='AA:BB:CC:DD',
            email=None,
            reg_code='super_reg_code',
            delay_time=1,
            config_file='config_file',
            debug=True,
        )
        mock_os_path_isdir.return_value = False
        mock_is_zypper_running.return_value = False
        mock_get_available_smt_servers.return_value = []
        mock_has_network_access.return_value = True
        mock_has_region_changed.return_value = True
        mock_uses_rmt_as_scc_proxy.return_value = False
        mock_get_instance_data.return_value = None
        mock_smt_is_responsive.return_value = True
        mock_os_path_exists.side_effect = [True, False, False]
        mock_update_rmt_cert.return_value = True
        mock_has_rmt_in_hosts.return_value = False
        mock_has_registry_in_hosts.return_value = False
        mock_os_access.return_value = False
        with tempfile.TemporaryDirectory(suffix='foo') as tdir:
            mock_get_state_dir.return_value = tdir
        with raises(SystemExit) as sys_exit:
            register_cloud_guest.main(fake_args)
            assert 'No registration executable found' in self._caplog.text
            assert sys_exit.value.code == 1

    @patch('cloudregister.registerutils.set_proxy')
    @patch('cloudregister.registerutils.is_registration_supported')
    @patch('cloudregister.registerutils.set_as_current_smt')
    @patch('os.access')
    @patch('cloudregister.registerutils.get_register_cmd')
    @patch('cloudregister.registerutils.update_rmt_cert')
    @patch('cloudregister.registerutils.has_registry_in_hosts')
    @patch('cloudregister.registerutils.add_hosts_entry')
    @patch('cloudregister.registerutils.clean_hosts_file')
    @patch('cloudregister.registerutils.has_rmt_in_hosts')
    @patch('cloudregister.registerutils.os.path.exists')
    @patch.object(SMT, 'is_responsive')
    @patch('cloudregister.registercloudguest.setup_ltss_registration')
    @patch('cloudregister.registercloudguest.setup_registry')
    @patch('cloudregister.registerutils.get_instance_data')
    @patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
    @patch('cloudregister.registerutils.has_region_changed')
    @patch('cloudregister.registerutils.store_smt_data')
    @patch('cloudregister.registerutils.get_current_smt')
    @patch('cloudregister.registerutils.set_new_registration_flag')
    @patch('cloudregister.registerutils.has_network_access_by_ip_address')
    @patch('cloudregister.registerutils.is_zypper_running')
    @patch('cloudregister.registerutils.write_framework_identifier')
    @patch('cloudregister.registerutils.get_available_smt_servers')
    @patch('os.makedirs')
    @patch('os.path.isdir')
    @patch('time.sleep')
    @patch('cloudregister.registerutils.get_state_dir')
    @patch('cloudregister.registerutils.get_config')
    @patch('cloudregister.registercloudguest.cleanup')
    def test_register_cloud_guest_force_registration_not_supported(
        self,
        mock_cleanup,
        mock_get_config,
        mock_get_state_dir,
        mock_time_sleep,
        mock_os_path_isdir,
        mock_os_makedirs,
        mock_get_available_smt_servers,
        mock_write_framework_id,
        mock_is_zypper_running,
        mock_has_network_access,
        mock_set_new_registration_flag,
        mock_get_current_smt,
        mock_store_smt_data,
        mock_has_region_changed,
        mock_uses_rmt_as_scc_proxy,
        mock_get_instance_data,
        mock_setup_registry,
        mock_setup_ltss_registration,
        mock_smt_is_responsive,
        mock_os_path_exists,
        mock_has_rmt_in_hosts,
        mock_clean_hosts_file,
        mock_add_hosts_entry,
        mock_has_registry_in_hosts,
        mock_update_rmt_cert,
        mock_get_register_cmd,
        mock_os_access,
        mock_set_as_current_smt,
        mock_is_registration_supported,
        mock_set_proxy,
    ):
        smt_data_ipv46 = dedent(
            '''\
            <smtInfo fingerprint="AA:BB:CC:DD"
             SMTserverIP="1.2.3.5"
             SMTserverIPv6="fc00::1"
             SMTserverName="foo-ec2.susecloud.net"
             SMTregistryName="registry-ec2.susecloud.net"
             region="antarctica-1"/>'''
        )

        smt_server = SMT(etree.fromstring(smt_data_ipv46))
        mock_get_current_smt.return_value = smt_server
        fake_args = SimpleNamespace(
            clean_up=False,
            force_new_registration=True,
            user_smt_ip='1.2.3.5',
            user_smt_fqdn='foo-ec2.susecloud.net',
            user_smt_fp='AA:BB:CC:DD',
            email=None,
            reg_code='super_reg_code',
            delay_time=1,
            config_file='config_file',
            debug=True,
        )
        mock_os_path_isdir.return_value = False
        mock_is_zypper_running.return_value = False
        mock_get_available_smt_servers.return_value = []
        mock_has_network_access.return_value = True
        mock_has_region_changed.return_value = True
        mock_uses_rmt_as_scc_proxy.return_value = False
        mock_get_instance_data.return_value = None
        mock_smt_is_responsive.return_value = True
        mock_set_proxy.return_value = False
        mock_os_path_exists.side_effect = [True, False]
        mock_update_rmt_cert.return_value = True
        mock_has_rmt_in_hosts.return_value = False
        mock_has_registry_in_hosts.return_value = False
        mock_os_access.return_value = False
        mock_is_registration_supported.return_value = False
        with tempfile.TemporaryDirectory(suffix='foo') as tdir:
            mock_get_state_dir.return_value = tdir
        with raises(SystemExit) as sys_exit:
            register_cloud_guest.main(fake_args)
        assert sys_exit.value.code == 0

    @patch('cloudregister.registerutils.set_proxy')
    @patch('cloudregister.registerutils.get_installed_products')
    @patch('cloudregister.registerutils.set_as_current_smt')
    @patch('os.access')
    @patch('cloudregister.registerutils.get_register_cmd')
    @patch('cloudregister.registerutils.update_rmt_cert')
    @patch('cloudregister.registerutils.has_registry_in_hosts')
    @patch('cloudregister.registerutils.add_hosts_entry')
    @patch('cloudregister.registerutils.clean_hosts_file')
    @patch('cloudregister.registerutils.has_rmt_in_hosts')
    @patch('cloudregister.registerutils.os.path.exists')
    @patch.object(SMT, 'is_responsive')
    @patch('cloudregister.registercloudguest.setup_ltss_registration')
    @patch('cloudregister.registercloudguest.setup_registry')
    @patch('cloudregister.registerutils.get_instance_data')
    @patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
    @patch('cloudregister.registerutils.has_region_changed')
    @patch('cloudregister.registerutils.store_smt_data')
    @patch('cloudregister.registerutils.get_current_smt')
    @patch('cloudregister.registerutils.set_new_registration_flag')
    @patch('cloudregister.registerutils.has_network_access_by_ip_address')
    @patch('cloudregister.registerutils.is_zypper_running')
    @patch('cloudregister.registerutils.write_framework_identifier')
    @patch('cloudregister.registerutils.get_available_smt_servers')
    @patch('os.makedirs')
    @patch('os.path.isdir')
    @patch('time.sleep')
    @patch('cloudregister.registerutils.get_state_dir')
    @patch('cloudregister.registerutils.get_config')
    @patch('cloudregister.registercloudguest.cleanup')
    def test_register_cloud_guest_force_reg_no_products_installed(
        self,
        mock_cleanup,
        mock_get_config,
        mock_get_state_dir,
        mock_time_sleep,
        mock_os_path_isdir,
        mock_os_makedirs,
        mock_get_available_smt_servers,
        mock_write_framework_id,
        mock_is_zypper_running,
        mock_has_network_access,
        mock_set_new_registration_flag,
        mock_get_current_smt,
        mock_store_smt_data,
        mock_has_region_changed,
        mock_uses_rmt_as_scc_proxy,
        mock_get_instance_data,
        mock_setup_registry,
        mock_setup_ltss_registration,
        mock_smt_is_responsive,
        mock_os_path_exists,
        mock_has_rmt_in_hosts,
        mock_clean_hosts_file,
        mock_add_hosts_entry,
        mock_has_registry_in_hosts,
        mock_update_rmt_cert,
        mock_get_register_cmd,
        mock_os_access,
        mock_set_as_current_smt,
        mock_get_installed_products,
        mock_set_proxy,
    ):
        smt_data_ipv46 = dedent(
            '''\
            <smtInfo fingerprint="AA:BB:CC:DD"
             SMTserverIP="1.2.3.5"
             SMTserverIPv6="fc00::1"
             SMTserverName="foo-ec2.susecloud.net"
             SMTregistryName="registry-ec2.susecloud.net"
             region="antarctica-1"/>'''
        )

        smt_server = SMT(etree.fromstring(smt_data_ipv46))
        mock_get_current_smt.return_value = smt_server
        fake_args = SimpleNamespace(
            clean_up=False,
            force_new_registration=True,
            user_smt_ip='1.2.3.5',
            user_smt_fqdn='foo-ec2.susecloud.net',
            user_smt_fp='AA:BB:CC:DD',
            email=None,
            reg_code='super_reg_code',
            delay_time=1,
            config_file='config_file',
            debug=True,
        )
        mock_os_path_isdir.return_value = False
        mock_is_zypper_running.return_value = False
        mock_get_available_smt_servers.return_value = []
        mock_has_network_access.return_value = True
        mock_has_region_changed.return_value = True
        mock_uses_rmt_as_scc_proxy.return_value = False
        mock_get_instance_data.return_value = None
        mock_smt_is_responsive.return_value = True
        mock_set_proxy.return_value = False
        mock_os_path_exists.side_effect = [True, True]
        mock_update_rmt_cert.return_value = True
        mock_has_rmt_in_hosts.return_value = False
        mock_has_registry_in_hosts.return_value = False
        mock_os_access.return_value = True
        mock_get_installed_products.return_value = None
        with tempfile.TemporaryDirectory(suffix='foo') as tdir:
            mock_get_state_dir.return_value = tdir
        with raises(SystemExit) as sys_exit:
            register_cloud_guest.main(fake_args)
        assert 'No products installed on system' in self._caplog.text
        assert sys_exit.value.code == 1

    @patch('cloudregister.registerutils.set_proxy')
    @patch('cloudregister.registerutils.import_smt_cert')
    @patch('cloudregister.registerutils.get_installed_products')
    @patch('cloudregister.registerutils.set_as_current_smt')
    @patch('os.access')
    @patch('cloudregister.registerutils.get_register_cmd')
    @patch('cloudregister.registerutils.update_rmt_cert')
    @patch('cloudregister.registerutils.has_registry_in_hosts')
    @patch('cloudregister.registerutils.add_hosts_entry')
    @patch('cloudregister.registerutils.clean_hosts_file')
    @patch('cloudregister.registerutils.has_rmt_in_hosts')
    @patch('cloudregister.registerutils.os.path.exists')
    @patch.object(SMT, 'is_responsive')
    @patch('cloudregister.registercloudguest.setup_ltss_registration')
    @patch('cloudregister.registercloudguest.setup_registry')
    @patch('cloudregister.registerutils.get_instance_data')
    @patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
    @patch('cloudregister.registerutils.has_region_changed')
    @patch('cloudregister.registerutils.store_smt_data')
    @patch('cloudregister.registerutils.get_current_smt')
    @patch('cloudregister.registerutils.set_new_registration_flag')
    @patch('cloudregister.registerutils.has_network_access_by_ip_address')
    @patch('cloudregister.registerutils.is_zypper_running')
    @patch('cloudregister.registerutils.write_framework_identifier')
    @patch('cloudregister.registerutils.get_available_smt_servers')
    @patch('os.makedirs')
    @patch('os.path.isdir')
    @patch('time.sleep')
    @patch('cloudregister.registerutils.get_state_dir')
    @patch('cloudregister.registerutils.get_config')
    @patch('cloudregister.registercloudguest.cleanup')
    def test_register_cloud_guest_force_reg_cert_import_failed(
        self,
        mock_cleanup,
        mock_get_config,
        mock_get_state_dir,
        mock_time_sleep,
        mock_os_path_isdir,
        mock_os_makedirs,
        mock_get_available_smt_servers,
        mock_write_framework_id,
        mock_is_zypper_running,
        mock_has_network_access,
        mock_set_new_registration_flag,
        mock_get_current_smt,
        mock_store_smt_data,
        mock_has_region_changed,
        mock_uses_rmt_as_scc_proxy,
        mock_get_instance_data,
        mock_setup_registry,
        mock_setup_ltss_registration,
        mock_smt_is_responsive,
        mock_os_path_exists,
        mock_has_rmt_in_hosts,
        mock_clean_hosts_file,
        mock_add_hosts_entry,
        mock_has_registry_in_hosts,
        mock_update_rmt_cert,
        mock_get_register_cmd,
        mock_os_access,
        mock_set_as_current_smt,
        mock_get_installed_products,
        mock_import_smt_cert,
        mock_set_proxy,
    ):
        smt_data_ipv46 = dedent(
            '''\
            <smtInfo fingerprint="AA:BB:CC:DD"
             SMTserverIP="1.2.3.5"
             SMTserverIPv6="fc00::1"
             SMTserverName="foo-ec2.susecloud.net"
             SMTregistryName="registry-ec2.susecloud.net"
             region="antarctica-1"/>'''
        )

        smt_server = SMT(etree.fromstring(smt_data_ipv46))
        mock_get_current_smt.return_value = smt_server
        fake_args = SimpleNamespace(
            clean_up=False,
            force_new_registration=True,
            user_smt_ip='1.2.3.5',
            user_smt_fqdn='foo-ec2.susecloud.net',
            user_smt_fp='AA:BB:CC:DD',
            email=None,
            reg_code='super_reg_code',
            delay_time=1,
            config_file='config_file',
            debug=True,
        )
        mock_os_path_isdir.return_value = False
        mock_is_zypper_running.return_value = False
        mock_get_available_smt_servers.return_value = []
        mock_has_network_access.return_value = True
        mock_has_region_changed.return_value = True
        mock_uses_rmt_as_scc_proxy.return_value = False
        mock_get_instance_data.return_value = None
        mock_smt_is_responsive.return_value = True
        mock_set_proxy.return_value = False
        mock_os_path_exists.side_effect = [True, True]
        mock_update_rmt_cert.return_value = True
        mock_has_rmt_in_hosts.return_value = False
        mock_has_registry_in_hosts.return_value = False
        mock_os_access.return_value = True
        mock_get_installed_products.return_value = 'foo'
        mock_import_smt_cert.return_value = False
        with tempfile.TemporaryDirectory(suffix='foo') as tdir:
            mock_get_state_dir.return_value = tdir
        with raises(SystemExit) as sys_exit:
            register_cloud_guest.main(fake_args)
        assert sys_exit.value.code == 1

    @patch('cloudregister.registerutils.set_proxy')
    @patch('cloudregister.registerutils.register_product')
    @patch('cloudregister.registerutils.import_smt_cert')
    @patch('cloudregister.registerutils.get_installed_products')
    @patch('cloudregister.registerutils.set_as_current_smt')
    @patch('os.access')
    @patch('cloudregister.registerutils.get_register_cmd')
    @patch('cloudregister.registerutils.update_rmt_cert')
    @patch('cloudregister.registerutils.has_registry_in_hosts')
    @patch('cloudregister.registerutils.add_hosts_entry')
    @patch('cloudregister.registerutils.clean_hosts_file')
    @patch('cloudregister.registerutils.has_rmt_in_hosts')
    @patch('cloudregister.registerutils.os.path.exists')
    @patch.object(SMT, 'is_responsive')
    @patch('cloudregister.registercloudguest.setup_ltss_registration')
    @patch('cloudregister.registercloudguest.setup_registry')
    @patch('cloudregister.registerutils.get_instance_data')
    @patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
    @patch('cloudregister.registerutils.has_region_changed')
    @patch('cloudregister.registerutils.store_smt_data')
    @patch('cloudregister.registerutils.get_current_smt')
    @patch('cloudregister.registerutils.set_new_registration_flag')
    @patch('cloudregister.registerutils.has_network_access_by_ip_address')
    @patch('cloudregister.registerutils.is_zypper_running')
    @patch('cloudregister.registerutils.write_framework_identifier')
    @patch('cloudregister.registerutils.get_available_smt_servers')
    @patch('os.makedirs')
    @patch('os.path.isdir')
    @patch('time.sleep')
    @patch('cloudregister.registerutils.get_state_dir')
    @patch('cloudregister.registerutils.get_config')
    @patch('cloudregister.registerutils.deregister_non_free_extensions')
    @patch('cloudregister.registerutils.deregister_from_update_infrastructure')
    @patch('cloudregister.registerutils.deregister_from_SCC')
    @patch('cloudregister.registerutils.clean_cache')
    @patch('cloudregister.registerutils.clean_all_standard')
    def test_register_cloud_guest_force_baseprod_registration_failed(
        self,
        mock_clean_all_standard,
        mock_clean_cache,
        mock_deregister_from_SCC,
        mock_deregister_from_update_infrastructure,
        mock_deregister_non_free_extensions,
        mock_get_config,
        mock_get_state_dir,
        mock_time_sleep,
        mock_os_path_isdir,
        mock_os_makedirs,
        mock_get_available_smt_servers,
        mock_write_framework_id,
        mock_is_zypper_running,
        mock_has_network_access,
        mock_set_new_registration_flag,
        mock_get_current_smt,
        mock_store_smt_data,
        mock_has_region_changed,
        mock_uses_rmt_as_scc_proxy,
        mock_get_instance_data,
        mock_setup_registry,
        mock_setup_ltss_registration,
        mock_smt_is_responsive,
        mock_os_path_exists,
        mock_has_rmt_in_hosts,
        mock_clean_hosts_file,
        mock_add_hosts_entry,
        mock_has_registry_in_hosts,
        mock_update_rmt_cert,
        mock_get_register_cmd,
        mock_os_access,
        mock_set_as_current_smt,
        mock_get_installed_products,
        mock_import_smt_cert,
        mock_register_product,
        mock_set_proxy,
    ):
        smt_data_ipv46 = dedent(
            '''\
            <smtInfo fingerprint="AA:BB:CC:DD"
             SMTserverIP="1.2.3.5"
             SMTserverIPv6="fc00::1"
             SMTserverName="foo-ec2.susecloud.net"
             SMTregistryName="registry-ec2.susecloud.net"
             region="antarctica-1"/>'''
        )

        smt_server = SMT(etree.fromstring(smt_data_ipv46))
        mock_get_current_smt.return_value = smt_server
        fake_args = SimpleNamespace(
            clean_up=False,
            force_new_registration=True,
            user_smt_ip='1.2.3.5',
            user_smt_fqdn='foo-ec2.susecloud.net',
            user_smt_fp='AA:BB:CC:DD',
            email=None,
            reg_code='super_reg_code',
            delay_time=1,
            config_file='config_file',
            debug=True,
        )
        mock_os_path_isdir.return_value = False
        mock_is_zypper_running.return_value = False
        mock_get_available_smt_servers.return_value = []
        mock_has_network_access.return_value = True
        mock_has_region_changed.return_value = True
        mock_uses_rmt_as_scc_proxy.return_value = False
        mock_get_instance_data.return_value = None
        mock_smt_is_responsive.return_value = True
        mock_set_proxy.return_value = False
        mock_os_path_exists.side_effect = [True, True]
        mock_update_rmt_cert.return_value = True
        mock_has_rmt_in_hosts.return_value = False
        mock_has_registry_in_hosts.return_value = False
        mock_os_access.return_value = True
        mock_get_installed_products.return_value = 'foo'
        mock_import_smt_cert.return_value = True
        with tempfile.TemporaryDirectory(suffix='foo') as tdir:
            mock_get_state_dir.return_value = tdir
        prod_reg_type = namedtuple(
            'prod_reg_type', ['returncode', 'output', 'error']
        )
        mock_register_product.return_value = prod_reg_type(
            returncode=67, output='registration code', error='stderr'
        )
        with raises(SystemExit) as sys_exit:
            register_cloud_guest.main(fake_args)
        assert 'Baseproduct registration failed' in self._caplog.text
        assert sys_exit.value.code == 1

    @patch('cloudregister.registerutils._remove_state_file')
    @patch('cloudregister.registerutils.set_proxy')
    @patch('cloudregister.registerutils.get_credentials_file')
    @patch('cloudregister.registerutils.get_credentials')
    @patch('cloudregister.registerutils.get_product_tree')
    @patch('cloudregister.registerutils.requests.get')
    @patch('cloudregister.registerutils.set_rmt_as_scc_proxy_flag')
    @patch('cloudregister.registerutils.register_product')
    @patch('cloudregister.registerutils.import_smt_cert')
    @patch('cloudregister.registerutils.get_installed_products')
    @patch('cloudregister.registerutils.set_as_current_smt')
    @patch('os.access')
    @patch('cloudregister.registerutils.get_register_cmd')
    @patch('cloudregister.registerutils.update_rmt_cert')
    @patch('cloudregister.registerutils.has_registry_in_hosts')
    @patch('cloudregister.registerutils.add_hosts_entry')
    @patch('cloudregister.registerutils.clean_hosts_file')
    @patch('cloudregister.registerutils.has_rmt_in_hosts')
    @patch('cloudregister.registerutils.os.path.exists')
    @patch.object(SMT, 'is_responsive')
    @patch('cloudregister.registercloudguest.setup_ltss_registration')
    @patch('cloudregister.registercloudguest.setup_registry')
    @patch('cloudregister.registerutils.get_instance_data')
    @patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
    @patch('cloudregister.registerutils.has_region_changed')
    @patch('cloudregister.registerutils.store_smt_data')
    @patch('cloudregister.registerutils.get_current_smt')
    @patch('cloudregister.registerutils.set_new_registration_flag')
    @patch('cloudregister.registerutils.has_network_access_by_ip_address')
    @patch('cloudregister.registerutils.is_zypper_running')
    @patch('cloudregister.registerutils.write_framework_identifier')
    @patch('cloudregister.registerutils.get_available_smt_servers')
    @patch('os.makedirs')
    @patch('os.path.isdir')
    @patch('time.sleep')
    @patch('cloudregister.registerutils.get_state_dir')
    @patch('cloudregister.registerutils.get_config')
    @patch('cloudregister.registercloudguest.cleanup')
    def test_register_cloud_guest_force_baseprod_registration_ok_failed_extensions(
        self,
        mock_cleanup,
        mock_get_config,
        mock_get_state_dir,
        mock_time_sleep,
        mock_os_path_isdir,
        mock_os_makedirs,
        mock_get_available_smt_servers,
        mock_write_framework_id,
        mock_is_zypper_running,
        mock_has_network_access,
        mock_set_new_registration_flag,
        mock_get_current_smt,
        mock_store_smt_data,
        mock_has_region_changed,
        mock_uses_rmt_as_scc_proxy,
        mock_get_instance_data,
        mock_setup_registry,
        mock_setup_ltss_registration,
        mock_smt_is_responsive,
        mock_os_path_exists,
        mock_has_rmt_in_hosts,
        mock_clean_hosts_file,
        mock_add_hosts_entry,
        mock_has_registry_in_hosts,
        mock_update_rmt_cert,
        mock_get_register_cmd,
        mock_os_access,
        mock_set_as_current_smt,
        mock_get_installed_products,
        mock_import_smt_cert,
        mock_register_product,
        mock_set_rmt_as_scc_proxy_flag,
        mock_requests_get,
        mock_get_product_tree,
        mock_get_creds,
        mock_get_creds_file,
        mock_set_proxy,
        mock_remove_state_file,
    ):
        smt_data_ipv46 = dedent(
            '''\
            <smtInfo fingerprint="AA:BB:CC:DD"
             SMTserverIP="1.2.3.5"
             SMTserverIPv6="fc00::1"
             SMTserverName="foo-ec2.susecloud.net"
             SMTregistryName="registry-ec2.susecloud.net"
             region="antarctica-1"/>'''
        )

        smt_server = SMT(etree.fromstring(smt_data_ipv46))
        mock_get_current_smt.return_value = smt_server
        fake_args = SimpleNamespace(
            clean_up=False,
            force_new_registration=True,
            user_smt_ip='1.2.3.5',
            user_smt_fqdn='foo-ec2.susecloud.net',
            user_smt_fp='AA:BB:CC:DD',
            email=None,
            reg_code='super_reg_code',
            delay_time=1,
            config_file='config_file',
            debug=True,
        )
        mock_os_path_isdir.return_value = False
        mock_is_zypper_running.return_value = False
        mock_get_available_smt_servers.return_value = []
        mock_has_network_access.return_value = True
        mock_has_region_changed.return_value = True
        mock_uses_rmt_as_scc_proxy.return_value = False
        mock_get_instance_data.return_value = None
        mock_smt_is_responsive.return_value = True
        mock_os_path_exists.side_effect = [True, True]
        mock_update_rmt_cert.return_value = True
        mock_has_rmt_in_hosts.return_value = False
        mock_has_registry_in_hosts.return_value = False
        mock_os_access.return_value = True
        mock_get_installed_products.return_value = 'foo'
        mock_import_smt_cert.return_value = True
        mock_remove_state_file.return_value = True
        with tempfile.TemporaryDirectory(suffix='foo') as tdir:
            mock_get_state_dir.return_value = tdir
        prod_reg_type = namedtuple(
            'prod_reg_type', ['returncode', 'output', 'error']
        )
        mock_register_product.return_value = prod_reg_type(
            returncode=0, output='registration code', error='stderr'
        )
        response = Response()
        response.status_code = requests.codes.forbidden
        response.reason = 'Because nope'
        response.content = str(json.dumps('no accessio')).encode()
        mock_requests_get.return_value = response
        mock_get_creds.return_value = 'SCC_foo', 'bar'
        base_product = dedent(
            '''\
            <?xml version="1.0" encoding="UTF-8"?>
            <product schemeversion="0">
              <vendor>SUSE</vendor>
              <name>SLES</name>
              <version>15.4</version>
              <baseversion>15</baseversion>
              <patchlevel>4</patchlevel>
              <release>0</release>
              <endoflife></endoflife>
              <arch>x86_64</arch></product>'''
        )
        mock_get_product_tree.return_value = etree.fromstring(
            base_product[base_product.index('<product') :]
        )
        mock_set_proxy.return_value = False
        with raises(SystemExit) as sys_exit:
            register_cloud_guest.main(fake_args)
        assert (
            'Unable to obtain product information from server "1.2.3.5,None"'
            in self._caplog.text
        )
        assert 'Unable to register modules, exiting.' in self._caplog.text
        assert sys_exit.value.code == 1

    @patch('cloudregister.registerutils.set_proxy')
    @patch('cloudregister.registercloudguest.registration_returncode', 0)
    @patch('os.unlink')
    @patch('cloudregister.registerutils.get_credentials_file')
    @patch('cloudregister.registerutils.get_credentials')
    @patch('cloudregister.registerutils.get_product_tree')
    @patch('cloudregister.registerutils.requests.get')
    @patch('cloudregister.registerutils.set_rmt_as_scc_proxy_flag')
    @patch('cloudregister.registerutils.register_product')
    @patch('cloudregister.registerutils.import_smt_cert')
    @patch('cloudregister.registerutils.get_installed_products')
    @patch('cloudregister.registerutils.set_as_current_smt')
    @patch('os.access')
    @patch('cloudregister.registerutils.get_register_cmd')
    @patch('cloudregister.registerutils.update_rmt_cert')
    @patch('cloudregister.registerutils.has_registry_in_hosts')
    @patch('cloudregister.registerutils.add_hosts_entry')
    @patch('cloudregister.registerutils.clean_hosts_file')
    @patch('cloudregister.registerutils.has_rmt_in_hosts')
    @patch('cloudregister.registerutils.os.path.exists')
    @patch.object(SMT, 'is_responsive')
    @patch('cloudregister.registercloudguest.setup_ltss_registration')
    @patch('cloudregister.registercloudguest.setup_registry')
    @patch('cloudregister.registerutils.get_instance_data')
    @patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
    @patch('cloudregister.registerutils.has_region_changed')
    @patch('cloudregister.registerutils.store_smt_data')
    @patch('cloudregister.registerutils.get_current_smt')
    @patch('cloudregister.registerutils.set_new_registration_flag')
    @patch('cloudregister.registerutils.has_network_access_by_ip_address')
    @patch('cloudregister.registerutils.is_zypper_running')
    @patch('cloudregister.registerutils.write_framework_identifier')
    @patch('cloudregister.registerutils.get_available_smt_servers')
    @patch('os.makedirs')
    @patch('os.path.isdir')
    @patch('time.sleep')
    @patch('cloudregister.registerutils.get_state_dir')
    @patch('cloudregister.registerutils.get_config')
    @patch('cloudregister.registerutils.deregister_non_free_extensions')
    @patch('cloudregister.registerutils.deregister_from_update_infrastructure')
    @patch('cloudregister.registerutils.deregister_from_SCC')
    @patch('cloudregister.registerutils.clean_cache')
    @patch('cloudregister.registerutils.clean_all_standard')
    def test_register_cloud_guest_force_baseprod_extensions_raise(
        self,
        mock_clean_all_standard,
        mock_clean_cache,
        mock_deregister_from_SCC,
        mock_deregister_from_update_infrastructure,
        mock_deregister_non_free_extensions,
        mock_get_config,
        mock_get_state_dir,
        mock_time_sleep,
        mock_os_path_isdir,
        mock_os_makedirs,
        mock_get_available_smt_servers,
        mock_write_framework_id,
        mock_is_zypper_running,
        mock_has_network_access,
        mock_set_new_registration_flag,
        mock_get_current_smt,
        mock_store_smt_data,
        mock_has_region_changed,
        mock_uses_rmt_as_scc_proxy,
        mock_get_instance_data,
        mock_setup_registry,
        mock_setup_ltss_registration,
        mock_smt_is_responsive,
        mock_os_path_exists,
        mock_has_rmt_in_hosts,
        mock_clean_hosts_file,
        mock_add_hosts_entry,
        mock_has_registry_in_hosts,
        mock_update_rmt_cert,
        mock_get_register_cmd,
        mock_os_access,
        mock_set_as_current_smt,
        mock_get_installed_products,
        mock_import_smt_cert,
        mock_register_product,
        mock_set_rmt_as_scc_proxy_flag,
        mock_requests_get,
        mock_get_product_tree,
        mock_get_creds,
        mock_get_creds_file,
        mock_os_unlink,
        mock_set_proxy,
    ):
        smt_data_ipv46 = dedent(
            '''\
            <smtInfo fingerprint="AA:BB:CC:DD"
             SMTserverIP="1.2.3.5"
             SMTserverIPv6="fc00::1"
             SMTserverName="foo-ec2.susecloud.net"
             SMTregistryName="registry-ec2.susecloud.net"
             region="antarctica-1"/>'''
        )

        smt_server = SMT(etree.fromstring(smt_data_ipv46))
        mock_get_current_smt.return_value = smt_server
        fake_args = SimpleNamespace(
            clean_up=False,
            force_new_registration=True,
            user_smt_ip='1.2.3.5',
            user_smt_fqdn='foo-ec2.susecloud.net',
            user_smt_fp='AA:BB:CC:DD',
            email=None,
            reg_code='super_reg_code',
            delay_time=1,
            config_file='config_file',
            debug=True,
        )
        mock_os_path_isdir.return_value = False
        mock_is_zypper_running.return_value = False
        mock_get_available_smt_servers.return_value = []
        mock_has_network_access.return_value = True
        mock_has_region_changed.return_value = True
        mock_uses_rmt_as_scc_proxy.return_value = False
        mock_get_instance_data.return_value = None
        mock_smt_is_responsive.return_value = True
        mock_os_path_exists.side_effect = [True, True, True, True]
        mock_update_rmt_cert.return_value = True
        mock_has_rmt_in_hosts.return_value = False
        mock_has_registry_in_hosts.return_value = False
        mock_os_access.return_value = True
        mock_get_installed_products.return_value = 'SLES-LTSS/15.4/x86_64'
        mock_import_smt_cert.return_value = True
        with tempfile.TemporaryDirectory(suffix='foo') as tdir:
            mock_get_state_dir.return_value = tdir
        prod_reg_type = namedtuple(
            'prod_reg_type', ['returncode', 'output', 'error']
        )
        mock_register_product.side_effect = [
            prod_reg_type(returncode=0, output='all OK', error='stderr'),
            prod_reg_type(
                returncode=6, output='registration code', error='stderr'
            ),
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
                    'name': 'SUSE Linux Enterprise Server LTSS',
                    'identifier': 'SLES-LTSS',
                    'former_identifier': 'SLES-LTSS',
                    'version': '15.4',
                    'release_type': None,
                    'release_stage': 'released',
                    'arch': 'x86_64',
                    'friendly_name': 'SUSE Linux Enterprise Server LTSS 15 SP4 x86_64',
                    'product_class': 'SLES15-SP4-LTSS-X86',
                    'free': False,
                    'repositories': [],
                    'product_type': 'extension',
                    'extensions': [],
                    'recommended': False,
                    'available': True,
                }
            ],
        }
        response.json = json_mock
        mock_requests_get.return_value = response
        mock_get_creds.return_value = 'SCC_foo', 'bar'
        base_product = dedent(
            '''\
            <?xml version="1.0" encoding="UTF-8"?>
            <product schemeversion="0">
              <vendor>SUSE</vendor>
              <name>SLES</name>
              <version>15.4</version>
              <baseversion>15</baseversion>
              <patchlevel>4</patchlevel>
              <release>0</release>
              <endoflife></endoflife>
              <arch>x86_64</arch></product>'''
        )
        mock_get_product_tree.return_value = etree.fromstring(
            base_product[base_product.index('<product') :]
        )
        mock_set_proxy.return_value = False
        mock_get_register_cmd.return_value = '/usr/sbin/SUSEConnect'
        with raises(SystemExit) as sys_exit:
            register_cloud_guest.main(fake_args)
        assert sys_exit.value.code == 6

    @patch('cloudregister.registerutils.set_registration_completed_flag')
    @patch('cloudregister.registerutils.set_proxy')
    @patch('cloudregister.registercloudguest.urllib.parse.urlparse')
    @patch('cloudregister.registerutils.enable_repository')
    @patch('cloudregister.registerutils.exec_subprocess')
    @patch('cloudregister.registerutils.get_repo_url')
    @patch('cloudregister.registerutils.find_repos')
    @patch('cloudregister.registerutils.has_nvidia_support')
    @patch('cloudregister.registercloudguest.registration_returncode', 0)
    @patch('os.unlink')
    @patch('cloudregister.registerutils.get_credentials_file')
    @patch('cloudregister.registerutils.get_credentials')
    @patch('cloudregister.registerutils.get_product_tree')
    @patch('cloudregister.registerutils.requests.get')
    @patch('cloudregister.registerutils.set_rmt_as_scc_proxy_flag')
    @patch('cloudregister.registerutils.register_product')
    @patch('cloudregister.registerutils.import_smt_cert')
    @patch('cloudregister.registerutils.get_installed_products')
    @patch('cloudregister.registerutils.set_as_current_smt')
    @patch('os.access')
    @patch('cloudregister.registerutils.get_register_cmd')
    @patch('cloudregister.registerutils.update_rmt_cert')
    @patch('cloudregister.registerutils.has_registry_in_hosts')
    @patch('cloudregister.registerutils.add_hosts_entry')
    @patch('cloudregister.registerutils.clean_hosts_file')
    @patch('cloudregister.registerutils.has_rmt_in_hosts')
    @patch('cloudregister.registerutils.os.path.exists')
    @patch.object(SMT, 'is_responsive')
    @patch('cloudregister.registercloudguest.setup_ltss_registration')
    @patch('cloudregister.registercloudguest.setup_registry')
    @patch('cloudregister.registerutils.get_instance_data')
    @patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
    @patch('cloudregister.registerutils.has_region_changed')
    @patch('cloudregister.registerutils.store_smt_data')
    @patch('cloudregister.registerutils.get_current_smt')
    @patch('cloudregister.registerutils.set_new_registration_flag')
    @patch('cloudregister.registerutils.has_network_access_by_ip_address')
    @patch('cloudregister.registerutils.is_zypper_running')
    @patch('cloudregister.registerutils.write_framework_identifier')
    @patch('cloudregister.registerutils.get_available_smt_servers')
    @patch('os.makedirs')
    @patch('os.path.isdir')
    @patch('time.sleep')
    @patch('cloudregister.registerutils.get_state_dir')
    @patch('cloudregister.registerutils.get_config')
    @patch('cloudregister.registercloudguest.cleanup')
    def test_register_cloud_baseprod_registration_ok_extensions_ok_complete(
        self,
        mock_cleanup,
        mock_get_config,
        mock_get_state_dir,
        mock_time_sleep,
        mock_os_path_isdir,
        mock_os_makedirs,
        mock_get_available_smt_servers,
        mock_write_framework_id,
        mock_is_zypper_running,
        mock_has_network_access,
        mock_set_new_registration_flag,
        mock_get_current_smt,
        mock_store_smt_data,
        mock_has_region_changed,
        mock_uses_rmt_as_scc_proxy,
        mock_get_instance_data,
        mock_setup_registry,
        mock_setup_ltss_registration,
        mock_smt_is_responsive,
        mock_os_path_exists,
        mock_has_rmt_in_hosts,
        mock_clean_hosts_file,
        mock_add_hosts_entry,
        mock_has_registry_in_hosts,
        mock_update_rmt_cert,
        mock_get_register_cmd,
        mock_os_access,
        mock_set_as_current_smt,
        mock_get_installed_products,
        mock_import_smt_cert,
        mock_register_product,
        mock_set_rmt_as_scc_proxy_flag,
        mock_requests_get,
        mock_get_product_tree,
        mock_get_creds,
        mock_get_creds_file,
        mock_os_unlink,
        mock_has_nvidia_support,
        mock_find_repos,
        mock_get_repo_url,
        mock_exec_subprocess,
        mock_enable_repo,
        mock_urlparse,
        mock_set_proxy,
        mock_set_registration_completed_flag,
    ):
        smt_data_ipv46 = dedent(
            '''\
            <smtInfo fingerprint="AA:BB:CC:DD"
             SMTserverIP="1.2.3.5"
             SMTserverIPv6="fc00::1"
             SMTserverName="foo-ec2.susecloud.net"
             SMTregistryName="registry-ec2.susecloud.net"
             region="antarctica-1"/>'''
        )

        smt_server = SMT(etree.fromstring(smt_data_ipv46))
        mock_get_current_smt.return_value = smt_server
        fake_args = SimpleNamespace(
            clean_up=False,
            force_new_registration=True,
            user_smt_ip='1.2.3.5',
            user_smt_fqdn='foo-ec2.susecloud.net',
            user_smt_fp='AA:BB:CC:DD',
            email=None,
            reg_code='super_reg_code',
            delay_time=1,
            config_file='config_file',
            debug=True,
        )
        mock_os_path_isdir.return_value = False
        mock_is_zypper_running.return_value = False
        mock_get_available_smt_servers.return_value = []
        mock_has_network_access.return_value = True
        mock_has_region_changed.return_value = True
        mock_uses_rmt_as_scc_proxy.return_value = False
        mock_get_instance_data.return_value = None
        mock_smt_is_responsive.return_value = True
        mock_os_path_exists.side_effect = [True, True, True, True]
        mock_update_rmt_cert.return_value = True
        mock_has_rmt_in_hosts.return_value = False
        mock_has_registry_in_hosts.return_value = False
        mock_os_access.return_value = True
        mock_get_installed_products.return_value = 'SLES-LTSS/15.4/x86_64'
        mock_import_smt_cert.return_value = True
        with tempfile.TemporaryDirectory(suffix='foo') as tdir:
            mock_get_state_dir.return_value = tdir
        prod_reg_type = namedtuple(
            'prod_reg_type', ['returncode', 'output', 'error']
        )
        mock_register_product.side_effect = [
            prod_reg_type(returncode=0, output='all OK', error='stderr'),
            prod_reg_type(
                returncode=0, output='registration code', error='stderr'
            ),
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
                    'name': 'SUSE Linux Enterprise Server LTSS',
                    'identifier': 'SLES-LTSS',
                    'former_identifier': 'SLES-LTSS',
                    'version': '15.4',
                    'release_type': None,
                    'release_stage': 'released',
                    'arch': 'x86_64',
                    'friendly_name': 'SUSE Linux Enterprise Server LTSS 15 SP4 x86_64',
                    'product_class': 'SLES15-SP4-LTSS-X86',
                    'free': False,
                    'repositories': [],
                    'product_type': 'extension',
                    'extensions': [],
                    'recommended': False,
                    'available': True,
                }
            ],
        }
        response.json = json_mock
        mock_requests_get.return_value = response
        mock_get_creds.return_value = 'SCC_foo', 'bar'
        base_product = dedent(
            '''\
            <?xml version="1.0" encoding="UTF-8"?>
            <product schemeversion="0">
              <vendor>SUSE</vendor>
              <name>SLES</name>
              <version>15.4</version>
              <baseversion>15</baseversion>
              <patchlevel>4</patchlevel>
              <release>0</release>
              <endoflife></endoflife>
              <arch>x86_64</arch></product>'''
        )
        mock_get_product_tree.return_value = etree.fromstring(
            base_product[base_product.index('<product') :]
        )
        mock_get_register_cmd.return_value = '/usr/sbin/SUSEConnect'
        mock_has_nvidia_support.return_value = True
        mock_find_repos.return_value = ['repo_a', 'repo_b']
        mock_get_repo_url.return_value = (
            'plugin:/susecloud?credentials=Basesystem_Module_x86_64&'
            'path=/repo/SUSE/Updates/SLE-Module-Basesystem/15-SP4/x86_64/update/'
        )
        mock_exec_subprocess.side_effect = [True, False]
        mock_urlparse.return_value = ParseResult(
            scheme='https',
            netloc='susecloud.net:443',
            path='/some/repo',
            params='',
            query='highlight=params',
            fragment='url-parsing',
        )
        mock_set_proxy.return_value = False
        assert register_cloud_guest.main(fake_args) is None
        assert 'Forced new registration' in self._caplog.text
        assert (
            'Using user specified SMT server:\n\n\t"IP:1.2.3.5"\n\t"'
            in self._caplog.text
        )
        assert (
            'Region change detected, registering to new servers'
            in self._caplog.text
        )
        assert (
            'Cannot reach host: "susecloud.net", will not enable repo "repo_a"'
            in self._caplog.text
        )

    @patch('cloudregister.registerutils.set_registration_completed_flag')
    @patch('cloudregister.registerutils.set_proxy')
    @patch('cloudregister.registercloudguest.urllib.parse.urlparse')
    @patch('cloudregister.registerutils.enable_repository')
    @patch('cloudregister.registerutils.exec_subprocess')
    @patch('cloudregister.registerutils.get_repo_url')
    @patch('cloudregister.registerutils.find_repos')
    @patch('cloudregister.registerutils.has_nvidia_support')
    @patch('cloudregister.registercloudguest.registration_returncode', 0)
    @patch('os.unlink')
    @patch('cloudregister.registerutils.get_credentials_file')
    @patch('cloudregister.registerutils.get_credentials')
    @patch('cloudregister.registerutils.get_product_tree')
    @patch('cloudregister.registerutils.requests.get')
    @patch('cloudregister.registerutils.set_rmt_as_scc_proxy_flag')
    @patch('cloudregister.registerutils.register_product')
    @patch('cloudregister.registerutils.import_smt_cert')
    @patch('cloudregister.registerutils.get_installed_products')
    @patch('cloudregister.registerutils.set_as_current_smt')
    @patch('os.access')
    @patch('cloudregister.registerutils.get_register_cmd')
    @patch('cloudregister.registerutils.update_rmt_cert')
    @patch('cloudregister.registerutils.has_registry_in_hosts')
    @patch('cloudregister.registerutils.add_hosts_entry')
    @patch('cloudregister.registerutils.clean_hosts_file')
    @patch('cloudregister.registerutils.has_rmt_in_hosts')
    @patch('cloudregister.registerutils.os.path.exists')
    @patch.object(SMT, 'is_responsive')
    @patch('cloudregister.registercloudguest.setup_ltss_registration')
    @patch('cloudregister.registercloudguest.setup_registry')
    @patch('cloudregister.registerutils.get_instance_data')
    @patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
    @patch('cloudregister.registerutils.has_region_changed')
    @patch('cloudregister.registerutils.store_smt_data')
    @patch('cloudregister.registerutils.get_current_smt')
    @patch('cloudregister.registerutils.set_new_registration_flag')
    @patch('cloudregister.registerutils.has_network_access_by_ip_address')
    @patch('cloudregister.registerutils.is_zypper_running')
    @patch('cloudregister.registerutils.write_framework_identifier')
    @patch('cloudregister.registerutils.get_available_smt_servers')
    @patch('os.makedirs')
    @patch('os.path.isdir')
    @patch('time.sleep')
    @patch('cloudregister.registerutils.get_state_dir')
    @patch('cloudregister.registerutils.get_config')
    @patch('cloudregister.registercloudguest.cleanup')
    def test_register_cloud_baseprod_ok_recommended_extensions_ok_complete(
        self,
        mock_cleanup,
        mock_get_config,
        mock_get_state_dir,
        mock_time_sleep,
        mock_os_path_isdir,
        mock_os_makedirs,
        mock_get_available_smt_servers,
        mock_write_framework_id,
        mock_is_zypper_running,
        mock_has_network_access,
        mock_set_new_registration_flag,
        mock_get_current_smt,
        mock_store_smt_data,
        mock_has_region_changed,
        mock_uses_rmt_as_scc_proxy,
        mock_get_instance_data,
        mock_setup_registry,
        mock_setup_ltss_registration,
        mock_smt_is_responsive,
        mock_os_path_exists,
        mock_has_rmt_in_hosts,
        mock_clean_hosts_file,
        mock_add_hosts_entry,
        mock_has_registry_in_hosts,
        mock_update_rmt_cert,
        mock_get_register_cmd,
        mock_os_access,
        mock_set_as_current_smt,
        mock_get_installed_products,
        mock_import_smt_cert,
        mock_register_product,
        mock_set_rmt_as_scc_proxy_flag,
        mock_requests_get,
        mock_get_product_tree,
        mock_get_creds,
        mock_get_creds_file,
        mock_os_unlink,
        mock_has_nvidia_support,
        mock_find_repos,
        mock_get_repo_url,
        mock_exec_subprocess,
        mock_enable_repo,
        mock_urlparse,
        mock_set_proxy,
        mock_set_registration_completed_flag,
    ):
        smt_data_ipv46 = dedent(
            '''\
            <smtInfo fingerprint="AA:BB:CC:DD"
             SMTserverIP="1.2.3.5"
             SMTserverIPv6="fc00::1"
             SMTserverName="foo-ec2.susecloud.net"
             SMTregistryName="registry-ec2.susecloud.net"
             region="antarctica-1"/>'''
        )
        smt_server = SMT(etree.fromstring(smt_data_ipv46))
        mock_get_current_smt.return_value = smt_server
        fake_args = SimpleNamespace(
            clean_up=False,
            force_new_registration=True,
            user_smt_ip='fc00::1',
            user_smt_fqdn='foo-ec2.susecloud.net',
            user_smt_fp='AA:BB:CC:DD',
            email=None,
            reg_code='super_reg_code',
            delay_time=1,
            config_file='config_file',
            debug=True,
        )
        mock_os_path_isdir.return_value = False
        mock_is_zypper_running.return_value = False
        mock_get_available_smt_servers.return_value = []
        mock_has_network_access.return_value = True
        mock_has_region_changed.return_value = True
        mock_uses_rmt_as_scc_proxy.return_value = False
        mock_get_instance_data.return_value = None
        mock_smt_is_responsive.return_value = True
        mock_os_path_exists.side_effect = [True, True, True, True]
        mock_update_rmt_cert.return_value = True
        mock_has_rmt_in_hosts.return_value = False
        mock_has_registry_in_hosts.return_value = False
        mock_os_access.return_value = True
        mock_get_installed_products.return_value = 'SLES-LTSS/15.4/x86_64'
        mock_import_smt_cert.return_value = True
        with tempfile.TemporaryDirectory(suffix='foo') as tdir:
            mock_get_state_dir.return_value = tdir
        prod_reg_type = namedtuple(
            'prod_reg_type', ['returncode', 'output', 'error']
        )
        mock_register_product.side_effect = [
            prod_reg_type(returncode=0, output='all OK', error='stderr'),
            prod_reg_type(
                returncode=0, output='registration code', error='stderr'
            ),
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
                    'name': 'SUSE Linux Enterprise Server LTSS',
                    'identifier': 'SLES-LTSS',
                    'former_identifier': 'SLES-LTSS',
                    'version': '15.4',
                    'release_type': None,
                    'release_stage': 'released',
                    'arch': 'x86_64',
                    'friendly_name': 'SUSE Linux Enterprise Server LTSS 15 SP4 x86_64',
                    'product_class': 'SLES15-SP4-LTSS-X86',
                    'free': False,
                    'repositories': [],
                    'product_type': 'extension',
                    'extensions': [],
                    'recommended': True,
                    'available': True,
                }
            ],
        }
        response.json = json_mock
        mock_requests_get.return_value = response
        mock_get_creds.return_value = 'SCC_foo', 'bar'
        base_product = dedent(
            '''\
            <?xml version="1.0" encoding="UTF-8"?>
            <product schemeversion="0">
              <vendor>SUSE</vendor>
              <name>SLES</name>
              <version>15.4</version>
              <baseversion>15</baseversion>
              <patchlevel>4</patchlevel>
              <release>0</release>
              <endoflife></endoflife>
              <arch>x86_64</arch></product>'''
        )
        mock_get_product_tree.return_value = etree.fromstring(
            base_product[base_product.index('<product') :]
        )
        mock_get_register_cmd.return_value = '/usr/sbin/SUSEConnect'
        mock_has_nvidia_support.return_value = True
        mock_find_repos.return_value = ['repo_a', 'repo_b']
        mock_get_repo_url.return_value = (
            'plugin:/susecloud?credentials=Basesystem_Module_x86_64&'
            'path=/repo/SUSE/Updates/SLE-Module-Basesystem/15-SP4/x86_64/update/'
        )
        mock_exec_subprocess.side_effect = [True, False]
        mock_urlparse.return_value = ParseResult(
            scheme='https',
            netloc='susecloud.net:443',
            path='/some/repo',
            params='',
            query='highlight=params',
            fragment='url-parsing',
        )
        mock_set_proxy.return_value = False
        assert register_cloud_guest.main(fake_args) is None
        assert 'Forced new registration' in self._caplog.text
        assert (
            'Using user specified SMT server:\n\n\t"IP:fc00::1"\n\t"'
            in self._caplog.text
        )
        assert (
            'Region change detected, registering to new servers'
            in self._caplog.text
        )
        assert (
            'Cannot reach host: "susecloud.net", will not enable repo "repo_a"'
            in self._caplog.text
        )

    @patch('cloudregister.registerutils._remove_state_file')
    @patch('cloudregister.registerutils.set_registration_completed_flag')
    @patch('os.system')
    @patch('cloudregister.registerutils.set_proxy')
    @patch('cloudregister.registercloudguest.urllib.parse.urlparse')
    @patch('cloudregister.registerutils.enable_repository')
    @patch('cloudregister.registerutils.exec_subprocess')
    @patch('cloudregister.registerutils.get_repo_url')
    @patch('cloudregister.registerutils.find_repos')
    @patch('cloudregister.registerutils.has_nvidia_support')
    @patch('cloudregister.registercloudguest.registration_returncode', 0)
    @patch('os.unlink')
    @patch('cloudregister.registerutils.get_credentials_file')
    @patch('cloudregister.registerutils.get_credentials')
    @patch('cloudregister.registerutils.get_product_tree')
    @patch('cloudregister.registerutils.requests.get')
    @patch('cloudregister.registerutils.set_rmt_as_scc_proxy_flag')
    @patch('cloudregister.registerutils.register_product')
    @patch('cloudregister.registerutils.import_smt_cert')
    @patch('cloudregister.registerutils.get_installed_products')
    @patch('cloudregister.registerutils.set_as_current_smt')
    @patch('os.access')
    @patch('cloudregister.registerutils.get_register_cmd')
    @patch('cloudregister.registerutils.update_rmt_cert')
    @patch('cloudregister.registerutils.has_registry_in_hosts')
    @patch('cloudregister.registerutils.add_hosts_entry')
    @patch('cloudregister.registerutils.clean_hosts_file')
    @patch('cloudregister.registerutils.has_rmt_in_hosts')
    @patch('cloudregister.registerutils.os.path.exists')
    @patch.object(SMT, 'is_responsive')
    @patch('cloudregister.registercloudguest.setup_ltss_registration')
    @patch('cloudregister.registercloudguest.setup_registry')
    @patch('cloudregister.registerutils.get_instance_data')
    @patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
    @patch('cloudregister.registerutils.has_region_changed')
    @patch('cloudregister.registerutils.store_smt_data')
    @patch('cloudregister.registerutils.get_current_smt')
    @patch('cloudregister.registerutils.set_new_registration_flag')
    @patch('cloudregister.registerutils.has_network_access_by_ip_address')
    @patch('cloudregister.registerutils.is_zypper_running')
    @patch('cloudregister.registerutils.write_framework_identifier')
    @patch('cloudregister.registerutils.get_available_smt_servers')
    @patch('os.makedirs')
    @patch('os.path.isdir')
    @patch('time.sleep')
    @patch('cloudregister.registerutils.get_state_dir')
    @patch('cloudregister.registerutils.get_config')
    @patch('cloudregister.registercloudguest.cleanup')
    def test_reg_cloud_baseprod_ok_recommended_extensions_failed_is_transactional(
        self,
        mock_cleanup,
        mock_get_config,
        mock_get_state_dir,
        mock_time_sleep,
        mock_os_path_isdir,
        mock_os_makedirs,
        mock_get_available_smt_servers,
        mock_write_framework_id,
        mock_is_zypper_running,
        mock_has_network_access,
        mock_set_new_registration_flag,
        mock_get_current_smt,
        mock_store_smt_data,
        mock_has_region_changed,
        mock_uses_rmt_as_scc_proxy,
        mock_get_instance_data,
        mock_setup_registry,
        mock_setup_ltss_registration,
        mock_smt_is_responsive,
        mock_os_path_exists,
        mock_has_rmt_in_hosts,
        mock_clean_hosts_file,
        mock_add_hosts_entry,
        mock_has_registry_in_hosts,
        mock_update_rmt_cert,
        mock_get_register_cmd,
        mock_os_access,
        mock_set_as_current_smt,
        mock_get_installed_products,
        mock_import_smt_cert,
        mock_register_product,
        mock_set_rmt_as_scc_proxy_flag,
        mock_requests_get,
        mock_get_product_tree,
        mock_get_creds,
        mock_get_creds_file,
        mock_os_unlink,
        mock_has_nvidia_support,
        mock_find_repos,
        mock_get_repo_url,
        mock_exec_subprocess,
        mock_enable_repo,
        mock_urlparse,
        mock_set_proxy,
        mock_os_system,
        mock_set_registration_completed_flag,
        mock_remove_state_file,
    ):
        smt_data_ipv46 = dedent(
            '''\
            <smtInfo fingerprint="AA:BB:CC:DD"
             SMTserverIP="1.2.3.5"
             SMTserverIPv6="fc00::1"
             SMTserverName="foo-ec2.susecloud.net"
             SMTregistryName="registry-ec2.susecloud.net"
             region="antarctica-1"/>'''
        )
        smt_server = SMT(etree.fromstring(smt_data_ipv46))
        mock_get_current_smt.return_value = smt_server
        fake_args = SimpleNamespace(
            clean_up=False,
            force_new_registration=True,
            user_smt_ip='fc00::1',
            user_smt_fqdn='foo-ec2.susecloud.net',
            user_smt_fp='AA:BB:CC:DD',
            email=None,
            reg_code='super_reg_code',
            delay_time=1,
            config_file='config_file',
            debug=True,
        )
        mock_os_path_isdir.return_value = False
        mock_is_zypper_running.return_value = False
        mock_get_available_smt_servers.return_value = []
        mock_has_network_access.return_value = True
        mock_has_region_changed.return_value = True
        mock_uses_rmt_as_scc_proxy.return_value = False
        mock_get_instance_data.return_value = None
        mock_smt_is_responsive.return_value = True
        mock_os_path_exists.side_effect = [False, True, True, True]
        mock_update_rmt_cert.return_value = True
        mock_has_rmt_in_hosts.return_value = False
        mock_has_registry_in_hosts.return_value = False
        mock_os_access.return_value = True
        mock_get_installed_products.return_value = 'SLES-LTSS-FOO/15.4/x86_64'
        mock_import_smt_cert.return_value = True
        mock_remove_state_file.return_value = True
        with tempfile.TemporaryDirectory(suffix='foo') as tdir:
            mock_get_state_dir.return_value = tdir
        prod_reg_type = namedtuple(
            'prod_reg_type', ['returncode', 'output', 'error']
        )
        mock_register_product.side_effect = [
            prod_reg_type(returncode=0, output='all OK', error='stderr'),
            prod_reg_type(
                returncode=67, output='registration code', error='stderr'
            ),
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
                    'name': 'SUSE Linux Enterprise Server LTSS Foo',
                    'identifier': 'SLES-LTSS-FOO',
                    'former_identifier': 'SLES-LTSS-FOO',
                    'version': '15.4',
                    'release_type': None,
                    'release_stage': 'released',
                    'arch': 'x86_64',
                    'friendly_name': 'SUSE Linux Enterprise Server LTSS 15 SP4 x86_64',
                    'product_class': 'SLES15-SP4-LTSS-FOO-X86',
                    'free': False,
                    'repositories': [],
                    'product_type': 'extension',
                    'extensions': [],
                    'recommended': False,
                    'available': True,
                }
            ],
        }
        response.json = json_mock
        mock_requests_get.return_value = response
        mock_get_creds.return_value = 'SCC_foo', 'bar'
        base_product = dedent(
            '''\
            <?xml version="1.0" encoding="UTF-8"?>
            <product schemeversion="0">
              <vendor>SUSE</vendor>
              <name>SLES</name>
              <version>15.4</version>
              <baseversion>15</baseversion>
              <patchlevel>4</patchlevel>
              <release>0</release>
              <endoflife></endoflife>
              <arch>x86_64</arch></product>'''
        )
        mock_get_product_tree.return_value = etree.fromstring(
            base_product[base_product.index('<product') :]
        )
        mock_get_register_cmd.return_value = '/usr/sbin/SUSEConnect'
        mock_has_nvidia_support.return_value = False
        mock_find_repos.return_value = ['repo_a', 'repo_b']
        mock_get_repo_url.return_value = (
            'plugin:/susecloud?credentials=Basesystem_Module_x86_64&'
            'path=/repo/SUSE/Updates/SLE-Module-Basesystem/15-SP4/x86_64/update/'
        )
        findmnt_return = (
            b'{"filesystems": [{"target": "/","source": '
            + b'"/dev/sda3","fstype": "xfs","options": "ro"}]}'
        )
        mock_exec_subprocess.return_value = findmnt_return, b'', 0
        mock_os_path_exists.reset_mock()
        mock_os_path_exists.return_value = True
        mock_urlparse.return_value = ParseResult(
            scheme='https',
            netloc='susecloud.net:443',
            path='/some/repo',
            params='',
            query='highlight=params',
            fragment='url-parsing',
        )
        mock_set_proxy.return_value = False

        assert register_cloud_guest.main(fake_args) is None

        assert 'Registration succeeded' in self._caplog.text
        assert (
            'There are products that were not registered' in self._caplog.text
        )
        assert 'transactional-update register -p' in self._caplog.text
        assert 'SLES-LTSS-FOO/15.4/x86_64' in self._caplog.text
        assert '-r ADDITIONAL REGCODE' in self._caplog.text

    @patch('cloudregister.registerutils.set_proxy')
    @patch('cloudregister.registercloudguest.get_responding_update_server')
    @patch('cloudregister.registerutils.is_registration_supported')
    @patch('cloudregister.registerutils.fetch_smt_data')
    @patch('cloudregister.registercloudguest.urllib.parse.urlparse')
    @patch('cloudregister.registerutils.enable_repository')
    @patch('cloudregister.registerutils.exec_subprocess')
    @patch('cloudregister.registerutils.get_repo_url')
    @patch('cloudregister.registerutils.find_repos')
    @patch('cloudregister.registerutils.has_nvidia_support')
    @patch('cloudregister.registercloudguest.registration_returncode', 0)
    @patch('os.unlink')
    @patch('cloudregister.registerutils.get_credentials_file')
    @patch('cloudregister.registerutils.get_credentials')
    @patch('cloudregister.registerutils.get_product_tree')
    @patch('cloudregister.registerutils.requests.get')
    @patch('cloudregister.registerutils.set_rmt_as_scc_proxy_flag')
    @patch('cloudregister.registerutils.register_product')
    @patch('cloudregister.registerutils.import_smt_cert')
    @patch('cloudregister.registerutils.get_installed_products')
    @patch('cloudregister.registerutils.set_as_current_smt')
    @patch('os.access')
    @patch('cloudregister.registerutils.get_register_cmd')
    @patch('cloudregister.registerutils.update_rmt_cert')
    @patch('cloudregister.registerutils.has_registry_in_hosts')
    @patch('cloudregister.registerutils.add_hosts_entry')
    @patch('cloudregister.registerutils.clean_hosts_file')
    @patch('cloudregister.registerutils.has_rmt_in_hosts')
    @patch('cloudregister.registerutils.os.path.exists')
    @patch.object(SMT, 'is_responsive')
    @patch('cloudregister.registercloudguest.setup_ltss_registration')
    @patch('cloudregister.registercloudguest.setup_registry')
    @patch('cloudregister.registerutils.get_instance_data')
    @patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
    @patch('cloudregister.registerutils.has_region_changed')
    @patch('cloudregister.registerutils.store_smt_data')
    @patch('cloudregister.registerutils.get_current_smt')
    @patch('cloudregister.registerutils.set_new_registration_flag')
    @patch('cloudregister.registerutils.has_network_access_by_ip_address')
    @patch('cloudregister.registerutils.is_zypper_running')
    @patch('cloudregister.registerutils.write_framework_identifier')
    @patch('cloudregister.registerutils.get_available_smt_servers')
    @patch('os.makedirs')
    @patch('os.path.isdir')
    @patch('time.sleep')
    @patch('cloudregister.registerutils.get_state_dir')
    @patch('cloudregister.registerutils.get_config')
    @patch('cloudregister.registercloudguest.cleanup')
    def test_register_cloud_baseprod_ok_recommended_extensions_ok_complete_no_ip(
        self,
        mock_cleanup,
        mock_get_config,
        mock_get_state_dir,
        mock_time_sleep,
        mock_os_path_isdir,
        mock_os_makedirs,
        mock_get_available_smt_servers,
        mock_write_framework_id,
        mock_is_zypper_running,
        mock_has_network_access,
        mock_set_new_registration_flag,
        mock_get_current_smt,
        mock_store_smt_data,
        mock_has_region_changed,
        mock_uses_rmt_as_scc_proxy,
        mock_get_instance_data,
        mock_setup_registry,
        mock_setup_ltss_registration,
        mock_smt_is_responsive,
        mock_os_path_exists,
        mock_has_rmt_in_hosts,
        mock_clean_hosts_file,
        mock_add_hosts_entry,
        mock_has_registry_in_hosts,
        mock_update_rmt_cert,
        mock_get_register_cmd,
        mock_os_access,
        mock_set_as_current_smt,
        mock_get_installed_products,
        mock_import_smt_cert,
        mock_register_product,
        mock_set_rmt_as_scc_proxy_flag,
        mock_requests_get,
        mock_get_product_tree,
        mock_get_creds,
        mock_get_creds_file,
        mock_os_unlink,
        mock_has_nvidia_support,
        mock_find_repos,
        mock_get_repo_url,
        mock_exec_subprocess,
        mock_enable_repo,
        mock_urlparse,
        mock_fetch_smt_data,
        mock_is_reg_supported,
        mock_get_responding_update_server,
        mock_set_proxy,
    ):
        mock_set_proxy.return_value = False
        smt_data_ipv46 = dedent(
            '''\
            <smtInfo fingerprint="AA:BB:CC:DD"
             SMTserverIP="1.2.3.5"
             SMTserverIPv6="fc00::1"
             SMTserverName="foo-ec2.susecloud.net"
             SMTregistryName="registry-ec2.susecloud.net"
             region="antarctica-1"/>'''
        )
        smt_server = SMT(etree.fromstring(smt_data_ipv46))
        mock_fetch_smt_data.return_value = etree.fromstring(smt_data_ipv46)
        mock_get_current_smt.return_value = smt_server
        fake_args = SimpleNamespace(
            clean_up=False,
            force_new_registration=True,
            email=None,
            user_smt_ip=None,
            user_smt_fqdn=None,
            user_smt_fp=None,
            reg_code='super_reg_code',
            delay_time=1,
            config_file='config_file',
            debug=True,
        )
        mock_is_reg_supported.return_value = False
        mock_os_path_isdir.return_value = False
        mock_is_zypper_running.return_value = False
        mock_get_available_smt_servers.return_value = []
        mock_has_network_access.return_value = True
        mock_has_region_changed.return_value = True
        mock_uses_rmt_as_scc_proxy.return_value = False
        mock_get_instance_data.return_value = True
        mock_smt_is_responsive.return_value = True
        mock_os_path_exists.side_effect = [True, False, True, True, True]
        mock_update_rmt_cert.return_value = True
        mock_has_rmt_in_hosts.return_value = False
        mock_has_registry_in_hosts.return_value = False
        mock_os_access.return_value = True
        mock_get_installed_products.return_value = 'SLES-LTSS/15.4/x86_64'
        mock_import_smt_cert.return_value = True
        with tempfile.TemporaryDirectory(suffix='foo') as tdir:
            mock_get_state_dir.return_value = tdir
        prod_reg_type = namedtuple(
            'prod_reg_type', ['returncode', 'output', 'error']
        )
        mock_register_product.side_effect = [
            prod_reg_type(returncode=0, output='all OK', error='stderr'),
            prod_reg_type(
                returncode=0, output='registration code', error='stderr'
            ),
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
                    'name': 'SUSE Linux Enterprise Server LTSS',
                    'identifier': 'SLES-LTSS',
                    'former_identifier': 'SLES-LTSS',
                    'version': '15.4',
                    'release_type': None,
                    'release_stage': 'released',
                    'arch': 'x86_64',
                    'friendly_name': 'SUSE Linux Enterprise Server LTSS 15 SP4 x86_64',
                    'product_class': 'SLES15-SP4-LTSS-X86',
                    'free': False,
                    'repositories': [],
                    'product_type': 'extension',
                    'extensions': [],
                    'recommended': True,
                    'available': True,
                }
            ],
        }
        response.json = json_mock
        mock_requests_get.return_value = response
        mock_get_creds.return_value = 'SCC_foo', 'bar'
        base_product = dedent(
            '''\
            <?xml version="1.0" encoding="UTF-8"?>
            <product schemeversion="0">
              <vendor>SUSE</vendor>
              <name>SLES</name>
              <version>15.4</version>
              <baseversion>15</baseversion>
              <patchlevel>4</patchlevel>
              <release>0</release>
              <endoflife></endoflife>
              <arch>x86_64</arch></product>'''
        )
        mock_get_product_tree.return_value = etree.fromstring(
            base_product[base_product.index('<product') :]
        )
        mock_get_register_cmd.return_value = '/usr/sbin/SUSEConnect'
        mock_has_nvidia_support.return_value = True
        mock_find_repos.return_value = ['repo_a', 'repo_b']
        mock_get_repo_url.return_value = (
            'plugin:/susecloud?credentials=Basesystem_Module_x86_64&'
            'path=/repo/SUSE/Updates/SLE-Module-Basesystem/15-SP4/x86_64/update/'
        )
        mock_exec_subprocess.side_effect = [True, False]
        mock_urlparse.return_value = ParseResult(
            scheme='https',
            netloc='susecloud.net:443',
            path='/some/repo',
            params='',
            query='highlight=params',
            fragment='url-parsing',
        )
        with raises(SystemExit) as sys_exit:
            with patch('builtins.open', mock_open()):
                register_cloud_guest.main(fake_args)
        assert sys_exit.value.code == 0
        assert (
            'Region change detected, registering to new servers'
            in self._caplog.text
        )

    @patch('cloudregister.registerutils.register_product')
    def test_register_modules(self, mock_register_product):
        prod_reg_type = namedtuple(
            'prod_reg_type', ['returncode', 'output', 'error']
        )

        mock_register_product.return_value = prod_reg_type(
            returncode=67, output='registration code', error='stderr'
        )
        extensions = [
            {
                'id': 23,
                'name': 'SUSE Linux Enterprise Server LTSS',
                'identifier': 'SLES-LTSS',
                'former_identifier': 'SLES-LTSS',
                'version': '15.4',
                'release_type': None,
                'release_stage': 'released',
                'arch': 'x86_64',
                'friendly_name': 'SUSE Linux Enterprise Server LTSS 15 SP4 x86_64',
                'product_class': 'SLES15-SP4-LTSS-X86',
                'free': False,
                'repositories': [],
                'product_type': 'extension',
                'extensions': [],
                'recommended': False,
                'available': True,
            }
        ]
        register_cloud_guest.register_modules(
            extensions, ['SLES-LTSS/15.4/x86_64'], 'reg_target', 'path', [], []
        )

    @patch('cloudregister.registerutils.register_product')
    def test_register_modules_failed_credentials(self, mock_register_product):
        prod_reg_type = namedtuple(
            'prod_reg_type', ['returncode', 'output', 'error']
        )

        mock_register_product.return_value = prod_reg_type(
            returncode=67,
            output='',
            error='missing system credentials try again',
        )
        extensions = [
            {
                'id': 23,
                'name': 'SUSE Linux Enterprise Server LTSS',
                'identifier': 'SLES-LTSS',
                'former_identifier': 'SLES-LTSS',
                'version': '15.4',
                'release_type': None,
                'release_stage': 'released',
                'arch': 'x86_64',
                'friendly_name': 'SUSE Linux Enterprise Server LTSS 15 SP4 x86_64',
                'product_class': 'SLES15-SP4-LTSS-X86',
                'free': False,
                'repositories': [],
                'product_type': 'extension',
                'extensions': [],
                'recommended': False,
                'available': True,
            }
        ]
        register_cloud_guest.register_modules(
            extensions, ['SLES-LTSS/15.4/x86_64'], 'reg_target', 'path', [], []
        )

    @patch('cloudregister.registerutils.is_registry_registered')
    @patch('cloudregister.registerutils.get_credentials_file')
    @patch('cloudregister.registerutils.get_credentials')
    @patch('cloudregister.registerutils.set_registries_conf_docker')
    @patch('os.path.exists')
    def test_setup_registry_registered(
        self,
        mock_os_path_exists,
        mock_set_registries_conf_docker,
        mock_get_credentials,
        mock_get_credentials_file,
        mock_is_registry_registered,
    ):
        mock_os_path_exists.return_value = True
        mock_set_registries_conf_docker.return_value = False
        smt_data_ipv46 = dedent(
            '''\
            <smtInfo fingerprint="AA:BB:CC:DD"
             SMTserverIP="1.2.3.5"
             SMTserverIPv6="fc00::1"
             SMTserverName="foo-ec2.susecloud.net"
             SMTregistryName="registry-ec2.susecloud.net"
             region="antarctica-1"/>'''
        )
        smt_server = SMT(etree.fromstring(smt_data_ipv46))
        mock_get_credentials.return_value = 'foo', 'bar'
        mock_is_registry_registered.return_value = True
        with patch('sys.exit'):
            register_cloud_guest.setup_registry(smt_server)
        mock_set_registries_conf_docker.assert_called_once_with(
            'registry-ec2.susecloud.net'
        )
        mock_set_registries_conf_docker.return_value = True
        mock_set_registries_conf_docker.reset_mock()
        register_cloud_guest.setup_registry(smt_server)
        mock_set_registries_conf_docker.assert_called_once_with(
            'registry-ec2.susecloud.net'
        )

    @patch('cloudregister.registerutils.clean_registry_setup')
    @patch('cloudregister.registerutils.prepare_registry_setup')
    @patch('cloudregister.registerutils.is_registry_registered')
    @patch('cloudregister.registerutils.get_credentials_file')
    @patch('cloudregister.registerutils.get_credentials')
    def test_setup_clean_registry(
        self,
        mock_get_credentials,
        mock_get_credentials_file,
        mock_is_registry_registered,
        mock_prepare_registry_setup,
        mock_clean_registry_setup,
    ):
        smt_data_ipv46 = dedent(
            '''\
            <smtInfo fingerprint="AA:BB:CC:DD"
             SMTserverIP="1.2.3.5"
             SMTserverIPv6="fc00::1"
             SMTserverName="foo-ec2.susecloud.net"
             SMTregistryName="registry-ec2.susecloud.net"
             region="antarctica-1"/>'''
        )
        smt_server = SMT(etree.fromstring(smt_data_ipv46))
        mock_get_credentials.return_value = 'foo', 'bar'
        mock_is_registry_registered.return_value = False
        mock_prepare_registry_setup.return_value = False
        assert register_cloud_guest.setup_registry(smt_server) is False

    @patch('cloudregister.registerutils.prepare_registry_setup')
    @patch('cloudregister.registerutils.set_registries_conf_podman')
    @patch('cloudregister.registerutils.set_registries_conf_docker')
    @patch('cloudregister.registerutils.set_registry_fqdn_suma')
    @patch('cloudregister.registerutils.is_suma_instance')
    @patch('cloudregister.registerutils.is_registry_registered')
    @patch('cloudregister.registerutils.get_credentials_file')
    @patch('cloudregister.registerutils.get_credentials')
    @patch('cloudregister.registerutils.is_docker_present')
    def test_setup_registry_ok(
        self,
        mock_is_docker_present,
        mock_get_credentials,
        mock_get_credentials_file,
        mock_is_registry_registered,
        mock_is_suma_instance,
        mock_set_registry_fqdn_suma,
        mock_set_registries_conf_docker,
        mock_set_registries_conf_podman,
        mock_prepare_registry_setup,
    ):
        mock_is_docker_present.return_value = True
        mock_is_suma_instance.return_value = True
        smt_data_ipv46 = dedent(
            '''\
            <smtInfo fingerprint="AA:BB:CC:DD"
             SMTserverIP="1.2.3.5"
             SMTserverIPv6="fc00::1"
             SMTserverName="foo-ec2.susecloud.net"
             SMTregistryName="registry-ec2.susecloud.net"
             region="antarctica-1"/>'''
        )
        smt_server = SMT(etree.fromstring(smt_data_ipv46))
        mock_get_credentials.return_value = 'foo', 'bar'
        mock_is_registry_registered.return_value = False
        mock_prepare_registry_setup.return_value = True
        mock_set_registries_conf_podman.return_value = True
        mock_set_registries_conf_docker.return_value = True
        mock_set_registry_fqdn_suma.return_value = True
        assert register_cloud_guest.setup_registry(smt_server) is True
        mock_set_registries_conf_podman.assert_called_once_with(
            'registry-ec2.susecloud.net'
        )
        mock_set_registries_conf_docker.assert_called_once_with(
            'registry-ec2.susecloud.net'
        )
        mock_set_registry_fqdn_suma.assert_called_once_with(
            'registry-ec2.susecloud.net'
        )

    @patch('cloudregister.registerutils.prepare_registry_setup')
    @patch('cloudregister.registerutils.set_registries_conf_podman')
    @patch('cloudregister.registerutils.set_registries_conf_docker')
    @patch('cloudregister.registerutils.set_registry_fqdn_suma')
    @patch('cloudregister.registerutils.is_suma_instance')
    @patch('cloudregister.registerutils.is_registry_registered')
    @patch('cloudregister.registerutils.get_credentials_file')
    @patch('cloudregister.registerutils.get_credentials')
    @patch('cloudregister.registerutils.is_docker_present')
    def test_setup_registry_ok_without_docker(
        self,
        mock_is_docker_present,
        mock_get_credentials,
        mock_get_credentials_file,
        mock_is_registry_registered,
        mock_is_suma_instance,
        mock_set_registry_fqdn_suma,
        mock_set_registries_conf_docker,
        mock_set_registries_conf_podman,
        mock_prepare_registry_setup,
    ):
        mock_is_docker_present.return_value = False
        mock_is_suma_instance.return_value = True
        smt_data_ipv46 = dedent(
            '''\
            <smtInfo fingerprint="AA:BB:CC:DD"
             SMTserverIP="1.2.3.5"
             SMTserverIPv6="fc00::1"
             SMTserverName="foo-ec2.susecloud.net"
             SMTregistryName="registry-ec2.susecloud.net"
             region="antarctica-1"/>'''
        )
        smt_server = SMT(etree.fromstring(smt_data_ipv46))
        mock_get_credentials.return_value = 'foo', 'bar'
        mock_is_registry_registered.return_value = False
        mock_prepare_registry_setup.return_value = True
        mock_set_registries_conf_podman.return_value = True
        mock_set_registry_fqdn_suma.return_value = True
        assert register_cloud_guest.setup_registry(smt_server) is True
        assert not mock_set_registries_conf_docker.called

    def test_get_responding_update_server_error(self):
        with raises(SystemExit) as sys_exit:
            assert register_cloud_guest.get_responding_update_server([])
        assert sys_exit.value.code == 1
        assert 'No response from: []' in self._caplog.text

    @patch('cloudregister.registerutils.get_product_tree')
    def test_setup_ltss_registration_no_product(self, mock_get_product_tree):
        mock_get_product_tree.return_value = None
        with raises(SystemExit) as sys_exit:
            register_cloud_guest.setup_ltss_registration(
                'target', 'regcode', 'instance_filepath'
            )
        assert sys_exit.value.code == 1
        assert (
            'Cannot find baseproduct registration for LTSS' in self._caplog.text
        )

    @patch('os.listdir')
    @patch('os.path.isdir')
    @patch('cloudregister.registerutils.get_product_tree')
    def test_setup_ltss_registration_registered(
        self, mock_get_product_tree, mock_os_path_isdir, mock_os_listdir
    ):
        mock_get_product_tree.return_value = True
        mock_os_path_isdir.return_value = True
        mock_os_listdir.return_value = ['LTSS']
        assert (
            register_cloud_guest.setup_ltss_registration(
                'target', 'regcode', 'instance_filepath'
            )
            is None
        )
        assert 'Running LTSS registration...' in self._caplog.text
        assert 'LTSS registration succeeded' in self._caplog.text

    @patch('cloudregister.registerutils.register_product')
    @patch('os.listdir')
    @patch('os.path.isdir')
    @patch('cloudregister.registerutils.get_product_tree')
    def test_setup_ltss_registration_registration_ok(
        self,
        mock_get_product_tree,
        mock_os_path_isdir,
        mock_os_listdir,
        mock_register_product,
    ):
        mock_os_path_isdir.return_value = True
        mock_os_listdir.return_value = ['foo']
        base_product = dedent(
            '''\
            <?xml version="1.0" encoding="UTF-8"?>
            <product schemeversion="0">
              <vendor>SUSE</vendor>
              <name>SLES</name>
              <version>15.4</version>
              <baseversion>15</baseversion>
              <patchlevel>4</patchlevel>
              <release>0</release>
              <endoflife></endoflife>
              <arch>x86_64</arch></product>'''
        )
        mock_get_product_tree.return_value = etree.fromstring(
            base_product[base_product.index('<product') :]
        )
        prod_reg_type = namedtuple(
            'prod_reg_type', ['returncode', 'output', 'error']
        )
        mock_register_product.return_value = prod_reg_type(
            returncode=0, output='all OK', error='stderr'
        )
        assert (
            register_cloud_guest.setup_ltss_registration(
                'target', 'regcode', 'instance_filepath'
            )
            is None
        )
        assert 'Running LTSS registration...' in self._caplog.text
        assert 'LTSS registration succeeded' in self._caplog.text

    @patch('cloudregister.registerutils.register_product')
    @patch('os.listdir')
    @patch('os.path.isdir')
    @patch('cloudregister.registerutils.get_product_tree')
    def test_setup_ltss_registration_registration_failed(
        self,
        mock_get_product_tree,
        mock_os_path_isdir,
        mock_os_listdir,
        mock_register_product,
    ):
        mock_os_path_isdir.return_value = True
        mock_os_listdir.return_value = ['foo']
        base_product = dedent(
            '''\
            <?xml version="1.0" encoding="UTF-8"?>
            <product schemeversion="0">
              <vendor>SUSE</vendor>
              <name>SLES</name>
              <version>15.4</version>
              <baseversion>15</baseversion>
              <patchlevel>4</patchlevel>
              <release>0</release>
              <endoflife></endoflife>
              <arch>x86_64</arch></product>'''
        )
        mock_get_product_tree.return_value = etree.fromstring(
            base_product[base_product.index('<product') :]
        )
        prod_reg_type = namedtuple(
            'prod_reg_type', ['returncode', 'output', 'error']
        )
        mock_register_product.return_value = prod_reg_type(
            returncode=7, output='not OK', error='stderr'
        )
        with raises(SystemExit) as sys_exit:
            register_cloud_guest.setup_ltss_registration(
                'target', 'regcode', 'instance_filepath'
            )
        assert sys_exit.value.code == 1
        assert 'LTSS registration failed' in self._caplog.text
        assert '\tnot OK' in self._caplog.text

    @patch('cloudregister.registerutils.register_product')
    @patch('cloudregister.registerutils.add_hosts_entry')
    @patch('cloudregister.registercloudguest.cleanup')
    @patch('cloudregister.registerutils.clear_rmt_as_scc_proxy_flag')
    @patch('cloudregister.registerutils.deregister_non_free_extensions')
    @patch('cloudregister.registerutils.deregister_from_update_infrastructure')
    @patch('cloudregister.registerutils.deregister_from_SCC')
    @patch('cloudregister.registerutils.clean_registered_smt_data_file')
    @patch('cloudregister.registerutils.clean_hosts_file')
    @patch('cloudregister.registerutils.clear_new_registration_flag')
    @patch('cloudregister.registerutils.set_rmt_as_scc_proxy_flag')
    def test_register_base_product(
        self,
        mock_set_rmt_as_scc_proxy_flag,
        mock_clear_new_registration_flag,
        mock_clean_hosts_file,
        mock_clean_registered_smt_data_file,
        mock_deregister_from_SCC,
        mock_deregister_from_update_infrastructure,
        mock_deregister_non_free_extensions,
        mock_clear_rmt_as_scc_proxy_flag,
        mock_cleanup,
        mock_add_hosts_entry,
        mock_register_product,
    ):
        prod_reg = Mock()
        prod_reg.returncode = 0
        prod_reg.output = 'zypper output'
        mock_register_product.return_value = prod_reg
        registration_target = Mock()
        instance_data_filepath = 'some'
        commandline_args = Mock()
        region_smt_servers = [Mock(), Mock()]
        # Test success case
        register_cloud_guest.register_base_product(
            registration_target,
            instance_data_filepath,
            commandline_args,
            region_smt_servers,
        )
        assert 'Baseproduct registration complete' in self._caplog.text
        mock_clear_new_registration_flag.assert_called_once_with()
        mock_set_rmt_as_scc_proxy_flag.assert_called_once_with()

        # Test error case
        prod_reg.returncode = 1
        with raises(SystemExit):
            register_cloud_guest.register_base_product(
                registration_target,
                instance_data_filepath,
                commandline_args,
                region_smt_servers,
            )
            mock_deregister_non_free_extensions.assert_called_once_with()
            mock_clear_rmt_as_scc_proxy_flag.assert_called_once_with()
            mock_deregister_non_free_extensions.assert_called_once_with()
            mock_deregister_from_update_infrastructure.assert_called_once_with()
            mock_deregister_from_SCC.assert_called_once_with()
            mock_clean_registered_smt_data_file.assert_called_once_with()
            mock_clean_hosts_file.assert_called_once_with()

    @patch('cloudregister.registerutils.deregister_non_free_extensions')
    @patch('cloudregister.registerutils.deregister_from_update_infrastructure')
    @patch('cloudregister.registerutils.deregister_from_SCC')
    @patch('cloudregister.registerutils.clean_cache')
    @patch('cloudregister.registerutils.clean_all_standard')
    def test_cleanup(
        self,
        mock_clean_all_standard,
        mock_clean_cache,
        mock_deregister_from_SCC,
        mock_deregister_from_update_infrastructure,
        mock_deregister_non_free_extensions,
    ):
        # cleanup standard style
        register_cloud_guest.cleanup()
        mock_clean_all_standard.assert_called_once_with()

    @patch('cloudregister.registerutils._remove_state_file')
    @patch('cloudregister.registerutils.set_registration_completed_flag')
    @patch('os.system')
    @patch('cloudregister.registerutils.set_proxy')
    @patch('cloudregister.registercloudguest.urllib.parse.urlparse')
    @patch('cloudregister.registerutils.enable_repository')
    @patch('cloudregister.registerutils.exec_subprocess')
    @patch('cloudregister.registerutils.get_repo_url')
    @patch('cloudregister.registerutils.find_repos')
    @patch('cloudregister.registerutils.has_nvidia_support')
    @patch('cloudregister.registercloudguest.registration_returncode', 0)
    @patch('os.unlink')
    @patch('cloudregister.registerutils.get_credentials_file')
    @patch('cloudregister.registerutils.get_credentials')
    @patch('cloudregister.registerutils.get_product_tree')
    @patch('cloudregister.registerutils.requests.get')
    @patch('cloudregister.registerutils.set_rmt_as_scc_proxy_flag')
    @patch('cloudregister.registerutils.register_product')
    @patch('cloudregister.registerutils.import_smt_cert')
    @patch('cloudregister.registerutils.get_installed_products')
    @patch('cloudregister.registerutils.set_as_current_smt')
    @patch('os.access')
    @patch('cloudregister.registerutils.get_register_cmd')
    @patch('cloudregister.registerutils.update_rmt_cert')
    @patch('cloudregister.registerutils.has_registry_in_hosts')
    @patch('cloudregister.registerutils.add_hosts_entry')
    @patch('cloudregister.registerutils.clean_hosts_file')
    @patch('cloudregister.registerutils.has_rmt_in_hosts')
    @patch('cloudregister.registerutils.os.path.exists')
    @patch.object(SMT, 'is_responsive')
    @patch('cloudregister.registercloudguest.setup_ltss_registration')
    @patch('cloudregister.registercloudguest.setup_registry')
    @patch('cloudregister.registerutils.get_instance_data')
    @patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
    @patch('cloudregister.registerutils.has_region_changed')
    @patch('cloudregister.registerutils.store_smt_data')
    @patch('cloudregister.registerutils.get_current_smt')
    @patch('cloudregister.registerutils.set_new_registration_flag')
    @patch('cloudregister.registerutils.has_network_access_by_ip_address')
    @patch('cloudregister.registerutils.is_zypper_running')
    @patch('cloudregister.registerutils.write_framework_identifier')
    @patch('cloudregister.registerutils.get_available_smt_servers')
    @patch('os.makedirs')
    @patch('os.path.isdir')
    @patch('time.sleep')
    @patch('cloudregister.registerutils.get_state_dir')
    @patch('cloudregister.registerutils.get_config')
    @patch('cloudregister.registercloudguest.cleanup')
    def test_reg_cloud_baseprod_ok_setup_registry_failed(
        self,
        mock_cleanup,
        mock_get_config,
        mock_get_state_dir,
        mock_time_sleep,
        mock_os_path_isdir,
        mock_os_makedirs,
        mock_get_available_smt_servers,
        mock_write_framework_id,
        mock_is_zypper_running,
        mock_has_network_access,
        mock_set_new_registration_flag,
        mock_get_current_smt,
        mock_store_smt_data,
        mock_has_region_changed,
        mock_uses_rmt_as_scc_proxy,
        mock_get_instance_data,
        mock_setup_registry,
        mock_setup_ltss_registration,
        mock_smt_is_responsive,
        mock_os_path_exists,
        mock_has_rmt_in_hosts,
        mock_clean_hosts_file,
        mock_add_hosts_entry,
        mock_has_registry_in_hosts,
        mock_update_rmt_cert,
        mock_get_register_cmd,
        mock_os_access,
        mock_set_as_current_smt,
        mock_get_installed_products,
        mock_import_smt_cert,
        mock_register_product,
        mock_set_rmt_as_scc_proxy_flag,
        mock_requests_get,
        mock_get_product_tree,
        mock_get_creds,
        mock_get_creds_file,
        mock_os_unlink,
        mock_has_nvidia_support,
        mock_find_repos,
        mock_get_repo_url,
        mock_exec_subprocess,
        mock_enable_repo,
        mock_urlparse,
        mock_set_proxy,
        mock_os_system,
        mock_set_registration_completed_flag,
        mock_remove_state_file,
    ):
        smt_data_ipv46 = dedent(
            '''\
            <smtInfo fingerprint="AA:BB:CC:DD"
             SMTserverIP="1.2.3.5"
             SMTserverIPv6="fc00::1"
             SMTserverName="foo-ec2.susecloud.net"
             SMTregistryName="registry-ec2.susecloud.net"
             region="antarctica-1"/>'''
        )
        smt_server = SMT(etree.fromstring(smt_data_ipv46))
        mock_get_current_smt.return_value = smt_server
        fake_args = SimpleNamespace(
            clean_up=False,
            force_new_registration=True,
            user_smt_ip='fc00::1',
            user_smt_fqdn='foo-ec2.susecloud.net',
            user_smt_fp='AA:BB:CC:DD',
            email=None,
            reg_code='super_reg_code',
            delay_time=1,
            config_file='config_file',
            debug=True,
        )
        mock_os_path_isdir.return_value = False
        mock_is_zypper_running.return_value = False
        mock_get_available_smt_servers.return_value = []
        mock_has_network_access.return_value = True
        mock_has_region_changed.return_value = True
        mock_uses_rmt_as_scc_proxy.return_value = False
        mock_get_instance_data.return_value = None
        mock_smt_is_responsive.return_value = True
        mock_os_path_exists.side_effect = [False, True, True, True]
        mock_update_rmt_cert.return_value = True
        mock_has_rmt_in_hosts.return_value = False
        mock_has_registry_in_hosts.return_value = False
        mock_os_access.return_value = True
        mock_get_installed_products.return_value = 'SLES-LTSS-FOO/15.4/x86_64'
        mock_import_smt_cert.return_value = True
        mock_remove_state_file.return_value = True
        with tempfile.TemporaryDirectory(suffix='foo') as tdir:
            mock_get_state_dir.return_value = tdir
        prod_reg_type = namedtuple(
            'prod_reg_type', ['returncode', 'output', 'error']
        )
        mock_register_product.side_effect = [
            prod_reg_type(returncode=0, output='all OK', error='stderr'),
            prod_reg_type(
                returncode=67, output='registration code', error='stderr'
            ),
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
                    'name': 'SUSE Linux Enterprise Server LTSS Foo',
                    'identifier': 'SLES-LTSS-FOO',
                    'former_identifier': 'SLES-LTSS-FOO',
                    'version': '15.4',
                    'release_type': None,
                    'release_stage': 'released',
                    'arch': 'x86_64',
                    'friendly_name': 'SUSE Linux Enterprise Server LTSS 15 SP4 x86_64',
                    'product_class': 'SLES15-SP4-LTSS-FOO-X86',
                    'free': False,
                    'repositories': [],
                    'product_type': 'extension',
                    'extensions': [],
                    'recommended': False,
                    'available': True,
                }
            ],
        }
        response.json = json_mock
        mock_requests_get.return_value = response
        mock_get_creds.return_value = 'SCC_foo', 'bar'
        base_product = dedent(
            '''\
            <?xml version="1.0" encoding="UTF-8"?>
            <product schemeversion="0">
              <vendor>SUSE</vendor>
              <name>SLES</name>
              <version>15.4</version>
              <baseversion>15</baseversion>
              <patchlevel>4</patchlevel>
              <release>0</release>
              <endoflife></endoflife>
              <arch>x86_64</arch></product>'''
        )
        mock_get_product_tree.return_value = etree.fromstring(
            base_product[base_product.index('<product') :]
        )
        mock_get_register_cmd.return_value = '/usr/sbin/SUSEConnect'
        mock_has_nvidia_support.return_value = False
        mock_find_repos.return_value = ['repo_a', 'repo_b']
        mock_get_repo_url.return_value = (
            'plugin:/susecloud?credentials=Basesystem_Module_x86_64&'
            'path=/repo/SUSE/Updates/SLE-Module-Basesystem/15-SP4/x86_64/update/'
        )
        findmnt_return = (
            b'{"filesystems": [{"target": "/","source": '
            + b'"/dev/sda3","fstype": "xfs","options": "ro"}]}'
        )
        mock_exec_subprocess.return_value = findmnt_return, b'', 0
        mock_os_path_exists.reset_mock()
        mock_os_path_exists.return_value = True
        mock_urlparse.return_value = ParseResult(
            scheme='https',
            netloc='susecloud.net:443',
            path='/some/repo',
            params='',
            query='highlight=params',
            fragment='url-parsing',
        )
        mock_set_proxy.return_value = False
        mock_setup_registry.return_value = False
        with raises(SystemExit) as sys_exit:
            register_cloud_guest.main(fake_args)
            assert sys_exit.value.code == 1
