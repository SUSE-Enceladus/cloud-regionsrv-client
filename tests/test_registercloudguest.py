import inspect
import json
import os
import requests

from io import StringIO
from collections import namedtuple
from importlib.machinery import SourceFileLoader
from lxml import etree
from textwrap import dedent
from urllib.parse import ParseResult

from pytest import raises
from types import SimpleNamespace
from unittest.mock import patch, call, Mock, mock_open

test_path = os.path.abspath(
   os.path.dirname(inspect.getfile(inspect.currentframe())))
code_path = os.path.abspath('%s/../lib' % test_path)
data_path = test_path + os.sep + 'data/'

from cloudregister.smt import SMT # noqa
import cloudregister.registerutils as utils # noqa

# Hack to get the script without the .py imported for testing
register_cloud_guest = SourceFileLoader(
    'register_cloud_guest',
    './usr/sbin/registercloudguest'
).load_module()


def test_register_cloud_guest_missing_param():
    fake_args = SimpleNamespace(
        user_smt_ip='fc00::1',
        user_smt_fqdn='foo.susecloud.net',
        user_smt_fp=None
    )
    with raises(SystemExit):
        assert register_cloud_guest.main(fake_args) is None


@patch('cloudregister.registerutils.has_network_access_by_ip_address')
def test_register_cloud_guest_no_connection_ip(mock_has_network):
    mock_has_network.return_value = False
    fake_args = SimpleNamespace(
        user_smt_ip='1.2.3.5',
        user_smt_fqdn='foo.susecloud.net',
        user_smt_fp='AA:BB:CC:DD'
    )
    with raises(SystemExit):
        assert register_cloud_guest.main(fake_args) is None


def test_register_cloud_guest_non_ip_value():
    fake_args = SimpleNamespace(
        user_smt_ip='Not.an.IP.Address',
        user_smt_fqdn='foo.susecloud.net',
        user_smt_fp='AA:BB:CC'
    )
    with raises(SystemExit):
        assert register_cloud_guest.main(fake_args) is None


def test_register_cloud_guest_mixed_param():
    fake_args = SimpleNamespace(
        clean_up=True,
        force_new_registration=True,
        user_smt_ip=None,
        user_smt_fqdn=None,
        user_smt_fp=None
    )
    with raises(SystemExit):
        assert register_cloud_guest.main(fake_args) is None


def test_register_cloud_guest_no_regcode_email():
    fake_args = SimpleNamespace(
        clean_up=False,
        force_new_registration=False,
        user_smt_ip=None,
        user_smt_fqdn=None,
        user_smt_fp=None,
        email='foo',
        reg_code=None
    )
    with raises(SystemExit):
        assert register_cloud_guest.main(fake_args) is None


@patch('cloudregister.registerutils.clean_hosts_file')
@patch('cloudregister.registerutils.clean_non_free_extensions')
@patch('register_cloud_guest.time.sleep')
@patch('cloudregister.registerutils.get_config')
@patch('cloudregister.registerutils.clean_framework_identifier')
@patch('cloudregister.registerutils.clear_new_registration_flag')
@patch('cloudregister.registerutils.clean_smt_cache')
@patch('cloudregister.registerutils.remove_registration_data')
@patch('cloudregister.registerutils.clean_registry_setup')
def test_register_cloud_guest_cleanup(
    mock_clean_reg_setup, mock_remove_reg_data, mock_clean_smt_cache,
    mock_clear_reg_flag, mock_framework_id,  mock_get_config, mock_time_sleep,
    mock_clean_non_free_extensions, mock_clean_hosts_file
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
        config_file='config_file'
    )
    with raises(SystemExit):
        register_cloud_guest.main(fake_args)
    mock_clean_reg_setup.assert_called_once()


@patch('cloudregister.registerutils.clean_non_free_extensions')
@patch('register_cloud_guest.time.sleep')
@patch('cloudregister.registerutils.get_config')
@patch('cloudregister.registerutils.clean_framework_identifier')
@patch('cloudregister.registerutils.clear_new_registration_flag')
@patch('cloudregister.registerutils.clean_smt_cache')
@patch('cloudregister.registerutils.remove_registration_data')
@patch('cloudregister.registerutils.clean_registry_setup')
def test_register_cloud_guest_cleanup_exception(
    mock_clean_reg_setup, mock_remove_reg_data, mock_clean_smt_cache,
    mock_clear_reg_flag, mock_framework_id,  mock_get_config, mock_time_sleep,
    mock_clean_non_free_extensions
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
        config_file='config_file'
    )
    mock_clean_non_free_extensions.side_effect = Exception('oh no')
    with raises(SystemExit):
        register_cloud_guest.main(fake_args)
    mock_clean_reg_setup.assert_called_once()


@patch('cloudregister.registerutils.set_registration_completed_flag')
@patch('cloudregister.registerutils.set_new_registration_flag')
@patch('cloudregister.registerutils.has_network_access_by_ip_address')
@patch('cloudregister.registerutils.is_zypper_running')
@patch('cloudregister.registerutils.clear_new_registration_flag')
@patch('cloudregister.registerutils.get_available_smt_servers')
@patch('register_cloud_guest.os.makedirs')
@patch('register_cloud_guest.os.path.isdir')
@patch('register_cloud_guest.time.sleep')
@patch('cloudregister.registerutils.get_state_dir')
@patch('cloudregister.registerutils.get_config')
@patch('register_cloud_guest.cleanup')
def test_register_cloud_guest_force_reg_zypper_running(
    mock_cleanup, mock_get_config,
    mock_get_state_dir, mock_time_sleep,
    mock_os_path_isdir, mock_os_makedirs,
    mock_get_available_smt_servers, mock_clear_reg_flag,
    mock_is_zypper_running, mock_has_network_access,
    mock_set_new_registration_flag, mock_set_registration_completed_flag
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
        config_file='config_file'
    )
    mock_os_path_isdir.return_value = False
    mock_is_zypper_running.return_value = True
    mock_get_available_smt_servers.return_value = ['some', 'smt', 'servers']
    mock_has_network_access.return_value = True
    with raises(SystemExit) as sys_exit:
        register_cloud_guest.main(fake_args)
    assert sys_exit.value.code == 1


@patch('cloudregister.registerutils.set_new_registration_flag')
@patch('cloudregister.registerutils.has_network_access_by_ip_address')
@patch('cloudregister.registerutils.is_zypper_running')
@patch('cloudregister.registerutils.write_framework_identifier')
@patch('cloudregister.registerutils.get_available_smt_servers')
@patch('register_cloud_guest.os.makedirs')
@patch('register_cloud_guest.os.path.isdir')
@patch('register_cloud_guest.time.sleep')
@patch('cloudregister.registerutils.get_state_dir')
@patch('cloudregister.registerutils.get_config')
@patch('register_cloud_guest.cleanup')
def test_register_cloud_guest_force_reg_zypper_runnning_write_config(
    mock_cleanup, mock_get_config,
    mock_get_state_dir, mock_time_sleep,
    mock_os_path_isdir, mock_os_makedirs,
    mock_get_available_smt_servers, mock_write_framework_id,
    mock_is_zypper_running, mock_has_network_access,
    mock_set_new_registration_flag
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
        config_file='config_file'
    )
    mock_os_path_isdir.return_value = False
    mock_is_zypper_running.return_value = True
    mock_get_available_smt_servers.return_value = []
    mock_has_network_access.return_value = True
    with raises(SystemExit) as sys_exit:
        register_cloud_guest.main(fake_args)
    assert sys_exit.value.code == 1


@patch('register_cloud_guest.logging')
@patch.object(SMT, 'is_equivalent')
@patch.object(SMT, 'is_responsive')
@patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
@patch('cloudregister.registerutils.has_region_changed')
@patch('cloudregister.registerutils.os.path.join')
@patch('cloudregister.registerutils.store_smt_data')
@patch('cloudregister.registerutils.get_current_smt')
@patch('cloudregister.registerutils.set_new_registration_flag')
@patch('cloudregister.registerutils.has_network_access_by_ip_address')
@patch('cloudregister.registerutils.is_zypper_running')
@patch('cloudregister.registerutils.write_framework_identifier')
@patch('cloudregister.registerutils.get_available_smt_servers')
@patch('register_cloud_guest.os.makedirs')
@patch('register_cloud_guest.os.path.isdir')
@patch('register_cloud_guest.time.sleep')
@patch('cloudregister.registerutils.get_state_dir')
@patch('cloudregister.registerutils.get_config')
@patch('register_cloud_guest.cleanup')
def test_register_cloud_guest_force_reg_zypper_not_running_region_changed(
    mock_cleanup, mock_get_config,
    mock_get_state_dir, mock_time_sleep,
    mock_os_path_isdir, mock_os_makedirs,
    mock_get_available_smt_servers, mock_write_framework_id,
    mock_is_zypper_running, mock_has_network_access,
    mock_set_new_registration_flag, mock_get_current_smt,
    mock_store_smt_data, mock_os_path_join,
    mock_has_region_changed, mock_uses_rmt_as_scc_proxy,
    mock_smt_is_responsive, mock_smt_is_equivalent, mock_logging
):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="AA:BB:CC:DD"
         SMTserverIP="1.2.3.5"
         SMTserverIPv6="fc00::1"
         SMTserverName="foo-ec2.susecloud.net"
         SMTregistryName="registry-ec2.susecloud.net"
         region="antarctica-1"/>''')

    smt_server = SMT(etree.fromstring(smt_data_ipv46))
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
        config_file='config_file'
    )
    mock_os_path_isdir.return_value = False
    mock_is_zypper_running.return_value = False
    mock_get_available_smt_servers.return_value = []
    mock_has_network_access.return_value = True
    mock_has_region_changed.return_value = True
    mock_uses_rmt_as_scc_proxy.return_value = True
    mock_smt_is_responsive.side_effect = [False, True]
    mock_smt_is_equivalent.return_value = False
    with raises(SystemExit) as sys_exit:
        register_cloud_guest.main(fake_args)
    assert sys_exit.value.code == 1
    assert mock_logging.error.call_args_list == [
        call(
            'Configured update server is unresponsive. Could not find '
            'a replacement update server in this region. '
            'Possible network configuration issue'
        )
    ]


@patch('cloudregister.registerutils.set_proxy')
@patch('cloudregister.registerutils.update_rmt_cert')
@patch('cloudregister.registerutils.has_registry_in_hosts')
@patch('cloudregister.registerutils.add_hosts_entry')
@patch('cloudregister.registerutils.clean_hosts_file')
@patch('cloudregister.registerutils.has_rmt_in_hosts')
@patch('cloudregister.registerutils.os.path.exists')
@patch.object(SMT, 'is_responsive')
@patch('register_cloud_guest.setup_ltss_registration')
@patch('register_cloud_guest.setup_registry')
@patch('cloudregister.registerutils.get_instance_data')
@patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
@patch('cloudregister.registerutils.has_region_changed')
@patch('cloudregister.registerutils.os.path.join')
@patch('cloudregister.registerutils.store_smt_data')
@patch('cloudregister.registerutils.get_current_smt')
@patch('cloudregister.registerutils.set_new_registration_flag')
@patch('cloudregister.registerutils.has_network_access_by_ip_address')
@patch('cloudregister.registerutils.is_zypper_running')
@patch('cloudregister.registerutils.write_framework_identifier')
@patch('cloudregister.registerutils.get_available_smt_servers')
@patch('register_cloud_guest.os.makedirs')
@patch('register_cloud_guest.os.path.isdir')
@patch('register_cloud_guest.time.sleep')
@patch('cloudregister.registerutils.get_state_dir')
@patch('cloudregister.registerutils.get_config')
@patch('register_cloud_guest.cleanup')
def test_register_cloud_guest_force_reg_zypper_not_running_region_not_changed(
    mock_cleanup, mock_get_config,
    mock_get_state_dir, mock_time_sleep,
    mock_os_path_isdir, mock_os_makedirs,
    mock_get_available_smt_servers, mock_write_framework_id,
    mock_is_zypper_running, mock_has_network_access,
    mock_set_new_registration_flag, mock_get_current_smt,
    mock_store_smt_data, mock_os_path_join,
    mock_has_region_changed, mock_uses_rmt_as_scc_proxy,
    mock_get_instance_data, mock_setup_registry, mock_setup_ltss_registration,
    mock_smt_is_responsive, mock_os_path_exists, mock_has_rmt_in_hosts,
    mock_clean_hosts_file, mock_add_hosts_entry, mock_has_registry_in_hosts,
    mock_update_rmt_cert, mock_set_proxy
):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="AA:BB:CC:DD"
         SMTserverIP="1.2.3.5"
         SMTserverIPv6="fc00::1"
         SMTserverName="foo-ec2.susecloud.net"
         SMTregistryName="registry-ec2.susecloud.net"
         region="antarctica-1"/>''')

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
@patch('register_cloud_guest.setup_ltss_registration')
@patch('register_cloud_guest.setup_registry')
@patch('cloudregister.registerutils.get_instance_data')
@patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
@patch('cloudregister.registerutils.has_region_changed')
@patch('cloudregister.registerutils.os.path.join')
@patch('cloudregister.registerutils.store_smt_data')
@patch('cloudregister.registerutils.get_current_smt')
@patch('cloudregister.registerutils.set_new_registration_flag')
@patch('cloudregister.registerutils.has_network_access_by_ip_address')
@patch('cloudregister.registerutils.is_zypper_running')
@patch('cloudregister.registerutils.write_framework_identifier')
@patch('cloudregister.registerutils.get_available_smt_servers')
@patch('register_cloud_guest.os.makedirs')
@patch('register_cloud_guest.os.path.isdir')
@patch('register_cloud_guest.time.sleep')
@patch('cloudregister.registerutils.get_state_dir')
@patch('cloudregister.registerutils.get_config')
@patch('register_cloud_guest.cleanup')
def test_register_cloud_guest_region_not_changed_proxy_ok(
    mock_cleanup, mock_get_config,
    mock_get_state_dir, mock_time_sleep,
    mock_os_path_isdir, mock_os_makedirs,
    mock_get_available_smt_servers, mock_write_framework_id,
    mock_is_zypper_running, mock_has_network_access,
    mock_set_new_registration_flag, mock_get_current_smt,
    mock_store_smt_data, mock_os_path_join,
    mock_has_region_changed, mock_uses_rmt_as_scc_proxy,
    mock_get_instance_data, mock_setup_registry, mock_setup_ltss_registration,
    mock_smt_is_responsive, mock_os_path_exists, mock_has_rmt_in_hosts,
    mock_clean_hosts_file, mock_add_hosts_entry, mock_has_registry_in_hosts,
    mock_update_rmt_cert, mock_set_proxy
):
    mock_set_proxy.return_value = True
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="AA:BB:CC:DD"
         SMTserverIP="1.2.3.5"
         SMTserverIPv6="fc00::1"
         SMTserverName="foo-ec2.susecloud.net"
         SMTregistryName="registry-ec2.susecloud.net"
         region="antarctica-1"/>''')

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
@patch('register_cloud_guest.setup_ltss_registration')
@patch('register_cloud_guest.setup_registry')
@patch('cloudregister.registerutils.get_instance_data')
@patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
@patch('cloudregister.registerutils.has_region_changed')
@patch('cloudregister.registerutils.os.path.join')
@patch('cloudregister.registerutils.store_smt_data')
@patch('cloudregister.registerutils.get_current_smt')
@patch('cloudregister.registerutils.set_new_registration_flag')
@patch('cloudregister.registerutils.has_network_access_by_ip_address')
@patch('cloudregister.registerutils.is_zypper_running')
@patch('cloudregister.registerutils.write_framework_identifier')
@patch('cloudregister.registerutils.get_available_smt_servers')
@patch('register_cloud_guest.os.makedirs')
@patch('register_cloud_guest.os.path.isdir')
@patch('register_cloud_guest.time.sleep')
@patch('cloudregister.registerutils.get_state_dir')
@patch('cloudregister.registerutils.get_config')
@patch('register_cloud_guest.cleanup')
def test_register_cloud_guest_region_not_responsive_proxy_ok(
    mock_cleanup, mock_get_config,
    mock_get_state_dir, mock_time_sleep,
    mock_os_path_isdir, mock_os_makedirs,
    mock_get_available_smt_servers, mock_write_framework_id,
    mock_is_zypper_running, mock_has_network_access,
    mock_set_new_registration_flag, mock_get_current_smt,
    mock_store_smt_data, mock_os_path_join,
    mock_has_region_changed, mock_uses_rmt_as_scc_proxy,
    mock_get_instance_data, mock_setup_registry, mock_setup_ltss_registration,
    mock_smt_is_responsive, mock_os_path_exists, mock_has_rmt_in_hosts,
    mock_clean_hosts_file, mock_add_hosts_entry, mock_has_registry_in_hosts,
    mock_update_rmt_cert, mock_set_proxy, mock_smt_is_equivalent,
    mock_has_ipv6_access, mock_replace_hosts_entry
):
    mock_set_proxy.return_value = True
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="AA:BB:CC:DD"
         SMTserverIP="1.2.3.5"
         SMTserverIPv6="fc00::1"
         SMTserverName="foo-ec2.susecloud.net"
         SMTregistryName="registry-ec2.susecloud.net"
         region="antarctica-1"/>''')

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
@patch('register_cloud_guest.setup_ltss_registration')
@patch('register_cloud_guest.setup_registry')
@patch('cloudregister.registerutils.get_instance_data')
@patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
@patch('cloudregister.registerutils.has_region_changed')
@patch('cloudregister.registerutils.os.path.join')
@patch('cloudregister.registerutils.store_smt_data')
@patch('cloudregister.registerutils.get_current_smt')
@patch('cloudregister.registerutils.set_new_registration_flag')
@patch('cloudregister.registerutils.has_network_access_by_ip_address')
@patch('cloudregister.registerutils.is_zypper_running')
@patch('cloudregister.registerutils.write_framework_identifier')
@patch('cloudregister.registerutils.get_available_smt_servers')
@patch('register_cloud_guest.os.makedirs')
@patch('register_cloud_guest.os.path.isdir')
@patch('register_cloud_guest.time.sleep')
@patch('cloudregister.registerutils.get_state_dir')
@patch('cloudregister.registerutils.get_config')
@patch('register_cloud_guest.cleanup')
def test_register_cloud_guest_force_reg_rmt_scc_as_proxy(
    mock_cleanup, mock_get_config,
    mock_get_state_dir, mock_time_sleep,
    mock_os_path_isdir, mock_os_makedirs,
    mock_get_available_smt_servers, mock_write_framework_id,
    mock_is_zypper_running, mock_has_network_access,
    mock_set_new_registration_flag, mock_get_current_smt,
    mock_store_smt_data, mock_os_path_join,
    mock_has_region_changed, mock_uses_rmt_as_scc_proxy,
    mock_get_instance_data, mock_setup_registry, mock_setup_ltss_registration,
    mock_smt_is_responsive, mock_os_path_exists, mock_has_rmt_in_hosts,
    mock_clean_hosts_file, mock_add_hosts_entry, mock_has_registry_in_hosts,
    mock_update_rmt_cert, mock_set_proxy
):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="AA:BB:CC:DD"
         SMTserverIP="1.2.3.5"
         SMTserverIPv6="fc00::1"
         SMTserverName="foo-ec2.susecloud.net"
         SMTregistryName="registry-ec2.susecloud.net"
         region="antarctica-1"/>''')

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
    with raises(SystemExit) as sys_exit:
        register_cloud_guest.main(fake_args)
        assert sys_exit.value.code == 0


@patch('cloudregister.registerutils.set_proxy')
@patch('register_cloud_guest.logging')
@patch('cloudregister.registerutils.set_as_current_smt')
@patch('register_cloud_guest.os.access')
@patch('cloudregister.registerutils.get_register_cmd')
@patch('cloudregister.registerutils.update_rmt_cert')
@patch('cloudregister.registerutils.has_registry_in_hosts')
@patch('cloudregister.registerutils.add_hosts_entry')
@patch('cloudregister.registerutils.clean_hosts_file')
@patch('cloudregister.registerutils.has_rmt_in_hosts')
@patch('cloudregister.registerutils.os.path.exists')
@patch.object(SMT, 'is_responsive')
@patch('register_cloud_guest.setup_ltss_registration')
@patch('register_cloud_guest.setup_registry')
@patch('cloudregister.registerutils.get_instance_data')
@patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
@patch('cloudregister.registerutils.has_region_changed')
@patch('cloudregister.registerutils.os.path.join')
@patch('cloudregister.registerutils.store_smt_data')
@patch('cloudregister.registerutils.get_current_smt')
@patch('cloudregister.registerutils.set_new_registration_flag')
@patch('cloudregister.registerutils.has_network_access_by_ip_address')
@patch('cloudregister.registerutils.is_zypper_running')
@patch('cloudregister.registerutils.write_framework_identifier')
@patch('cloudregister.registerutils.get_available_smt_servers')
@patch('register_cloud_guest.os.makedirs')
@patch('register_cloud_guest.os.path.isdir')
@patch('register_cloud_guest.time.sleep')
@patch('cloudregister.registerutils.get_state_dir')
@patch('cloudregister.registerutils.get_config')
@patch('register_cloud_guest.cleanup')
def test_register_cloud_guest_force_reg_no_executable_found(
    mock_cleanup, mock_get_config,
    mock_get_state_dir, mock_time_sleep,
    mock_os_path_isdir, mock_os_makedirs,
    mock_get_available_smt_servers, mock_write_framework_id,
    mock_is_zypper_running, mock_has_network_access,
    mock_set_new_registration_flag, mock_get_current_smt,
    mock_store_smt_data, mock_os_path_join,
    mock_has_region_changed, mock_uses_rmt_as_scc_proxy,
    mock_get_instance_data, mock_setup_registry, mock_setup_ltss_registration,
    mock_smt_is_responsive, mock_os_path_exists, mock_has_rmt_in_hosts,
    mock_clean_hosts_file, mock_add_hosts_entry, mock_has_registry_in_hosts,
    mock_update_rmt_cert, mock_get_register_cmd, mock_os_access,
    mock_set_as_current_smt, mock_logging, mock_set_proxy
):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="AA:BB:CC:DD"
         SMTserverIP="1.2.3.5"
         SMTserverIPv6="fc00::1"
         SMTserverName="foo-ec2.susecloud.net"
         SMTregistryName="registry-ec2.susecloud.net"
         region="antarctica-1"/>''')

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
    with raises(SystemExit) as sys_exit:
        register_cloud_guest.main(fake_args)
        assert mock_logging.error.call_args_list == [
            'No registration executable found'
        ]
        assert sys_exit.value.code == 1


@patch('cloudregister.registerutils.set_proxy')
@patch('cloudregister.registerutils.is_registration_supported')
@patch('cloudregister.registerutils.set_as_current_smt')
@patch('register_cloud_guest.os.access')
@patch('cloudregister.registerutils.get_register_cmd')
@patch('cloudregister.registerutils.update_rmt_cert')
@patch('cloudregister.registerutils.has_registry_in_hosts')
@patch('cloudregister.registerutils.add_hosts_entry')
@patch('cloudregister.registerutils.clean_hosts_file')
@patch('cloudregister.registerutils.has_rmt_in_hosts')
@patch('cloudregister.registerutils.os.path.exists')
@patch.object(SMT, 'is_responsive')
@patch('register_cloud_guest.setup_ltss_registration')
@patch('register_cloud_guest.setup_registry')
@patch('cloudregister.registerutils.get_instance_data')
@patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
@patch('cloudregister.registerutils.has_region_changed')
@patch('cloudregister.registerutils.os.path.join')
@patch('cloudregister.registerutils.store_smt_data')
@patch('cloudregister.registerutils.get_current_smt')
@patch('cloudregister.registerutils.set_new_registration_flag')
@patch('cloudregister.registerutils.has_network_access_by_ip_address')
@patch('cloudregister.registerutils.is_zypper_running')
@patch('cloudregister.registerutils.write_framework_identifier')
@patch('cloudregister.registerutils.get_available_smt_servers')
@patch('register_cloud_guest.os.makedirs')
@patch('register_cloud_guest.os.path.isdir')
@patch('register_cloud_guest.time.sleep')
@patch('cloudregister.registerutils.get_state_dir')
@patch('cloudregister.registerutils.get_config')
@patch('register_cloud_guest.cleanup')
def test_register_cloud_guest_force_registration_not_supported(
    mock_cleanup, mock_get_config,
    mock_get_state_dir, mock_time_sleep,
    mock_os_path_isdir, mock_os_makedirs,
    mock_get_available_smt_servers, mock_write_framework_id,
    mock_is_zypper_running, mock_has_network_access,
    mock_set_new_registration_flag, mock_get_current_smt,
    mock_store_smt_data, mock_os_path_join,
    mock_has_region_changed, mock_uses_rmt_as_scc_proxy,
    mock_get_instance_data, mock_setup_registry, mock_setup_ltss_registration,
    mock_smt_is_responsive, mock_os_path_exists, mock_has_rmt_in_hosts,
    mock_clean_hosts_file, mock_add_hosts_entry, mock_has_registry_in_hosts,
    mock_update_rmt_cert, mock_get_register_cmd, mock_os_access,
    mock_set_as_current_smt, mock_is_registration_supported, mock_set_proxy
):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="AA:BB:CC:DD"
         SMTserverIP="1.2.3.5"
         SMTserverIPv6="fc00::1"
         SMTserverName="foo-ec2.susecloud.net"
         SMTregistryName="registry-ec2.susecloud.net"
         region="antarctica-1"/>''')

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
    with raises(SystemExit) as sys_exit:
        register_cloud_guest.main(fake_args)
    assert sys_exit.value.code == 0


@patch('cloudregister.registerutils.set_proxy')
@patch('cloudregister.registerutils.get_installed_products')
@patch('register_cloud_guest.logging')
@patch('cloudregister.registerutils.set_as_current_smt')
@patch('register_cloud_guest.os.access')
@patch('cloudregister.registerutils.get_register_cmd')
@patch('cloudregister.registerutils.update_rmt_cert')
@patch('cloudregister.registerutils.has_registry_in_hosts')
@patch('cloudregister.registerutils.add_hosts_entry')
@patch('cloudregister.registerutils.clean_hosts_file')
@patch('cloudregister.registerutils.has_rmt_in_hosts')
@patch('cloudregister.registerutils.os.path.exists')
@patch.object(SMT, 'is_responsive')
@patch('register_cloud_guest.setup_ltss_registration')
@patch('register_cloud_guest.setup_registry')
@patch('cloudregister.registerutils.get_instance_data')
@patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
@patch('cloudregister.registerutils.has_region_changed')
@patch('cloudregister.registerutils.os.path.join')
@patch('cloudregister.registerutils.store_smt_data')
@patch('cloudregister.registerutils.get_current_smt')
@patch('cloudregister.registerutils.set_new_registration_flag')
@patch('cloudregister.registerutils.has_network_access_by_ip_address')
@patch('cloudregister.registerutils.is_zypper_running')
@patch('cloudregister.registerutils.write_framework_identifier')
@patch('cloudregister.registerutils.get_available_smt_servers')
@patch('register_cloud_guest.os.makedirs')
@patch('register_cloud_guest.os.path.isdir')
@patch('register_cloud_guest.time.sleep')
@patch('cloudregister.registerutils.get_state_dir')
@patch('cloudregister.registerutils.get_config')
@patch('register_cloud_guest.cleanup')
def test_register_cloud_guest_force_reg_no_products_installed(
    mock_cleanup, mock_get_config,
    mock_get_state_dir, mock_time_sleep,
    mock_os_path_isdir, mock_os_makedirs,
    mock_get_available_smt_servers, mock_write_framework_id,
    mock_is_zypper_running, mock_has_network_access,
    mock_set_new_registration_flag, mock_get_current_smt,
    mock_store_smt_data, mock_os_path_join,
    mock_has_region_changed, mock_uses_rmt_as_scc_proxy,
    mock_get_instance_data, mock_setup_registry, mock_setup_ltss_registration,
    mock_smt_is_responsive, mock_os_path_exists, mock_has_rmt_in_hosts,
    mock_clean_hosts_file, mock_add_hosts_entry, mock_has_registry_in_hosts,
    mock_update_rmt_cert, mock_get_register_cmd, mock_os_access,
    mock_set_as_current_smt, mock_logging, mock_get_installed_products,
    mock_set_proxy
):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="AA:BB:CC:DD"
         SMTserverIP="1.2.3.5"
         SMTserverIPv6="fc00::1"
         SMTserverName="foo-ec2.susecloud.net"
         SMTregistryName="registry-ec2.susecloud.net"
         region="antarctica-1"/>''')

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
    mock_os_path_join.return_value = ''
    with raises(SystemExit) as sys_exit:
        register_cloud_guest.main(fake_args)
    assert mock_logging.error.call_args_list == [
        call('No products installed on system')
    ]
    assert sys_exit.value.code == 1


@patch('cloudregister.registerutils.set_proxy')
@patch('cloudregister.registerutils.import_smt_cert')
@patch('cloudregister.registerutils.get_installed_products')
@patch('register_cloud_guest.logging')
@patch('cloudregister.registerutils.set_as_current_smt')
@patch('register_cloud_guest.os.access')
@patch('cloudregister.registerutils.get_register_cmd')
@patch('cloudregister.registerutils.update_rmt_cert')
@patch('cloudregister.registerutils.has_registry_in_hosts')
@patch('cloudregister.registerutils.add_hosts_entry')
@patch('cloudregister.registerutils.clean_hosts_file')
@patch('cloudregister.registerutils.has_rmt_in_hosts')
@patch('cloudregister.registerutils.os.path.exists')
@patch.object(SMT, 'is_responsive')
@patch('register_cloud_guest.setup_ltss_registration')
@patch('register_cloud_guest.setup_registry')
@patch('cloudregister.registerutils.get_instance_data')
@patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
@patch('cloudregister.registerutils.has_region_changed')
@patch('cloudregister.registerutils.os.path.join')
@patch('cloudregister.registerutils.store_smt_data')
@patch('cloudregister.registerutils.get_current_smt')
@patch('cloudregister.registerutils.set_new_registration_flag')
@patch('cloudregister.registerutils.has_network_access_by_ip_address')
@patch('cloudregister.registerutils.is_zypper_running')
@patch('cloudregister.registerutils.write_framework_identifier')
@patch('cloudregister.registerutils.get_available_smt_servers')
@patch('register_cloud_guest.os.makedirs')
@patch('register_cloud_guest.os.path.isdir')
@patch('register_cloud_guest.time.sleep')
@patch('cloudregister.registerutils.get_state_dir')
@patch('cloudregister.registerutils.get_config')
@patch('register_cloud_guest.cleanup')
def test_register_cloud_guest_force_reg_cert_import_failed(
    mock_cleanup, mock_get_config,
    mock_get_state_dir, mock_time_sleep,
    mock_os_path_isdir, mock_os_makedirs,
    mock_get_available_smt_servers, mock_write_framework_id,
    mock_is_zypper_running, mock_has_network_access,
    mock_set_new_registration_flag, mock_get_current_smt,
    mock_store_smt_data, mock_os_path_join,
    mock_has_region_changed, mock_uses_rmt_as_scc_proxy,
    mock_get_instance_data, mock_setup_registry, mock_setup_ltss_registration,
    mock_smt_is_responsive, mock_os_path_exists, mock_has_rmt_in_hosts,
    mock_clean_hosts_file, mock_add_hosts_entry, mock_has_registry_in_hosts,
    mock_update_rmt_cert, mock_get_register_cmd, mock_os_access,
    mock_set_as_current_smt, mock_logging, mock_get_installed_products,
    mock_import_smt_cert, mock_set_proxy
):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="AA:BB:CC:DD"
         SMTserverIP="1.2.3.5"
         SMTserverIPv6="fc00::1"
         SMTserverName="foo-ec2.susecloud.net"
         SMTregistryName="registry-ec2.susecloud.net"
         region="antarctica-1"/>''')

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
    mock_os_path_join.return_value = ''
    with raises(SystemExit) as sys_exit:
        register_cloud_guest.main(fake_args)
    assert sys_exit.value.code == 1
    assert mock_logging.error.call_args_list == [
        call('SMT certificate import failed')
    ]


@patch('cloudregister.registerutils.set_proxy')
@patch('cloudregister.registerutils.register_product')
@patch('cloudregister.registerutils.import_smt_cert')
@patch('cloudregister.registerutils.get_installed_products')
@patch('register_cloud_guest.logging')
@patch('cloudregister.registerutils.set_as_current_smt')
@patch('register_cloud_guest.os.access')
@patch('cloudregister.registerutils.get_register_cmd')
@patch('cloudregister.registerutils.update_rmt_cert')
@patch('cloudregister.registerutils.has_registry_in_hosts')
@patch('cloudregister.registerutils.add_hosts_entry')
@patch('cloudregister.registerutils.clean_hosts_file')
@patch('cloudregister.registerutils.has_rmt_in_hosts')
@patch('cloudregister.registerutils.os.path.exists')
@patch.object(SMT, 'is_responsive')
@patch('register_cloud_guest.setup_ltss_registration')
@patch('register_cloud_guest.setup_registry')
@patch('cloudregister.registerutils.get_instance_data')
@patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
@patch('cloudregister.registerutils.has_region_changed')
@patch('cloudregister.registerutils.os.path.join')
@patch('cloudregister.registerutils.store_smt_data')
@patch('cloudregister.registerutils.get_current_smt')
@patch('cloudregister.registerutils.set_new_registration_flag')
@patch('cloudregister.registerutils.has_network_access_by_ip_address')
@patch('cloudregister.registerutils.is_zypper_running')
@patch('cloudregister.registerutils.write_framework_identifier')
@patch('cloudregister.registerutils.get_available_smt_servers')
@patch('register_cloud_guest.os.makedirs')
@patch('register_cloud_guest.os.path.isdir')
@patch('register_cloud_guest.time.sleep')
@patch('cloudregister.registerutils.get_state_dir')
@patch('cloudregister.registerutils.get_config')
@patch('register_cloud_guest.cleanup')
def test_register_cloud_guest_force_baseprod_registration_failed(
    mock_cleanup, mock_get_config,
    mock_get_state_dir, mock_time_sleep,
    mock_os_path_isdir, mock_os_makedirs,
    mock_get_available_smt_servers, mock_write_framework_id,
    mock_is_zypper_running, mock_has_network_access,
    mock_set_new_registration_flag, mock_get_current_smt,
    mock_store_smt_data, mock_os_path_join,
    mock_has_region_changed, mock_uses_rmt_as_scc_proxy,
    mock_get_instance_data, mock_setup_registry, mock_setup_ltss_registration,
    mock_smt_is_responsive, mock_os_path_exists, mock_has_rmt_in_hosts,
    mock_clean_hosts_file, mock_add_hosts_entry, mock_has_registry_in_hosts,
    mock_update_rmt_cert, mock_get_register_cmd, mock_os_access,
    mock_set_as_current_smt, mock_logging, mock_get_installed_products,
    mock_import_smt_cert, mock_register_product, mock_set_proxy
):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="AA:BB:CC:DD"
         SMTserverIP="1.2.3.5"
         SMTserverIPv6="fc00::1"
         SMTserverName="foo-ec2.susecloud.net"
         SMTregistryName="registry-ec2.susecloud.net"
         region="antarctica-1"/>''')

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
    mock_os_path_join.return_value = ''
    prod_reg_type = namedtuple(
        'prod_reg_type', ['returncode', 'output', 'error']
    )
    mock_register_product.return_value = prod_reg_type(
        returncode=67,
        output='registration code',
        error='stderr'
    )
    with raises(SystemExit) as sys_exit:
        register_cloud_guest.main(fake_args)
    assert mock_logging.error.call_args_list == [
        call('Baseproduct registration failed'),
        call('\tregistration code')
    ]
    assert sys_exit.value.code == 1


@patch('cloudregister.registerutils.set_registration_completed_flag')
@patch('cloudregister.registerutils.set_proxy')
@patch.object(SMT, 'is_equivalent')
@patch('cloudregister.registerutils.is_registration_supported')
@patch('register_cloud_guest.get_responding_update_server')
@patch('cloudregister.registerutils.fetch_smt_data')
@patch('cloudregister.registerutils.remove_registration_data')
@patch('cloudregister.registerutils.register_product')
@patch('cloudregister.registerutils.import_smt_cert')
@patch('cloudregister.registerutils.get_installed_products')
@patch('register_cloud_guest.logging')
@patch('cloudregister.registerutils.set_as_current_smt')
@patch('register_cloud_guest.os.access')
@patch('cloudregister.registerutils.get_register_cmd')
@patch('cloudregister.registerutils.update_rmt_cert')
@patch('cloudregister.registerutils.has_registry_in_hosts')
@patch('cloudregister.registerutils.add_hosts_entry')
@patch('cloudregister.registerutils.clean_hosts_file')
@patch('cloudregister.registerutils.has_rmt_in_hosts')
@patch('cloudregister.registerutils.os.path.exists')
@patch.object(SMT, 'is_responsive')
@patch('register_cloud_guest.setup_ltss_registration')
@patch('register_cloud_guest.setup_registry')
@patch('cloudregister.registerutils.get_instance_data')
@patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
@patch('cloudregister.registerutils.has_region_changed')
@patch('cloudregister.registerutils.os.path.join')
@patch('cloudregister.registerutils.store_smt_data')
@patch('cloudregister.registerutils.get_current_smt')
@patch('cloudregister.registerutils.set_new_registration_flag')
@patch('cloudregister.registerutils.has_network_access_by_ip_address')
@patch('cloudregister.registerutils.is_zypper_running')
@patch('cloudregister.registerutils.write_framework_identifier')
@patch('cloudregister.registerutils.get_available_smt_servers')
@patch('register_cloud_guest.os.makedirs')
@patch('register_cloud_guest.os.path.isdir')
@patch('register_cloud_guest.time.sleep')
@patch('cloudregister.registerutils.get_state_dir')
@patch('cloudregister.registerutils.get_config')
@patch('register_cloud_guest.cleanup')
def test_register_cloud_guest_force_baseprod_registration_failed_connection(
    mock_cleanup, mock_get_config,
    mock_get_state_dir, mock_time_sleep,
    mock_os_path_isdir, mock_os_makedirs,
    mock_get_available_smt_servers, mock_write_framework_id,
    mock_is_zypper_running, mock_has_network_access,
    mock_set_new_registration_flag, mock_get_current_smt,
    mock_store_smt_data, mock_os_path_join,
    mock_has_region_changed, mock_uses_rmt_as_scc_proxy,
    mock_get_instance_data, mock_setup_registry, mock_setup_ltss_registration,
    mock_smt_is_responsive, mock_os_path_exists, mock_has_rmt_in_hosts,
    mock_clean_hosts_file, mock_add_hosts_entry, mock_has_registry_in_hosts,
    mock_update_rmt_cert, mock_get_register_cmd, mock_os_access,
    mock_set_as_current_smt, mock_logging, mock_get_installed_products,
    mock_import_smt_cert, mock_register_product, mock_remove_reg_data,
    mock_fetch_smt_data, mock_get_responding_update_server,
    mock_is_reg_supported, mock_is_equivalent, mock_set_proxy,
    mock_set_registration_completed_flag
):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="AA:BB:CC:DD"
         SMTserverIP="1.2.3.5"
         SMTserverIPv6="fc00::1"
         SMTserverName="foo-ec2.susecloud.net"
         SMTregistryName="registry-ec2.susecloud.net"
         region="antarctica-1"/>''')

    smt_region_data = dedent('''\
        <regionSMTdata><smtInfo fingerprint="AA:BB:CC:DD"
         SMTserverIP="1.2.3.5"
         SMTserverIPv6="fc00::1"
         SMTserverName="foo-ec2.susecloud.net"
         SMTregistryName="registry-ec2.susecloud.net"
         region="antarctica-1"/><smtInfo fingerprint="AA:BB:CC:DD"
         SMTserverIP="1.2.3.6"
         SMTserverIPv6="fc00::1"
         SMTserverName="foo-ec2.susecloud.net"
         SMTregistryName="registry-ec2.susecloud.net"
         region="antarctica-1"/></regionSMTdata>''')

    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_current_smt.return_value = smt_server
    fake_args = SimpleNamespace(
        clean_up=False,
        force_new_registration=True,
        user_smt_ip=None,
        user_smt_fqdn=None,
        user_smt_fp=None,
        email=None,
        reg_code='super_reg_code',
        delay_time=1,
        config_file='config_file',
    )
    mock_os_path_isdir.return_value = False
    mock_is_zypper_running.return_value = False
    mock_get_available_smt_servers.return_value = [smt_server, smt_server]
    mock_get_responding_update_server.return_value = smt_server
    mock_has_network_access.return_value = True
    mock_has_region_changed.return_value = True
    mock_uses_rmt_as_scc_proxy.return_value = False
    mock_get_instance_data.return_value = None
    mock_smt_is_responsive.return_value = False
    mock_is_equivalent.return_value = False
    mock_set_proxy.return_value = False
    mock_os_path_exists.side_effect = [True, True]
    mock_update_rmt_cert.return_value = True
    mock_has_rmt_in_hosts.return_value = False
    mock_has_registry_in_hosts.return_value = False
    mock_os_access.return_value = True
    mock_get_installed_products.return_value = 'foo'
    mock_import_smt_cert.return_value = True
    mock_os_path_join.return_value = ''
    prod_reg_type = namedtuple(
        'prod_reg_type', ['returncode', 'output', 'error']
    )
    mock_register_product.return_value = prod_reg_type(
        returncode=64,
        output='some error',
        error='stderr'
    )
    mock_fetch_smt_data.return_value = etree.fromstring(smt_region_data)
    mock_is_reg_supported.return_value = True
    with raises(SystemExit) as sys_exit:
        register_cloud_guest.main(fake_args)
    assert mock_logging.error.call_args_list == [
        call(
            "Registration with ('1.2.3.5', 'fc00::1') failed. "
            "Trying ('1.2.3.6', 'fc00::1')"
        ),
        call('Baseproduct registration failed'),
        call('\tsome error')
    ]
    assert sys_exit.value.code == 1


@patch('cloudregister.registerutils.set_proxy')
@patch('cloudregister.registerutils.get_credentials_file')
@patch('cloudregister.registerutils.get_credentials')
@patch('cloudregister.registerutils.get_product_tree')
@patch('cloudregister.registerutils.requests.get')
@patch('cloudregister.registerutils.set_rmt_as_scc_proxy_flag')
@patch('cloudregister.registerutils.register_product')
@patch('cloudregister.registerutils.import_smt_cert')
@patch('cloudregister.registerutils.get_installed_products')
@patch('register_cloud_guest.logging')
@patch('cloudregister.registerutils.set_as_current_smt')
@patch('register_cloud_guest.os.access')
@patch('cloudregister.registerutils.get_register_cmd')
@patch('cloudregister.registerutils.update_rmt_cert')
@patch('cloudregister.registerutils.has_registry_in_hosts')
@patch('cloudregister.registerutils.add_hosts_entry')
@patch('cloudregister.registerutils.clean_hosts_file')
@patch('cloudregister.registerutils.has_rmt_in_hosts')
@patch('cloudregister.registerutils.os.path.exists')
@patch.object(SMT, 'is_responsive')
@patch('register_cloud_guest.setup_ltss_registration')
@patch('register_cloud_guest.setup_registry')
@patch('cloudregister.registerutils.get_instance_data')
@patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
@patch('cloudregister.registerutils.has_region_changed')
@patch('cloudregister.registerutils.os.path.join')
@patch('cloudregister.registerutils.store_smt_data')
@patch('cloudregister.registerutils.get_current_smt')
@patch('cloudregister.registerutils.set_new_registration_flag')
@patch('cloudregister.registerutils.has_network_access_by_ip_address')
@patch('cloudregister.registerutils.is_zypper_running')
@patch('cloudregister.registerutils.write_framework_identifier')
@patch('cloudregister.registerutils.get_available_smt_servers')
@patch('register_cloud_guest.os.makedirs')
@patch('register_cloud_guest.os.path.isdir')
@patch('register_cloud_guest.time.sleep')
@patch('cloudregister.registerutils.get_state_dir')
@patch('cloudregister.registerutils.get_config')
@patch('register_cloud_guest.cleanup')
def test_register_cloud_guest_force_baseprod_registration_ok_failed_extensions(
    mock_cleanup, mock_get_config,
    mock_get_state_dir, mock_time_sleep,
    mock_os_path_isdir, mock_os_makedirs,
    mock_get_available_smt_servers, mock_write_framework_id,
    mock_is_zypper_running, mock_has_network_access,
    mock_set_new_registration_flag, mock_get_current_smt,
    mock_store_smt_data, mock_os_path_join,
    mock_has_region_changed, mock_uses_rmt_as_scc_proxy,
    mock_get_instance_data, mock_setup_registry, mock_setup_ltss_registration,
    mock_smt_is_responsive, mock_os_path_exists, mock_has_rmt_in_hosts,
    mock_clean_hosts_file, mock_add_hosts_entry, mock_has_registry_in_hosts,
    mock_update_rmt_cert, mock_get_register_cmd, mock_os_access,
    mock_set_as_current_smt, mock_logging, mock_get_installed_products,
    mock_import_smt_cert, mock_register_product, mock_set_rmt_as_scc_proxy_flag,
    mock_requests_get, mock_get_product_tree, mock_get_creds,
    mock_get_creds_file, mock_set_proxy
):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="AA:BB:CC:DD"
         SMTserverIP="1.2.3.5"
         SMTserverIPv6="fc00::1"
         SMTserverName="foo-ec2.susecloud.net"
         SMTregistryName="registry-ec2.susecloud.net"
         region="antarctica-1"/>''')

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
    mock_os_path_join.return_value = ''
    prod_reg_type = namedtuple(
        'prod_reg_type', ['returncode', 'output', 'error']
    )
    mock_register_product.return_value = prod_reg_type(
        returncode=0,
        output='registration code',
        error='stderr'
    )
    response = Response()
    response.status_code = requests.codes.forbidden
    response.reason = 'Because nope'
    response.content = str(json.dumps('no accessio')).encode()
    mock_requests_get.return_value = response
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
    mock_set_proxy.return_value = False
    with raises(SystemExit) as sys_exit:
        register_cloud_guest.main(fake_args)
    mock_logging.error.assert_called_once_with(
        'Unable to obtain product information from server "1.2.3.5,None"'
        '\n\tBecause nope\n\t"no accessio"\n'
        'Unable to register modules, exiting.'
    )
    assert sys_exit.value.code == 1


@patch('cloudregister.registerutils.set_proxy')
@patch('register_cloud_guest.registration_returncode', 0)
@patch('register_cloud_guest.os.unlink')
@patch('cloudregister.registerutils.get_credentials_file')
@patch('cloudregister.registerutils.get_credentials')
@patch('cloudregister.registerutils.get_product_tree')
@patch('cloudregister.registerutils.requests.get')
@patch('cloudregister.registerutils.set_rmt_as_scc_proxy_flag')
@patch('cloudregister.registerutils.register_product')
@patch('cloudregister.registerutils.import_smt_cert')
@patch('cloudregister.registerutils.get_installed_products')
@patch('register_cloud_guest.logging')
@patch('cloudregister.registerutils.set_as_current_smt')
@patch('register_cloud_guest.os.access')
@patch('cloudregister.registerutils.get_register_cmd')
@patch('cloudregister.registerutils.update_rmt_cert')
@patch('cloudregister.registerutils.has_registry_in_hosts')
@patch('cloudregister.registerutils.add_hosts_entry')
@patch('cloudregister.registerutils.clean_hosts_file')
@patch('cloudregister.registerutils.has_rmt_in_hosts')
@patch('cloudregister.registerutils.os.path.exists')
@patch.object(SMT, 'is_responsive')
@patch('register_cloud_guest.setup_ltss_registration')
@patch('register_cloud_guest.setup_registry')
@patch('cloudregister.registerutils.get_instance_data')
@patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
@patch('cloudregister.registerutils.has_region_changed')
@patch('cloudregister.registerutils.os.path.join')
@patch('cloudregister.registerutils.store_smt_data')
@patch('cloudregister.registerutils.get_current_smt')
@patch('cloudregister.registerutils.set_new_registration_flag')
@patch('cloudregister.registerutils.has_network_access_by_ip_address')
@patch('cloudregister.registerutils.is_zypper_running')
@patch('cloudregister.registerutils.write_framework_identifier')
@patch('cloudregister.registerutils.get_available_smt_servers')
@patch('register_cloud_guest.os.makedirs')
@patch('register_cloud_guest.os.path.isdir')
@patch('register_cloud_guest.time.sleep')
@patch('cloudregister.registerutils.get_state_dir')
@patch('cloudregister.registerutils.get_config')
@patch('register_cloud_guest.cleanup')
def test_register_cloud_guest_force_baseprod_extensions_raise(
    mock_cleanup, mock_get_config,
    mock_get_state_dir, mock_time_sleep,
    mock_os_path_isdir, mock_os_makedirs,
    mock_get_available_smt_servers, mock_write_framework_id,
    mock_is_zypper_running, mock_has_network_access,
    mock_set_new_registration_flag, mock_get_current_smt,
    mock_store_smt_data, mock_os_path_join,
    mock_has_region_changed, mock_uses_rmt_as_scc_proxy,
    mock_get_instance_data, mock_setup_registry, mock_setup_ltss_registration,
    mock_smt_is_responsive, mock_os_path_exists, mock_has_rmt_in_hosts,
    mock_clean_hosts_file, mock_add_hosts_entry, mock_has_registry_in_hosts,
    mock_update_rmt_cert, mock_get_register_cmd, mock_os_access,
    mock_set_as_current_smt, mock_logging, mock_get_installed_products,
    mock_import_smt_cert, mock_register_product,
    mock_set_rmt_as_scc_proxy_flag,
    mock_requests_get, mock_get_product_tree, mock_get_creds,
    mock_get_creds_file, mock_os_unlink, mock_set_proxy
):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="AA:BB:CC:DD"
         SMTserverIP="1.2.3.5"
         SMTserverIPv6="fc00::1"
         SMTserverName="foo-ec2.susecloud.net"
         SMTregistryName="registry-ec2.susecloud.net"
         region="antarctica-1"/>''')

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
    mock_os_path_join.return_value = ''
    prod_reg_type = namedtuple(
        'prod_reg_type', ['returncode', 'output', 'error']
    )
    mock_register_product.side_effect = [
        prod_reg_type(
            returncode=0,
            output='all OK',
            error='stderr'
        ),
        prod_reg_type(
            returncode=6,
            output='registration code',
            error='stderr'
        )
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
    mock_set_proxy.return_value = False
    mock_get_register_cmd.return_value = '/usr/sbin/SUSEConnect'
    with raises(SystemExit) as sys_exit:
        register_cloud_guest.main(fake_args)
    assert sys_exit.value.code == 6


@patch('cloudregister.registerutils.set_registration_completed_flag')
@patch('cloudregister.registerutils.set_proxy')
@patch('register_cloud_guest.urllib.parse.urlparse')
@patch('cloudregister.registerutils.enable_repository')
@patch('cloudregister.registerutils.exec_subprocess')
@patch('cloudregister.registerutils.get_repo_url')
@patch('cloudregister.registerutils.find_repos')
@patch('cloudregister.registerutils.has_nvidia_support')
@patch('register_cloud_guest.registration_returncode', 0)
@patch('register_cloud_guest.os.unlink')
@patch('cloudregister.registerutils.get_credentials_file')
@patch('cloudregister.registerutils.get_credentials')
@patch('cloudregister.registerutils.get_product_tree')
@patch('cloudregister.registerutils.requests.get')
@patch('cloudregister.registerutils.set_rmt_as_scc_proxy_flag')
@patch('cloudregister.registerutils.register_product')
@patch('cloudregister.registerutils.import_smt_cert')
@patch('cloudregister.registerutils.get_installed_products')
@patch('register_cloud_guest.logging')
@patch('cloudregister.registerutils.set_as_current_smt')
@patch('register_cloud_guest.os.access')
@patch('cloudregister.registerutils.get_register_cmd')
@patch('cloudregister.registerutils.update_rmt_cert')
@patch('cloudregister.registerutils.has_registry_in_hosts')
@patch('cloudregister.registerutils.add_hosts_entry')
@patch('cloudregister.registerutils.clean_hosts_file')
@patch('cloudregister.registerutils.has_rmt_in_hosts')
@patch('cloudregister.registerutils.os.path.exists')
@patch.object(SMT, 'is_responsive')
@patch('register_cloud_guest.setup_ltss_registration')
@patch('register_cloud_guest.setup_registry')
@patch('cloudregister.registerutils.get_instance_data')
@patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
@patch('cloudregister.registerutils.has_region_changed')
@patch('cloudregister.registerutils.os.path.join')
@patch('cloudregister.registerutils.store_smt_data')
@patch('cloudregister.registerutils.get_current_smt')
@patch('cloudregister.registerutils.set_new_registration_flag')
@patch('cloudregister.registerutils.has_network_access_by_ip_address')
@patch('cloudregister.registerutils.is_zypper_running')
@patch('cloudregister.registerutils.write_framework_identifier')
@patch('cloudregister.registerutils.get_available_smt_servers')
@patch('register_cloud_guest.os.makedirs')
@patch('register_cloud_guest.os.path.isdir')
@patch('register_cloud_guest.time.sleep')
@patch('cloudregister.registerutils.get_state_dir')
@patch('cloudregister.registerutils.get_config')
@patch('register_cloud_guest.cleanup')
def test_register_cloud_baseprod_registration_ok_extensions_ok_complete(
    mock_cleanup, mock_get_config,
    mock_get_state_dir, mock_time_sleep,
    mock_os_path_isdir, mock_os_makedirs,
    mock_get_available_smt_servers, mock_write_framework_id,
    mock_is_zypper_running, mock_has_network_access,
    mock_set_new_registration_flag, mock_get_current_smt,
    mock_store_smt_data, mock_os_path_join,
    mock_has_region_changed, mock_uses_rmt_as_scc_proxy,
    mock_get_instance_data, mock_setup_registry, mock_setup_ltss_registration,
    mock_smt_is_responsive, mock_os_path_exists, mock_has_rmt_in_hosts,
    mock_clean_hosts_file, mock_add_hosts_entry, mock_has_registry_in_hosts,
    mock_update_rmt_cert, mock_get_register_cmd, mock_os_access,
    mock_set_as_current_smt, mock_logging, mock_get_installed_products,
    mock_import_smt_cert, mock_register_product,
    mock_set_rmt_as_scc_proxy_flag,
    mock_requests_get, mock_get_product_tree, mock_get_creds,
    mock_get_creds_file, mock_os_unlink, mock_has_nvidia_support,
    mock_find_repos, mock_get_repo_url, mock_exec_subprocess, mock_enable_repo,
    mock_urlparse, mock_set_proxy, mock_set_registration_completed_flag
):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="AA:BB:CC:DD"
         SMTserverIP="1.2.3.5"
         SMTserverIPv6="fc00::1"
         SMTserverName="foo-ec2.susecloud.net"
         SMTregistryName="registry-ec2.susecloud.net"
         region="antarctica-1"/>''')

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
    mock_os_path_join.return_value = ''
    prod_reg_type = namedtuple(
        'prod_reg_type', ['returncode', 'output', 'error']
    )
    mock_register_product.side_effect = [
        prod_reg_type(
            returncode=0,
            output='all OK',
            error='stderr'
        ),
        prod_reg_type(
            returncode=0,
            output='registration code',
            error='stderr'
        )
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
    mock_get_register_cmd.return_value = '/usr/sbin/SUSEConnect'
    mock_has_nvidia_support.return_value = True
    mock_find_repos.return_value = ['repo_a', 'repo_b']
    mock_get_repo_url.return_value = (
        'plugin:/susecloud?credentials=Basesystem_Module_x86_64&'
        'path=/repo/SUSE/Updates/SLE-Module-Basesystem/15-SP4/x86_64/update/'
    )
    mock_exec_subprocess.side_effect = [True, False]
    mock_urlparse.return_value = ParseResult(
        scheme='https', netloc='susecloud.net:443',
        path='/some/repo', params='',
        query='highlight=params', fragment='url-parsing'
    )
    mock_set_proxy.return_value = False
    assert register_cloud_guest.main(fake_args) is None
    assert mock_logging.info.call_args_list == [
        call('Forced new registration'),
        call(
            'Using user specified SMT server:\n\n\t"IP:1.2.3.5"\n\t"'
            'FQDN:foo-ec2.susecloud.net"\n\t"Fingerprint:AA:BB:CC:DD"'
        ),
        call('Region change detected, registering to new servers'),
        call('Baseproduct registration complete'),
        call(
            'Cannot reach host: "susecloud.net", will not enable repo "repo_a"'
        )
    ]


@patch('cloudregister.registerutils.set_registration_completed_flag')
@patch('cloudregister.registerutils.set_proxy')
@patch('register_cloud_guest.urllib.parse.urlparse')
@patch('cloudregister.registerutils.enable_repository')
@patch('cloudregister.registerutils.exec_subprocess')
@patch('cloudregister.registerutils.get_repo_url')
@patch('cloudregister.registerutils.find_repos')
@patch('cloudregister.registerutils.has_nvidia_support')
@patch('register_cloud_guest.registration_returncode', 0)
@patch('register_cloud_guest.os.unlink')
@patch('cloudregister.registerutils.get_credentials_file')
@patch('cloudregister.registerutils.get_credentials')
@patch('cloudregister.registerutils.get_product_tree')
@patch('cloudregister.registerutils.requests.get')
@patch('cloudregister.registerutils.set_rmt_as_scc_proxy_flag')
@patch('cloudregister.registerutils.register_product')
@patch('cloudregister.registerutils.import_smt_cert')
@patch('cloudregister.registerutils.get_installed_products')
@patch('register_cloud_guest.logging')
@patch('cloudregister.registerutils.set_as_current_smt')
@patch('register_cloud_guest.os.access')
@patch('cloudregister.registerutils.get_register_cmd')
@patch('cloudregister.registerutils.update_rmt_cert')
@patch('cloudregister.registerutils.has_registry_in_hosts')
@patch('cloudregister.registerutils.add_hosts_entry')
@patch('cloudregister.registerutils.clean_hosts_file')
@patch('cloudregister.registerutils.has_rmt_in_hosts')
@patch('cloudregister.registerutils.os.path.exists')
@patch.object(SMT, 'is_responsive')
@patch('register_cloud_guest.setup_ltss_registration')
@patch('register_cloud_guest.setup_registry')
@patch('cloudregister.registerutils.get_instance_data')
@patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
@patch('cloudregister.registerutils.has_region_changed')
@patch('cloudregister.registerutils.os.path.join')
@patch('cloudregister.registerutils.store_smt_data')
@patch('cloudregister.registerutils.get_current_smt')
@patch('cloudregister.registerutils.set_new_registration_flag')
@patch('cloudregister.registerutils.has_network_access_by_ip_address')
@patch('cloudregister.registerutils.is_zypper_running')
@patch('cloudregister.registerutils.write_framework_identifier')
@patch('cloudregister.registerutils.get_available_smt_servers')
@patch('register_cloud_guest.os.makedirs')
@patch('register_cloud_guest.os.path.isdir')
@patch('register_cloud_guest.time.sleep')
@patch('cloudregister.registerutils.get_state_dir')
@patch('cloudregister.registerutils.get_config')
@patch('register_cloud_guest.cleanup')
def test_register_cloud_baseprod_ok_recommended_extensions_ok_complete(
    mock_cleanup, mock_get_config,
    mock_get_state_dir, mock_time_sleep,
    mock_os_path_isdir, mock_os_makedirs,
    mock_get_available_smt_servers, mock_write_framework_id,
    mock_is_zypper_running, mock_has_network_access,
    mock_set_new_registration_flag, mock_get_current_smt,
    mock_store_smt_data, mock_os_path_join,
    mock_has_region_changed, mock_uses_rmt_as_scc_proxy,
    mock_get_instance_data, mock_setup_registry, mock_setup_ltss_registration,
    mock_smt_is_responsive, mock_os_path_exists, mock_has_rmt_in_hosts,
    mock_clean_hosts_file, mock_add_hosts_entry, mock_has_registry_in_hosts,
    mock_update_rmt_cert, mock_get_register_cmd, mock_os_access,
    mock_set_as_current_smt, mock_logging, mock_get_installed_products,
    mock_import_smt_cert, mock_register_product,
    mock_set_rmt_as_scc_proxy_flag,
    mock_requests_get, mock_get_product_tree, mock_get_creds,
    mock_get_creds_file, mock_os_unlink, mock_has_nvidia_support,
    mock_find_repos, mock_get_repo_url, mock_exec_subprocess, mock_enable_repo,
    mock_urlparse, mock_set_proxy, mock_set_registration_completed_flag
):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="AA:BB:CC:DD"
         SMTserverIP="1.2.3.5"
         SMTserverIPv6="fc00::1"
         SMTserverName="foo-ec2.susecloud.net"
         SMTregistryName="registry-ec2.susecloud.net"
         region="antarctica-1"/>''')
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
    mock_os_path_join.return_value = ''
    prod_reg_type = namedtuple(
        'prod_reg_type', ['returncode', 'output', 'error']
    )
    mock_register_product.side_effect = [
        prod_reg_type(
            returncode=0,
            output='all OK',
            error='stderr'
        ),
        prod_reg_type(
            returncode=0,
            output='registration code',
            error='stderr'
        )
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
                'friendly_name':
                'SUSE Linux Enterprise Server LTSS 15 SP4 x86_64',
                'product_class': 'SLES15-SP4-LTSS-X86',
                'free': False,
                'repositories': [],
                'product_type': 'extension',
                'extensions': [],
                'recommended': True,
                'available': True
            }
        ]
    }
    response.json = json_mock
    mock_requests_get.return_value = response
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
    mock_get_register_cmd.return_value = '/usr/sbin/SUSEConnect'
    mock_has_nvidia_support.return_value = True
    mock_find_repos.return_value = ['repo_a', 'repo_b']
    mock_get_repo_url.return_value = (
        'plugin:/susecloud?credentials=Basesystem_Module_x86_64&'
        'path=/repo/SUSE/Updates/SLE-Module-Basesystem/15-SP4/x86_64/update/'
    )
    mock_exec_subprocess.side_effect = [True, False]
    mock_urlparse.return_value = ParseResult(
        scheme='https', netloc='susecloud.net:443',
        path='/some/repo', params='',
        query='highlight=params', fragment='url-parsing'
    )
    mock_set_proxy.return_value = False
    assert register_cloud_guest.main(fake_args) is None
    assert mock_logging.info.call_args_list == [
        call('Forced new registration'),
        call(
            'Using user specified SMT server:\n\n\t"IP:fc00::1"\n\t"'
            'FQDN:foo-ec2.susecloud.net"\n\t"Fingerprint:AA:BB:CC:DD"'
        ),
        call('Region change detected, registering to new servers'),
        call('Baseproduct registration complete'),
        call(
            'Cannot reach host: "susecloud.net", will not enable repo "repo_a"'
        )
    ]


@patch('cloudregister.registerutils.set_registration_completed_flag')
@patch('register_cloud_guest.os.system')
@patch('cloudregister.registerutils.set_proxy')
@patch('register_cloud_guest.urllib.parse.urlparse')
@patch('cloudregister.registerutils.enable_repository')
@patch('cloudregister.registerutils.exec_subprocess')
@patch('cloudregister.registerutils.get_repo_url')
@patch('cloudregister.registerutils.find_repos')
@patch('cloudregister.registerutils.has_nvidia_support')
@patch('register_cloud_guest.registration_returncode', 0)
@patch('register_cloud_guest.os.unlink')
@patch('cloudregister.registerutils.get_credentials_file')
@patch('cloudregister.registerutils.get_credentials')
@patch('cloudregister.registerutils.get_product_tree')
@patch('cloudregister.registerutils.requests.get')
@patch('cloudregister.registerutils.set_rmt_as_scc_proxy_flag')
@patch('cloudregister.registerutils.register_product')
@patch('cloudregister.registerutils.import_smt_cert')
@patch('cloudregister.registerutils.get_installed_products')
@patch('register_cloud_guest.logging')
@patch('cloudregister.registerutils.set_as_current_smt')
@patch('register_cloud_guest.os.access')
@patch('cloudregister.registerutils.get_register_cmd')
@patch('cloudregister.registerutils.update_rmt_cert')
@patch('cloudregister.registerutils.has_registry_in_hosts')
@patch('cloudregister.registerutils.add_hosts_entry')
@patch('cloudregister.registerutils.clean_hosts_file')
@patch('cloudregister.registerutils.has_rmt_in_hosts')
@patch('cloudregister.registerutils.os.path.exists')
@patch.object(SMT, 'is_responsive')
@patch('register_cloud_guest.setup_ltss_registration')
@patch('register_cloud_guest.setup_registry')
@patch('cloudregister.registerutils.get_instance_data')
@patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
@patch('cloudregister.registerutils.has_region_changed')
@patch('cloudregister.registerutils.os.path.join')
@patch('cloudregister.registerutils.store_smt_data')
@patch('cloudregister.registerutils.get_current_smt')
@patch('cloudregister.registerutils.set_new_registration_flag')
@patch('cloudregister.registerutils.has_network_access_by_ip_address')
@patch('cloudregister.registerutils.is_zypper_running')
@patch('cloudregister.registerutils.write_framework_identifier')
@patch('cloudregister.registerutils.get_available_smt_servers')
@patch('register_cloud_guest.os.makedirs')
@patch('register_cloud_guest.os.path.isdir')
@patch('register_cloud_guest.time.sleep')
@patch('cloudregister.registerutils.get_state_dir')
@patch('cloudregister.registerutils.get_config')
@patch('register_cloud_guest.cleanup')
def test_reg_cloud_baseprod_ok_recommended_extensions_failed_is_transactional(
    mock_cleanup, mock_get_config,
    mock_get_state_dir, mock_time_sleep,
    mock_os_path_isdir, mock_os_makedirs,
    mock_get_available_smt_servers, mock_write_framework_id,
    mock_is_zypper_running, mock_has_network_access,
    mock_set_new_registration_flag, mock_get_current_smt,
    mock_store_smt_data, mock_os_path_join,
    mock_has_region_changed, mock_uses_rmt_as_scc_proxy,
    mock_get_instance_data, mock_setup_registry, mock_setup_ltss_registration,
    mock_smt_is_responsive, mock_os_path_exists, mock_has_rmt_in_hosts,
    mock_clean_hosts_file, mock_add_hosts_entry, mock_has_registry_in_hosts,
    mock_update_rmt_cert, mock_get_register_cmd, mock_os_access,
    mock_set_as_current_smt, mock_logging, mock_get_installed_products,
    mock_import_smt_cert, mock_register_product,
    mock_set_rmt_as_scc_proxy_flag,
    mock_requests_get, mock_get_product_tree, mock_get_creds,
    mock_get_creds_file, mock_os_unlink, mock_has_nvidia_support,
    mock_find_repos, mock_get_repo_url, mock_exec_subprocess, mock_enable_repo,
    mock_urlparse, mock_set_proxy, mock_os_system,
    mock_set_registration_completed_flag
):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="AA:BB:CC:DD"
         SMTserverIP="1.2.3.5"
         SMTserverIPv6="fc00::1"
         SMTserverName="foo-ec2.susecloud.net"
         SMTregistryName="registry-ec2.susecloud.net"
         region="antarctica-1"/>''')
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
    mock_os_path_join.return_value = ''
    prod_reg_type = namedtuple(
        'prod_reg_type', ['returncode', 'output', 'error']
    )
    mock_register_product.side_effect = [
        prod_reg_type(
            returncode=0,
            output='all OK',
            error='stderr'
        ),
        prod_reg_type(
            returncode=67,
            output='registration code',
            error='stderr'
        )
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
                'friendly_name':
                'SUSE Linux Enterprise Server LTSS 15 SP4 x86_64',
                'product_class': 'SLES15-SP4-LTSS-FOO-X86',
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
    mock_get_register_cmd.return_value = '/usr/sbin/SUSEConnect'
    mock_has_nvidia_support.return_value = False
    mock_find_repos.return_value = ['repo_a', 'repo_b']
    mock_get_repo_url.return_value = (
        'plugin:/susecloud?credentials=Basesystem_Module_x86_64&'
        'path=/repo/SUSE/Updates/SLE-Module-Basesystem/15-SP4/x86_64/update/'
    )
    findmnt_return = b'{"filesystems": [{"target": "/","source": ' + \
        b'"/dev/sda3","fstype": "xfs","options": "ro"}]}'
    mock_exec_subprocess.return_value = findmnt_return, b'', 0
    mock_os_path_exists.reset_mock()
    mock_os_path_exists.return_value = True
    mock_urlparse.return_value = ParseResult(
        scheme='https', netloc='susecloud.net:443',
        path='/some/repo', params='',
        query='highlight=params', fragment='url-parsing'
    )
    mock_set_proxy.return_value = False

    with patch('sys.stdout', new_callable=StringIO) as buffer:
        assert register_cloud_guest.main(fake_args) is None
    fake_stdout = buffer.getvalue()

    assert 'Registration succeeded' in fake_stdout
    assert 'There are products that were not registered' in fake_stdout
    assert 'transactional-update register -p' in fake_stdout
    assert 'SLES-LTSS-FOO/15.4/x86_64' in fake_stdout
    assert '-r ADDITIONAL REGCODE' in fake_stdout


@patch('cloudregister.registerutils.set_proxy')
@patch('register_cloud_guest.get_responding_update_server')
@patch('cloudregister.registerutils.is_registration_supported')
@patch('cloudregister.registerutils.fetch_smt_data')
@patch('register_cloud_guest.urllib.parse.urlparse')
@patch('cloudregister.registerutils.enable_repository')
@patch('cloudregister.registerutils.exec_subprocess')
@patch('cloudregister.registerutils.get_repo_url')
@patch('cloudregister.registerutils.find_repos')
@patch('cloudregister.registerutils.has_nvidia_support')
@patch('register_cloud_guest.registration_returncode', 0)
@patch('register_cloud_guest.os.unlink')
@patch('cloudregister.registerutils.get_credentials_file')
@patch('cloudregister.registerutils.get_credentials')
@patch('cloudregister.registerutils.get_product_tree')
@patch('cloudregister.registerutils.requests.get')
@patch('cloudregister.registerutils.set_rmt_as_scc_proxy_flag')
@patch('cloudregister.registerutils.register_product')
@patch('cloudregister.registerutils.import_smt_cert')
@patch('cloudregister.registerutils.get_installed_products')
@patch('register_cloud_guest.logging')
@patch('cloudregister.registerutils.set_as_current_smt')
@patch('register_cloud_guest.os.access')
@patch('cloudregister.registerutils.get_register_cmd')
@patch('cloudregister.registerutils.update_rmt_cert')
@patch('cloudregister.registerutils.has_registry_in_hosts')
@patch('cloudregister.registerutils.add_hosts_entry')
@patch('cloudregister.registerutils.clean_hosts_file')
@patch('cloudregister.registerutils.has_rmt_in_hosts')
@patch('cloudregister.registerutils.os.path.exists')
@patch.object(SMT, 'is_responsive')
@patch('register_cloud_guest.setup_ltss_registration')
@patch('register_cloud_guest.setup_registry')
@patch('cloudregister.registerutils.get_instance_data')
@patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
@patch('cloudregister.registerutils.has_region_changed')
@patch('cloudregister.registerutils.os.path.join')
@patch('cloudregister.registerutils.store_smt_data')
@patch('cloudregister.registerutils.get_current_smt')
@patch('cloudregister.registerutils.set_new_registration_flag')
@patch('cloudregister.registerutils.has_network_access_by_ip_address')
@patch('cloudregister.registerutils.is_zypper_running')
@patch('cloudregister.registerutils.write_framework_identifier')
@patch('cloudregister.registerutils.get_available_smt_servers')
@patch('register_cloud_guest.os.makedirs')
@patch('register_cloud_guest.os.path.isdir')
@patch('register_cloud_guest.time.sleep')
@patch('cloudregister.registerutils.get_state_dir')
@patch('cloudregister.registerutils.get_config')
@patch('register_cloud_guest.cleanup')
def test_register_cloud_baseprod_ok_recommended_extensions_ok_complete_no_ip(
    mock_cleanup, mock_get_config,
    mock_get_state_dir, mock_time_sleep,
    mock_os_path_isdir, mock_os_makedirs,
    mock_get_available_smt_servers, mock_write_framework_id,
    mock_is_zypper_running, mock_has_network_access,
    mock_set_new_registration_flag, mock_get_current_smt,
    mock_store_smt_data, mock_os_path_join,
    mock_has_region_changed, mock_uses_rmt_as_scc_proxy,
    mock_get_instance_data, mock_setup_registry, mock_setup_ltss_registration,
    mock_smt_is_responsive, mock_os_path_exists, mock_has_rmt_in_hosts,
    mock_clean_hosts_file, mock_add_hosts_entry, mock_has_registry_in_hosts,
    mock_update_rmt_cert, mock_get_register_cmd, mock_os_access,
    mock_set_as_current_smt, mock_logging, mock_get_installed_products,
    mock_import_smt_cert, mock_register_product,
    mock_set_rmt_as_scc_proxy_flag,
    mock_requests_get, mock_get_product_tree, mock_get_creds,
    mock_get_creds_file, mock_os_unlink, mock_has_nvidia_support,
    mock_find_repos, mock_get_repo_url, mock_exec_subprocess, mock_enable_repo,
    mock_urlparse, mock_fetch_smt_data,
    mock_is_reg_supported, mock_get_responding_update_server, mock_set_proxy
):
    mock_set_proxy.return_value = False
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="AA:BB:CC:DD"
         SMTserverIP="1.2.3.5"
         SMTserverIPv6="fc00::1"
         SMTserverName="foo-ec2.susecloud.net"
         SMTregistryName="registry-ec2.susecloud.net"
         region="antarctica-1"/>''')
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
    mock_os_path_join.return_value = ''
    prod_reg_type = namedtuple(
        'prod_reg_type', ['returncode', 'output', 'error']
    )
    mock_register_product.side_effect = [
        prod_reg_type(
            returncode=0,
            output='all OK',
            error='stderr'
        ),
        prod_reg_type(
            returncode=0,
            output='registration code',
            error='stderr'
        )
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
                'friendly_name':
                'SUSE Linux Enterprise Server LTSS 15 SP4 x86_64',
                'product_class': 'SLES15-SP4-LTSS-X86',
                'free': False,
                'repositories': [],
                'product_type': 'extension',
                'extensions': [],
                'recommended': True,
                'available': True
            }
        ]
    }
    response.json = json_mock
    mock_requests_get.return_value = response
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
    mock_get_register_cmd.return_value = '/usr/sbin/SUSEConnect'
    mock_has_nvidia_support.return_value = True
    mock_find_repos.return_value = ['repo_a', 'repo_b']
    mock_get_repo_url.return_value = (
        'plugin:/susecloud?credentials=Basesystem_Module_x86_64&'
        'path=/repo/SUSE/Updates/SLE-Module-Basesystem/15-SP4/x86_64/update/'
    )
    mock_exec_subprocess.side_effect = [True, False]
    mock_urlparse.return_value = ParseResult(
        scheme='https', netloc='susecloud.net:443',
        path='/some/repo', params='',
        query='highlight=params', fragment='url-parsing'
    )
    with raises(SystemExit) as sys_exit:
        with patch('builtins.open', mock_open()):
            register_cloud_guest.main(fake_args)
    assert sys_exit.value.code == 0
    assert mock_logging.info.call_args_list == [
        call('Forced new registration'),
        call('Region change detected, registering to new servers')
    ]


@patch('cloudregister.registerutils.register_product')
def test_register_modules(mock_register_product):
    prod_reg_type = namedtuple(
        'prod_reg_type', ['returncode', 'output', 'error']
    )

    mock_register_product.return_value = prod_reg_type(
        returncode=67,
        output='registration code',
        error='stderr'
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
    register_cloud_guest.register_modules(
        extensions, ['SLES-LTSS/15.4/x86_64'], 'reg_target', 'path', [], []
    )


@patch('cloudregister.registerutils.register_product')
def test_register_modules_failed_credentials(mock_register_product):
    prod_reg_type = namedtuple(
        'prod_reg_type', ['returncode', 'output', 'error']
    )

    mock_register_product.return_value = prod_reg_type(
        returncode=67,
        output='',
        error='missing system credentials try again'
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
    register_cloud_guest.register_modules(
        extensions, ['SLES-LTSS/15.4/x86_64'], 'reg_target', 'path', [], []
    )


@patch('cloudregister.registerutils.is_registry_registered')
@patch('cloudregister.registerutils.get_credentials_file')
@patch('cloudregister.registerutils.get_credentials')
@patch('cloudregister.registerutils.set_registries_conf_docker')
@patch('os.path.exists')
def test_setup_registry_registered(
    mock_os_path_exists, mock_set_registries_conf_docker,
    mock_get_credentials, mock_get_credentials_file,
    mock_is_registry_registered
):
    mock_os_path_exists.return_value = True
    mock_set_registries_conf_docker.return_value = False
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="AA:BB:CC:DD"
         SMTserverIP="1.2.3.5"
         SMTserverIPv6="fc00::1"
         SMTserverName="foo-ec2.susecloud.net"
         SMTregistryName="registry-ec2.susecloud.net"
         region="antarctica-1"/>''')
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


@patch('register_cloud_guest.cleanup')
@patch('cloudregister.registerutils.prepare_registry_setup')
@patch('cloudregister.registerutils.is_registry_registered')
@patch('cloudregister.registerutils.get_credentials_file')
@patch('cloudregister.registerutils.get_credentials')
def test_setup_clean_all(
    mock_get_credentials, mock_get_credentials_file,
    mock_is_registry_registered, mock_prepare_registry_setup,
    mock_cleanup
):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="AA:BB:CC:DD"
         SMTserverIP="1.2.3.5"
         SMTserverIPv6="fc00::1"
         SMTserverName="foo-ec2.susecloud.net"
         SMTregistryName="registry-ec2.susecloud.net"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_credentials.return_value = 'foo', 'bar'
    mock_is_registry_registered.return_value = False
    mock_prepare_registry_setup.return_value = False
    with raises(SystemExit) as sys_exit:
        register_cloud_guest.setup_registry(smt_server, 'all')
    assert sys_exit.value.code == 1


@patch('cloudregister.registerutils.clean_registry_setup')
@patch('cloudregister.registerutils.prepare_registry_setup')
@patch('cloudregister.registerutils.is_registry_registered')
@patch('cloudregister.registerutils.get_credentials_file')
@patch('cloudregister.registerutils.get_credentials')
def test_setup_clean_registry(
    mock_get_credentials, mock_get_credentials_file,
    mock_is_registry_registered, mock_prepare_registry_setup,
    mock_clean_registry_setup
):
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="AA:BB:CC:DD"
         SMTserverIP="1.2.3.5"
         SMTserverIPv6="fc00::1"
         SMTserverName="foo-ec2.susecloud.net"
         SMTregistryName="registry-ec2.susecloud.net"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_credentials.return_value = 'foo', 'bar'
    mock_is_registry_registered.return_value = False
    mock_prepare_registry_setup.return_value = False
    with raises(SystemExit) as sys_exit:
        register_cloud_guest.setup_registry(smt_server)
    assert sys_exit.value.code == 1


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
    mock_is_docker_present, mock_get_credentials,
    mock_get_credentials_file, mock_is_registry_registered,
    mock_is_suma_instance, mock_set_registry_fqdn_suma,
    mock_set_registries_conf_docker, mock_set_registries_conf_podman,
    mock_prepare_registry_setup
):
    mock_is_docker_present.return_value = True
    mock_is_suma_instance.return_value = True
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="AA:BB:CC:DD"
         SMTserverIP="1.2.3.5"
         SMTserverIPv6="fc00::1"
         SMTserverName="foo-ec2.susecloud.net"
         SMTregistryName="registry-ec2.susecloud.net"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_credentials.return_value = 'foo', 'bar'
    mock_is_registry_registered.return_value = False
    mock_prepare_registry_setup.return_value = True
    mock_set_registries_conf_podman.return_value = True
    mock_set_registries_conf_docker.return_value = True
    mock_set_registry_fqdn_suma.return_value = True
    assert register_cloud_guest.setup_registry(smt_server) is None
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
    mock_is_docker_present, mock_get_credentials,
    mock_get_credentials_file, mock_is_registry_registered,
    mock_is_suma_instance, mock_set_registry_fqdn_suma,
    mock_set_registries_conf_docker, mock_set_registries_conf_podman,
    mock_prepare_registry_setup
):
    mock_is_docker_present.return_value = False
    mock_is_suma_instance.return_value = True
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="AA:BB:CC:DD"
         SMTserverIP="1.2.3.5"
         SMTserverIPv6="fc00::1"
         SMTserverName="foo-ec2.susecloud.net"
         SMTregistryName="registry-ec2.susecloud.net"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_credentials.return_value = 'foo', 'bar'
    mock_is_registry_registered.return_value = False
    mock_prepare_registry_setup.return_value = True
    mock_set_registries_conf_podman.return_value = True
    mock_set_registry_fqdn_suma.return_value = True
    assert register_cloud_guest.setup_registry(smt_server) is None
    assert not mock_set_registries_conf_docker.called


@patch('register_cloud_guest.logging')
def test_get_responding_update_server_error(mock_logging):
    with raises(SystemExit) as sys_exit:
        assert register_cloud_guest.get_responding_update_server([])
    assert sys_exit.value.code == 1
    assert mock_logging.error.call_args_list == [call('No response from: []')]


@patch('register_cloud_guest.logging')
@patch('cloudregister.registerutils.get_product_tree')
def test_setup_ltss_registration_no_product(
    mock_get_product_tree, mock_logging
):
    mock_get_product_tree.return_value = None
    with raises(SystemExit) as sys_exit:
        register_cloud_guest.setup_ltss_registration(
            'target', 'regcode', 'instance_filepath'
        )
    assert sys_exit.value.code == 1
    assert mock_logging.error.call_args_list == [
        call('Cannot find baseproduct registration for LTSS')
    ]


@patch('register_cloud_guest.os.listdir')
@patch('register_cloud_guest.os.path.isdir')
@patch('register_cloud_guest.logging')
@patch('cloudregister.registerutils.get_product_tree')
def test_setup_ltss_registration_registered(
    mock_get_product_tree, mock_logging, mock_os_path_isdir, mock_os_listdir
):
    mock_get_product_tree.return_value = True
    mock_os_path_isdir.return_value = True
    mock_os_listdir.return_value = ['LTSS']
    assert register_cloud_guest.setup_ltss_registration(
        'target', 'regcode', 'instance_filepath'
    ) is None
    assert mock_logging.info.call_args_list == [
        call('Running LTSS registration...'),
        call('LTSS registration succeeded')
    ]


@patch('cloudregister.registerutils.register_product')
@patch('register_cloud_guest.os.listdir')
@patch('register_cloud_guest.os.path.isdir')
@patch('register_cloud_guest.logging')
@patch('cloudregister.registerutils.get_product_tree')
def test_setup_ltss_registration_registration_ok(
    mock_get_product_tree, mock_logging,
    mock_os_path_isdir, mock_os_listdir,
    mock_register_product
):
    mock_os_path_isdir.return_value = True
    mock_os_listdir.return_value = ['foo']
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
    assert register_cloud_guest.setup_ltss_registration(
        'target', 'regcode', 'instance_filepath'
    ) is None
    assert mock_logging.info.call_args_list == [
        call('Running LTSS registration...'),
        call('LTSS registration succeeded')
    ]


@patch('cloudregister.registerutils.register_product')
@patch('register_cloud_guest.os.listdir')
@patch('register_cloud_guest.os.path.isdir')
@patch('register_cloud_guest.logging')
@patch('cloudregister.registerutils.get_product_tree')
def test_setup_ltss_registration_registration_failed(
    mock_get_product_tree, mock_logging,
    mock_os_path_isdir, mock_os_listdir,
    mock_register_product
):
    mock_os_path_isdir.return_value = True
    mock_os_listdir.return_value = ['foo']
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
        returncode=7,
        output='not OK',
        error='stderr'
    )
    with raises(SystemExit) as sys_exit:
        register_cloud_guest.setup_ltss_registration(
            'target', 'regcode', 'instance_filepath'
        )
    assert sys_exit.value.code == 1
    assert mock_logging.error.call_args_list == [
        call('LTSS registration failed'),
        call('\tnot OK')
    ]


# Helper functions
class Response():
    """Fake a request response object"""
    def json(self):
        pass
