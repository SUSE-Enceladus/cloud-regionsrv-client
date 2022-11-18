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
from unittest.mock import patch
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


@patch('cloudregister.registerutils.__get_framework_plugin')
@patch('cloudregister.registerutils.get_framework_identifier_path')
@patch('cloudregister.registerutils.exec_subprocess')
def test_has_region_changed_no_dmidecode_has_cache(subproc, id_path, plugin):
    subproc.side_effect = TypeError('demidecode failed')
    id_path.return_value = data_path + 'framework_info'
    plugin.return_value = False
    assert True == utils.has_region_changed(cfg)


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


@patch('cloudregister.registerutils.__get_region_server_args')
@patch('cloudregister.registerutils.__get_framework_plugin')
@patch('cloudregister.registerutils.get_framework_identifier_path')
@patch('cloudregister.registerutils.exec_subprocess')
def test_has_region_changed_no_data(
        subproc, id_path, plugin, srvargs
):
    subproc.return_value = (b'Google', b'')
    id_path.return_value = 'foo'
    plugin.return_value = True
    srvargs.return_value = 'regionHint=us-east2-f'
    assert False == utils.has_region_changed(cfg)


def test_is_registration_supported_SUSE_Family():
    cfg.set('service', 'packageBackend', 'zypper')
    assert utils.is_registration_supported(cfg) is True


def test_is_registration_supported_RHEL_Family():
    cfg.set('service', 'packageBackend', 'dnf')
    assert utils.is_registration_supported(cfg) is False


@patch('cloudregister.registerutils.is_new_registration')
def test_update_rmt_certs_new_reg(new_reg):
    new_reg.return_value = True
    res = utils.update_rmt_certs()
    assert res is None


@patch('cloudregister.registerutils.import_smt_cert')
@patch('cloudregister.registerutils.get_config')
@patch('cloudregister.registerutils.fetch_smt_data')
@patch('cloudregister.registerutils.set_proxy')
@patch('cloudregister.registerutils.get_state_dir')
@patch('cloudregister.registerutils.is_new_registration')
def test_update_rmt_certs_no_cert_change(
        new_reg, state_dir, set_proxy, fetch_srvs, get_config, import_cert
):
    new_reg.return_value = False
    state_dir.return_value = data_path
    set_proxy.return_value = False
    fetch_srvs.return_value = get_servers_data()
    get_config.return_value = {}
    utils.update_rmt_certs()
    assert not import_cert.called


@patch('cloudregister.registerutils.__populate_srv_cache')
@patch('cloudregister.registerutils.clean_smt_cache')
@patch('cloudregister.registerutils.import_smt_cert')
@patch('cloudregister.registerutils.get_config')
@patch('cloudregister.registerutils.fetch_smt_data')
@patch('cloudregister.registerutils.set_proxy')
@patch('cloudregister.registerutils.get_state_dir')
@patch('cloudregister.registerutils.is_new_registration')
def test_update_rmt_certs_cert_change(
        new_reg, state_dir, set_proxy, fetch_srvs, get_config, import_cert,
        cache_clean, pop_cache
):
    new_reg.return_value = False
    state_dir.return_value = data_path
    set_proxy.return_value = False
    fetch_srvs.return_value = get_modified_servers_data()
    get_config.return_value = {}
    utils.update_rmt_certs()
    assert import_cert.called
    assert cache_clean.called
    assert pop_cache.called


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
