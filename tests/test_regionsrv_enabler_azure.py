import inspect
import importlib
import os
import sys

from lxml import etree
from pytest import raises
from textwrap import dedent
from unittest import mock
from unittest.mock import patch, call, MagicMock, Mock

test_path = os.path.abspath(
    os.path.dirname(inspect.getfile(inspect.currentframe())))
code_path = os.path.abspath('%s/../lib' % test_path)
data_path = test_path + os.sep + 'data/'

sys.path.insert(0, code_path)

from smt import SMT

# Hack to get the script without the .py imported for testing
from importlib.machinery import SourceFileLoader

regionsrv_enabler_azure = SourceFileLoader(
    'regionsrv_enabler_azure',
    './usr/sbin/regionsrv-enabler-azure'
).load_module()


@patch('regionsrv_enabler_azure.run_command')
@patch('regionsrv_enabler_azure.update_license_cache')
@patch('regionsrv_enabler_azure.has_license_changed')
@patch('regionsrv_enabler_azure.get_license_type')
@patch('cloudregister.registerutils.is_registered')
@patch('cloudregister.registerutils.is_scc_connected')
@patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
@patch('cloudregister.registerutils.get_smt')
def test_main_from_SLES_to_BYOS_cache_OK(
    mock_get_smt,
    mock_uses_rmt_as_scc_proxy,
    mock_is_scc_connected,
    mock_is_registered,
    mock_get_license_type,
    mock_has_license_changed,
    mock_update_license_cache,
    mock_run_command
):
    """
    Test a license type change from SLES to BYOS
    with an existing cache with SLES value in it.
    """
    mock_uses_rmt_as_scc_proxy.return_value = False
    mock_is_scc_connected.return_value = False
    mock_get_license_type.return_value = 'SLES_BYOS'
    mock_has_license_changed.return_value = True
    regionsrv_enabler_azure.main()
    assert mock_run_command.call_args_list == [
        call(['registercloudguest', '--clean']),
        call(['systemctl', 'disable', 'guestregister'])
    ]


@patch('regionsrv_enabler_azure.run_command')
@patch('regionsrv_enabler_azure.update_license_cache')
@patch('regionsrv_enabler_azure.has_license_changed')
@patch('regionsrv_enabler_azure.get_license_type')
@patch('cloudregister.registerutils.is_registered')
@patch('cloudregister.registerutils.is_scc_connected')
@patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
@patch('cloudregister.registerutils.get_smt')
def test_main_from_BYOS_to_SLES_cache_OK(
    mock_get_smt,
    mock_uses_rmt_as_scc_proxy,
    mock_is_scc_connected,
    mock_is_registered,
    mock_get_license_type,
    mock_has_license_changed,
    mock_update_license_cache,
    mock_run_command
):
    """
    Test a license type change from BYOS to SLES
    with an existing cache with SLES value in it.
    """
    mock_uses_rmt_as_scc_proxy.return_value = False
    mock_is_scc_connected.return_value = False
    mock_get_license_type.return_value = 'SLES'
    mock_has_license_changed.return_value = True
    regionsrv_enabler_azure.main()
    assert mock_run_command.call_args_list == [
        call(['registercloudguest', '--force-new']),
        call(['systemctl', 'enable', 'guestregister'])
    ]


@patch('regionsrv_enabler_azure.sys')
@patch('regionsrv_enabler_azure.run_command')
@patch('regionsrv_enabler_azure.update_license_cache')
@patch('regionsrv_enabler_azure.has_license_changed')
@patch('regionsrv_enabler_azure.get_license_type')
@patch('cloudregister.registerutils.is_registered')
@patch('cloudregister.registerutils.is_scc_connected')
@patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
@patch('cloudregister.registerutils.get_smt')
def test_main_SLES_no_change_cache_OK(
    mock_get_smt,
    mock_uses_rmt_as_scc_proxy,
    mock_is_scc_connected,
    mock_is_registered,
    mock_get_license_type,
    mock_has_license_changed,
    mock_update_license_cache,
    mock_run_command,
    mock_sys
):
    """
    Test a SLES license type that has no change
    with an existing cache with SLES value in it.
    """
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.2.1"
         SMTserverIPv6="fc00::2"
         SMTserverName="fantasy.example.net"
         region="antarctica-1"/>''')
    smt = SMT(etree.fromstring(smt_data_ipv46))

    mock_uses_rmt_as_scc_proxy.return_value = False
    mock_is_scc_connected.return_value = False
    mock_get_license_type.return_value = 'SLES'
    mock_has_license_changed.return_value = False
    mock_is_registered.return_value = True
    mock_get_smt.return_value = smt
    regionsrv_enabler_azure.main()
    mock_sys.exit.assert_called_once_with(0)


@patch('regionsrv_enabler_azure.sys')
@patch('regionsrv_enabler_azure.run_command')
@patch('regionsrv_enabler_azure.update_license_cache')
@patch('regionsrv_enabler_azure.has_license_changed')
@patch('regionsrv_enabler_azure.get_license_type')
@patch('cloudregister.registerutils.is_registered')
@patch('cloudregister.registerutils.is_scc_connected')
@patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
@patch('cloudregister.registerutils.get_smt')
def test_main_unregistered_BYOS_no_change_cache_OK(
    mock_get_smt,
    mock_uses_rmt_as_scc_proxy,
    mock_is_scc_connected,
    mock_is_registered,
    mock_get_license_type,
    mock_has_license_changed,
    mock_update_license_cache,
    mock_run_command,
    mock_sys
):
    """
    Test an unregistered BYOS system that has no license type change
    with an existing cache with SLES_BYOS value in it.
    """
    mock_uses_rmt_as_scc_proxy.return_value = False
    mock_is_scc_connected.return_value = False
    mock_get_license_type.return_value = 'SLES_BYOS'
    mock_has_license_changed.return_value = False
    mock_get_smt.return_value = None
    regionsrv_enabler_azure.main()
    assert mock_run_command.not_called
    assert mock_sys.exit.not_called
    assert mock_update_license_cache.not_called


@patch('regionsrv_enabler_azure.sys')
@patch('regionsrv_enabler_azure.run_command')
@patch('regionsrv_enabler_azure.update_license_cache')
@patch('regionsrv_enabler_azure.has_license_changed')
@patch('regionsrv_enabler_azure.get_license_type')
@patch('cloudregister.registerutils.is_registered')
@patch('cloudregister.registerutils.is_scc_connected')
@patch('cloudregister.registerutils.uses_rmt_as_scc_proxy')
@patch('cloudregister.registerutils.get_smt')
def test_main_registered_SLES_to_BYOS_no_cache(
    mock_get_smt,
    mock_uses_rmt_as_scc_proxy,
    mock_is_scc_connected,
    mock_is_registered,
    mock_get_license_type,
    mock_has_license_changed,
    mock_update_license_cache,
    mock_run_command,
    mock_sys
):
    """
    Test an unregistered BYOS system that has no license type change
    with an existing cache with SLES_BYOS value in it.
    """
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.2.1"
         SMTserverIPv6="fc00::2"
         SMTserverName="fantasy.example.net"
         region="antarctica-1"/>''')
    smt = SMT(etree.fromstring(smt_data_ipv46))
    mock_uses_rmt_as_scc_proxy.return_value = False
    mock_is_scc_connected.return_value = False
    mock_get_license_type.return_value = 'SLES_BYOS'
    mock_has_license_changed.return_value = False
    mock_get_smt.return_value = smt
    mock_is_registered.return_value = True
    regionsrv_enabler_azure.main()
    assert mock_run_command.call_args_list == [
        call(['registercloudguest', '--clean']),
        call(['systemctl', 'disable', 'guestregister'])
    ]
    assert mock_update_license_cache.not_called


def test_update_license_cache():
    """
    Test update the cahce with a new license type.
    """
    open_mock = mock.mock_open(read_data='SLES')
    def open_f(filename, *args, **kwargs):
         return open_mock()
    with patch('builtins.open', create=True) as mock_open:
       mock_open.side_effect = open_f
       regionsrv_enabler_azure.update_license_cache('foo')
       assert mock_open.call_args_list == [
           call('/var/cache/cloudregister/cached_license', 'w+')
       ]
       mock_open(
           'tests/data/repo_foo.repo', 'w'
       ).write.assert_called_once_with('foo')


def test_has_license_changed():
    """
    Test if license has changed compared to the cached value.
    """
    open_mock = mock.mock_open(read_data='SLES')
    def open_f(filename, *args, **kwargs):
         return open_mock()
    with patch('builtins.open', create=True) as mock_open:
       mock_open.side_effect = open_f
       assert regionsrv_enabler_azure.has_license_changed('foo') == True
       assert mock_open.call_args_list == [
           call('/var/cache/cloudregister/cached_license', 'r')
       ]


def test_has_license_changed_no_changed():
    """
    Test if license has changed compared to the cached value.
    """
    open_mock = mock.mock_open(read_data='SLES')
    def open_f(filename, *args, **kwargs):
         return open_mock()
    with patch('builtins.open', create=True) as mock_open:
       mock_open.side_effect = open_f
       assert regionsrv_enabler_azure.has_license_changed('SLES') == False
       assert mock_open.call_args_list == [
           call('/var/cache/cloudregister/cached_license', 'r')
       ]


@patch('regionsrv_enabler_azure.update_license_cache')
def test_has_license_changed_file_not_found(mock_update_license_cache):
    """
    Test if license has changed compared to the cached value.
    """
    with patch('builtins.open', create=True) as mock_open:
       mock_open.side_effect = FileNotFoundError('oh no')
       assert regionsrv_enabler_azure.has_license_changed('SLES') == False
       assert mock_open.call_args_list == [
           call('/var/cache/cloudregister/cached_license', 'r')
       ]
       mock_update_license_cache.assert_called_once_with('SLES')


@patch('regionsrv_enabler_azure.requests.get')
def test_get_license_type_request_OK(mock_request_get):
    """
    Test getting the license type from instance metadata.
    """
    response = Mock()
    response.status_code = 200
    response.text = 'SLES'
    mock_request_get.return_value = response
    assert regionsrv_enabler_azure.get_license_type() == 'SLES'
    mock_request_get.assert_called_once_with(
        'http://169.254.169.254/metadata/instance/compute/licenseType?'
        'api-version=2021-03-01&format=text',
        headers={'Metadata': 'true'},
        proxies={'http': None, 'https': None}
    )


@patch('regionsrv_enabler_azure.sys')
@patch('regionsrv_enabler_azure.logging')
@patch('regionsrv_enabler_azure.requests.get')
def test_get_license_type_request_not_200(
    mock_request_get,
    mock_logging,
    mock_sys
):
    """
    Test getting the license type from instance metadata
    when the response status code is not 200.
    """
    response = Mock()
    response.status_code = 422
    mock_request_get.return_value = response
    regionsrv_enabler_azure.get_license_type()
    mock_logging.error.assert_called_once_with(
        'Unable to obtain instance metadata'
    )
    mock_sys.exit.assert_called_once_with(1)
    mock_request_get.assert_called_once_with(
        'http://169.254.169.254/metadata/instance/compute/licenseType?'
        'api-version=2021-03-01&format=text',
        headers={'Metadata': 'true'},
        proxies={'http': None, 'https': None}
    )


@patch('regionsrv_enabler_azure.logging')
@patch('regionsrv_enabler_azure.subprocess.Popen')
def test_run_command_error(mock_popen, mock_logging):
    """
    Test run command that failes.
    """
    mock_process = Mock()
    mock_process.communicate = Mock(
        return_value=[str.encode(''), str.encode('error')]
    )
    mock_process.returncode = 1
    mock_popen.return_value = mock_process
    with raises(SystemExit) as pytest_wrapped_e:
        regionsrv_enabler_azure.run_command('foo')
    mock_logging.info.assert_called_once_with('Calling foo')
    mock_logging.error.assert_called_once_with(
        'EXEC: Failed with stderr: error, stdout: ')


@patch('regionsrv_enabler_azure.logging')
@patch('regionsrv_enabler_azure.subprocess.Popen')
def test_run_command_exception(mock_popen, mock_logging):
    """
    Test run command produces an exception.
    """
    mock_popen.side_effect = Exception('An exception !')
    with raises(SystemExit) as pytest_wrapped_e:
        regionsrv_enabler_azure.run_command(['foo'])
    mock_logging.info.assert_called_once_with("Calling ['foo']")
    mock_logging.error.assert_called_once_with(
        'EXEC: Exception running command foo with issue: '
        'Exception: An exception !'
    )


@patch('regionsrv_enabler_azure.logging')
@patch('regionsrv_enabler_azure.subprocess.Popen')
def test_run_command(mock_popen, mock_logging):
    """
    Test run command.
    """
    mock_process = Mock()
    mock_process.communicate = Mock(
        return_value=[str.encode('OK'), str.encode('')]
    )
    mock_process.returncode = 0
    mock_popen.return_value = mock_process
    assert regionsrv_enabler_azure.run_command(['foo']) == 'OK'
    mock_logging.info.assert_called_once_with("Calling ['foo']")
    assert mock_logging.error.not_called


