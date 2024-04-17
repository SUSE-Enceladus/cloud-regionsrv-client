import inspect
import os
import sys

from lxml import etree

from cloudregister.smt import SMT
from importlib.machinery import SourceFileLoader

from pytest import raises
from textwrap import dedent
from unittest.mock import patch

test_path = os.path.abspath(
    os.path.dirname(inspect.getfile(inspect.currentframe())))
code_path = os.path.abspath('%s/../lib' % test_path)
data_path = test_path + os.sep + 'data/'

sys.path.insert(0, code_path)

# Hack to get the script without the .py imported for testing
cloudguestregistryauth = SourceFileLoader(
    'cloudguestregistryauth',
    './usr/sbin/cloudguestregistryauth'
).load_module()


@patch('cloudguestregistryauth.os.geteuid')
def test_registry_call_as_root(mock_os_geteuid):
    mock_os_geteuid.return_value = 1
    with raises(SystemExit) as pytest_wrapped_e:
        cloudguestregistryauth.main()

    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 'You must be root'


@patch('cloudregister.registerutils.get_activations')
@patch('cloudregister.registerutils.is_registered')
@patch('cloudregister.registerutils.get_current_smt')
@patch('cloudguestregistryauth.os.geteuid')
def test_registry_get_activations_error(
    mock_os_geteuid, mock_get_current_smt,
    mock_is_registered, mock_get_activations
):
    mock_os_geteuid.return_value = 0
    mock_is_registered.return_value = True
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="fantasy.example.com"
         SMTregistryName="registry-fantasy.example.com"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_current_smt.return_value = smt_server
    mock_get_activations.return_value = {}

    with raises(SystemExit) as pytest_wrapped_e:
        cloudguestregistryauth.main()

    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 'Could not refresh credentials'


@patch('builtins.print')
@patch('cloudregister.registerutils.get_activations')
@patch('cloudregister.registerutils.is_registered')
@patch('cloudregister.registerutils.get_current_smt')
@patch('cloudguestregistryauth.os.geteuid')
def test_registry_get_activations(
    mock_os_geteuid, mock_get_current_smt,
    mock_is_registered, mock_get_activations,
    mock_print
):
    mock_os_geteuid.return_value = 0
    mock_is_registered.return_value = True
    smt_data_ipv46 = dedent('''\
        <smtInfo fingerprint="00:11:22:33"
         SMTserverIP="192.168.1.1"
         SMTserverIPv6="fc00::1"
         SMTserverName="fantasy.example.com"
         SMTregistryName="registry-fantasy.example.com"
         region="antarctica-1"/>''')
    smt_server = SMT(etree.fromstring(smt_data_ipv46))
    mock_get_current_smt.return_value = smt_server
    mock_get_activations.return_value = {'foo': 'bar'}

    cloudguestregistryauth.main()
    mock_print.assert_called_once_with('Credentials refreshed')
