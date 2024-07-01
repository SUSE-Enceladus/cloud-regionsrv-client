# import inspect
# import importlib
# import sys

# from argparse import Namespace
# from lxml import etree
from pytest import raises
# from textwrap import dedent
from types import SimpleNamespace
# from unittest import mock
# from unittest.mock import patch, call, MagicMock, Mock

# test_path = os.path.abspath(
#    os.path.dirname(inspect.getfile(inspect.currentframe())))
# code_path = os.path.abspath('%s/../lib' % test_path)
# data_path = test_path + os.sep + 'data/'

# sys.path.insert(0, code_path)

# Hack to get the script without the .py imported for testing
from importlib.machinery import SourceFileLoader

register_cloud_guest = SourceFileLoader(
    'register_cloud_guest',
    './usr/sbin/registercloudguest'
).load_module()


def test_register_cloud_guest_missing_param():
    fake_args = SimpleNamespace(
        user_smt_ip='1.2.3.4',
        user_smt_fqdn='foo.susecloud.net',
        user_smt_fp=None
    )
    with raises(SystemExit):
        assert register_cloud_guest.main(fake_args) is None
