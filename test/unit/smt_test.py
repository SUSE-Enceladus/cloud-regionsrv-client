# Copyright (c) 2023, SUSE LLC, All rights reserved.
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

import glob
import os
import tempfile

from M2Crypto import X509
from lxml import etree
from pytest import fixture
from textwrap import dedent
from unittest.mock import patch, Mock

from cloudregister.logger import Logger
from cloudregister.smt import SMT  # noqa

test_path = ".."
data_path = test_path + os.sep + "data/"

log_instance = Logger()
log = Logger.get_logger()

smt_data_ipv4 = dedent(
    """\
    <smtInfo fingerprint="00:11:22:33"
     SMTserverIP="192.168.1.1"
     SMTserverName="fantasy.example.com"
     SMTregistryName="registry-fantasy.example.com"
     region="antarctica-1"/>"""
)

smt_data_ipv6 = dedent(
    """\
    <smtInfo fingerprint="00:44:22:33"
     SMTserverIPv6="fc00::1"
     SMTserverName="fantasy.example.com"
     SMTregistryName="registry-fantasy.example.com"
     region="antarctica-1"/>"""
)

smt_data_ipv46 = dedent(
    """\
    <smtInfo fingerprint="00:11:22:33"
     SMTserverIP="192.168.1.1"
     SMTserverIPv6="fc00::1"
     SMTserverName="fantasy.example.com"
     SMTregistryName="registry-fantasy.example.com"
     region="antarctica-1"/>"""
)

smt_data_no_region = dedent(
    """\
    <smtInfo fingerprint="00:11:22:33"
     SMTserverIP="localhost:1234"
     SMTserverName="fantasy.example.com"
     SMTregistryName="registry-fantasy.example.com"/>"""
)


# ----------------------------------------------------------------------------
class Response:
    """Fake a request response object"""

    pass


# ----------------------------------------------------------------------------
class TestSMT:
    @fixture(autouse=True)
    def inject_fixtures(self, caplog):
        self._caplog = caplog

    # ------------------------------------------------------------------------
    def test_ctor_ipv4(self):
        """Test object creation with IPv4 data only"""
        assert SMT(etree.fromstring(smt_data_ipv4), https_only=True)

    # ------------------------------------------------------------------------
    def test_ctor_ipv6(self):
        """Test object creation with IPv6 data only"""
        assert SMT(etree.fromstring(smt_data_ipv6))

    # ------------------------------------------------------------------------
    def test_ctor_dual(self):
        """Test object creation with IPv4 and IPv6 data only"""
        assert SMT(etree.fromstring(smt_data_ipv46))

    # ------------------------------------------------------------------------
    def test_ctor_no_region(self):
        """Test object whne no region is in the data"""
        smt = SMT(etree.fromstring(smt_data_no_region))
        assert smt.get_region() == "unknown"

    # ------------------------------------------------------------------------
    def test_equal_ipv4(self):
        """Test two SMT servers with same data,
        IPv4 only are considered equal"""
        smt1 = SMT(etree.fromstring(smt_data_ipv4))
        smt2 = SMT(etree.fromstring(smt_data_ipv4))
        assert smt1 == smt2

    # ------------------------------------------------------------------------
    def test_equal_ipv6(self):
        """Test two SMT servers with same data,
        IPv6 only are considered equal"""
        smt1 = SMT(etree.fromstring(smt_data_ipv6))
        smt2 = SMT(etree.fromstring(smt_data_ipv6))
        assert smt1 == smt2

    # ------------------------------------------------------------------------
    def test_equal_dual(self):
        """Test two SMT servers with same data, IPv4 and IPv6 are
        considered equal"""
        smt1 = SMT(etree.fromstring(smt_data_ipv46))
        smt2 = SMT(etree.fromstring(smt_data_ipv46))
        assert smt1 == smt2

    # ------------------------------------------------------------------------
    def test_not_equal_ipv4_ipv6(self):
        """Test two SMT servers with different data are not equal"""
        smt1 = SMT(etree.fromstring(smt_data_ipv4))
        smt2 = SMT(etree.fromstring(smt_data_ipv6))
        assert smt1 != smt2

    # ------------------------------------------------------------------------
    def test_not_equal_not_SMT_instance(self):
        """Test two SMT servers with different data are not equal"""
        smt1 = "foo"
        smt2 = SMT(etree.fromstring(smt_data_ipv6))
        assert smt1 != smt2

    # ------------------------------------------------------------------------
    @patch("cloudregister.smt.requests.get")
    def test_get_cert_invalid_cert(self, mock_cert_pull):
        """Received an invalid cert"""
        response = Response()
        response.status_code = 200
        response.text = "Not a cert"
        mock_cert_pull.return_value = response
        smt = SMT(etree.fromstring(smt_data_ipv46))
        assert not smt.get_cert()
        assert "Could not read X509 fingerprint from cert" in self._caplog.text

    # ------------------------------------------------------------------------
    @patch("cloudregister.smt.requests.get")
    def test_get_cert_access_exception_ipv4(self, mock_request_get):
        """Test the exception path for cert retrieval when we cannot reach
        an update server with IPv4 adddress"""
        mock_request_get.side_effect = Exception(
            "Server's too far, cant be reached"
        )
        smt = SMT(etree.fromstring(smt_data_ipv4))
        assert not smt.get_cert()
        assert "Server 192.168.1.1 is unreachable" in self._caplog.text

    # ------------------------------------------------------------------------
    @patch("cloudregister.smt.requests.get")
    def test_get_cert_access_exception_ipv6(self, mock_request_get):
        """Test the exception path for cert retrieval when we cannot reach
        an update server with IPv6 adddress"""
        mock_request_get.side_effect = Exception("FOO")
        smt = SMT(etree.fromstring(smt_data_ipv6))
        assert not smt.get_cert()
        assert "Server fc00::1 is unreachable" in self._caplog.text

    # ------------------------------------------------------------------------
    @patch("cloudregister.smt.X509.load_cert_string")
    @patch("cloudregister.smt.requests.get")
    def test_get_cert_no_match_cert(self, mock_cert_pull, mock_load_cert):
        """Test the received cert has a different fingerprint
        than stored one."""
        response = Response()
        response.status_code = 200
        response.text = "Not a cert"
        mock_cert_pull.return_value = response
        x509_mock = Mock()
        x509_mock.get_fingerprint.return_value = "not_matching_fingerprint"
        mock_load_cert.return_value = x509_mock
        smt = SMT(etree.fromstring(smt_data_ipv46))
        assert not smt.get_cert()
        assert "Fingerprint could not be verified" in self._caplog.text

    # ------------------------------------------------------------------------
    @patch.object(SMT, "get_fingerprint")
    @patch("cloudregister.smt.requests.get")
    def test_get_cert_not_found(self, mock_cert_pull, mock_get_fingerprint):
        """Test get cert."""
        response = Response()
        response.status_code = "404"
        mock_cert_pull.return_value = response
        smt = SMT(etree.fromstring(smt_data_ipv46))
        assert smt.get_cert() is None
        expected_msg = "Request to http://192.168.1.1/rmt.crt failed: 404"
        assert expected_msg in self._caplog.text

    # ------------------------------------------------------------------------
    @patch.object(SMT, "get_fingerprint")
    @patch("cloudregister.smt.requests.get")
    def test_get_cert(self, mock_cert_pull, mock_get_fingerprint):
        """Test get cert."""
        response = Response()
        response.status_code = 200
        with open("../data/cert.pem") as cert_file:
            response.text = cert_file.read()

        mock_cert_pull.return_value = response
        x509 = X509.load_cert_string(str(response.text))
        mock_get_fingerprint.return_value = x509.get_fingerprint("sha1")
        smt = SMT(etree.fromstring(smt_data_ipv46))
        assert smt.get_cert() == response.text
        expected_msg = "Request to http://[fc00::1]/smt.crt succeeded"
        assert expected_msg in self._caplog.text

    # ------------------------------------------------------------------------
    def test_get_domain_name(self):
        """Test get_domain_name returns expected value"""
        smt = SMT(etree.fromstring(smt_data_ipv6))
        assert "example.com" == smt.get_domain_name()

    # ------------------------------------------------------------------------
    def test_get_fingerprint(self):
        """Test get_fingerprint returns expected value"""
        smt = SMT(etree.fromstring(smt_data_ipv46))
        assert "00:11:22:33" == smt.get_fingerprint()

    # ------------------------------------------------------------------------
    def test_get_FQDN(self):
        """Test get_FQDN returns expected value"""
        smt = SMT(etree.fromstring(smt_data_ipv46))
        assert "fantasy.example.com" == smt.get_FQDN()

    # ------------------------------------------------------------------------
    def test_get_name(self):
        """Test get_name returns expected value"""
        smt = SMT(etree.fromstring(smt_data_ipv46))
        assert "fantasy" == smt.get_name()

    # ------------------------------------------------------------------------
    def test_get_ipv4(self):
        """Test get_ipv4 returns expected value"""
        smt = SMT(etree.fromstring(smt_data_ipv46))
        smt._ip = smt.get_ipv4()  # for old SMT objects
        assert "192.168.1.1" == smt.get_ipv4()

    # ------------------------------------------------------------------------
    def test_get_ipv4_null(self):
        """Test get_ipv4 returns expected value"""
        smt = SMT(etree.fromstring(smt_data_ipv6))
        assert not smt.get_ipv4()

    # ------------------------------------------------------------------------
    def test_get_ipv6(self):
        """Test get_ipv6 returns expected value"""
        smt = SMT(etree.fromstring(smt_data_ipv46))
        assert "fc00::1" == smt.get_ipv6()

    # ------------------------------------------------------------------------
    def test_get_ipv6_null(self):
        """Test get_ipv6 returns expected value"""
        smt = SMT(etree.fromstring(smt_data_ipv4))
        assert not smt.get_ipv6()
        del smt._ipv6  # for old SMT objects
        assert not smt.get_ipv6()

    # ------------------------------------------------------------------------
    def test_is_equivalent_on_ipv4(self):
        """Test two SMT servers with same name and fingerprint are treated
        as equivalent"""
        smt1 = SMT(etree.fromstring(smt_data_ipv4))
        smt2 = SMT(etree.fromstring(smt_data_ipv46))
        assert smt1.is_equivalent(smt2)

    # ------------------------------------------------------------------------
    def test_is_equivalent_on_ipv6(self):
        """Test two SMT servers with same name and fingerprint are treated
        as equivalent"""
        smt1 = SMT(etree.fromstring(smt_data_ipv6))
        smt2 = SMT(etree.fromstring(smt_data_ipv46))
        assert smt1.is_equivalent(smt2)

    # ------------------------------------------------------------------------
    def test_is_equivalent_fails_differ_ipv(self):
        """Test two SMT servers with different network config are not equivalent"""
        smt1 = SMT(etree.fromstring(smt_data_ipv4))
        smt2 = SMT(etree.fromstring(smt_data_ipv6))
        assert not smt1.is_equivalent(smt2)

    # ------------------------------------------------------------------------
    def test_is_equivalent_fails_differ_region(self):
        """Test two SMT servers with different regions are not equivalent"""
        smt1 = SMT(etree.fromstring(smt_data_ipv4))
        smt2 = SMT(etree.fromstring(smt_data_no_region))
        assert not smt1.is_equivalent(smt2)

    # ------------------------------------------------------------------------
    def test_is_equivalent_true_same(self):
        """Test that equal servers are also equivalent"""
        smt1 = SMT(etree.fromstring(smt_data_ipv4))
        smt2 = SMT(etree.fromstring(smt_data_ipv4))
        assert smt1.is_equivalent(smt2)

    # ------------------------------------------------------------------------
    @patch("cloudregister.smt.requests.get")
    def test_is_responsive_server_offline(self, mock_cert_pull):
        """Verify we detect a non responsive server"""
        mock_cert_pull.return_value = None
        smt = SMT(etree.fromstring(smt_data_ipv46))
        assert not smt.is_responsive()

    # ------------------------------------------------------------------------
    @patch("cloudregister.smt.requests.get")
    def test_is_responsive_server_error(self, mock_cert_pull):
        """Verify we detect a server an error as non responsive"""
        response = Response()
        response.status_code = 500
        response.text = "Not a cert"
        mock_cert_pull.return_value = response
        smt = SMT(etree.fromstring(smt_data_ipv46))
        assert not smt.is_responsive()

    # ------------------------------------------------------------------------
    @patch("cloudregister.smt.requests.get")
    def test_is_responsive_ok(self, mock_cert_pull):
        """Verify we detect a responsive server"""
        response = Mock()
        response.status_code = 200
        response.json.return_value = {"state": "online"}
        mock_cert_pull.return_value = response
        smt = SMT(etree.fromstring(smt_data_ipv46))
        assert smt.is_responsive() is True

    # ------------------------------------------------------------------------
    @patch("cloudregister.smt.requests.get")
    def test_is_responsive_not_found(self, mock_cert_pull):
        """
        Verify we detect a responsive server returning 404,
        make sure we download the cert (Apache is responsive).
        """
        first_request = Mock()
        first_request.status_code = 404
        first_request.json.return_value = {"state": "online"}
        second_request = Mock()
        second_request.status_code = 200
        mock_requests = Mock()
        mock_requests.side_effect = [first_request, second_request]

        mock_cert_pull.side_effect = mock_requests
        smt = SMT(etree.fromstring(smt_data_ipv46))
        assert smt.is_responsive() is True

    # ------------------------------------------------------------------------
    def test_set_protocol_none(self):
        smt = SMT(etree.fromstring(smt_data_ipv46))
        assert smt.set_protocol("foo") is None

    # ------------------------------------------------------------------------
    def test_set_protocol(self):
        smt = SMT(etree.fromstring(smt_data_ipv46))
        smt.set_protocol("https")
        assert smt._protocol == "https"

    # ------------------------------------------------------------------------
    def test_check_urls_ipv4(self):
        """Verify the correct urls are formed"""
        smt = SMT(etree.fromstring(smt_data_ipv4))
        assert (
            smt._check_urls.get("https://192.168.1.1/api/health/status")
            == "http://192.168.1.1/"
        )

    # ------------------------------------------------------------------------
    def test_check_urls_ipv6(self):
        """Verify the correct urls are formed"""
        smt = SMT(etree.fromstring(smt_data_ipv6))
        assert (
            smt._check_urls.get("https://[fc00::1]/api/health/status")
            == "http://[fc00::1]/"
        )

    # ------------------------------------------------------------------------
    def test_check_urls_ipv46(self):
        """Verify the correct urls are formed"""
        smt = SMT(etree.fromstring(smt_data_ipv46))
        assert (
            smt._check_urls.get("https://192.168.1.1/api/health/status")
            == "http://192.168.1.1/"
        )
        assert (
            smt._check_urls.get("https://[fc00::1]/api/health/status")
            == "http://[fc00::1]/"
        )

    # ------------------------------------------------------------------------
    @patch.object(SMT, "get_cert")
    def test_write_cert_ipv4_only(self, mock_get_cert):
        """Check we write the cert for the IPv4 address if the update server
        has an IPv4 only configuration"""
        mock_get_cert.return_value = "what a cert"
        smt = SMT(etree.fromstring(smt_data_ipv4))
        with tempfile.TemporaryDirectory() as tmpdirname:
            smt.write_cert(tmpdirname)
            certs = glob.glob("%s/*.pem" % tmpdirname)
            assert len(certs) == 1
            assert certs[0] == (
                "%s/registration_server_192_168_1_1.pem" % tmpdirname
            )

    # ------------------------------------------------------------------------
    @patch.object(SMT, "get_cert")
    def test_write_cert_ipv6_only(self, mock_get_cert):
        """Check we write the cert for the IPv6 address if the update server
        has an IPv6 only configuration"""
        mock_get_cert.return_value = "what a cert"
        smt = SMT(etree.fromstring(smt_data_ipv6))
        with tempfile.TemporaryDirectory() as tmpdirname:
            smt.write_cert(tmpdirname)
            certs = glob.glob("%s/*.pem" % tmpdirname)
            assert len(certs) == 1
            assert certs[0] == "%s/registration_server_fc00__1.pem" % tmpdirname

    # ------------------------------------------------------------------------
    @patch.object(SMT, "get_cert")
    def test_write_cert_dual_stack(self, mock_get_cert):
        """Check we write the cert for the IPv4 and IPv6 address if the update
        server has an IPv4 and IPv6 configuration"""
        mock_get_cert.return_value = "what a cert"
        smt = SMT(etree.fromstring(smt_data_ipv46))
        with tempfile.TemporaryDirectory() as tmpdirname:
            smt.write_cert(tmpdirname)
            certs = glob.glob("%s/*.pem" % tmpdirname)
            assert len(certs) == 2
            assert "%s/registration_server_fc00__1.pem" % tmpdirname in certs
            assert (
                "%s/registration_server_192_168_1_1.pem" % tmpdirname in certs
            )

    # --------------------------------------------------------------------
    @patch.object(SMT, "get_cert")
    def test_write_cert_no_write_perm(self, mock_get_cert):
        """Check that we properly handle the exception if we cannot write the
        cert."""
        mock_get_cert.return_value = "what a cert"
        smt = SMT(etree.fromstring(smt_data_ipv46))
        result = smt.write_cert("fussball")
        assert result == 0
        assert "Could not store update server certificate" in self._caplog.text
