# Copyright (c) 2026, SUSE LLC, All rights reserved.
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


import logging
import requests

from pytest import fixture
from unittest.mock import patch

import cloudregister.googlece as gce  # noqa

from cloudregister.logger import Logger

log_instance = Logger()
log = Logger.get_logger()


# ----------------------------------------------------------------------------
class Response:
    pass


# ----------------------------------------------------------------------------
class TestGCEPLugin:
    @fixture(autouse=True)
    def inject_fixtures(self, caplog):
        self._caplog = caplog

    # ------------------------------------------------------------------------
    @patch("cloudregister.googlece.requests.get")
    def test_request_fail(self, mock_request):
        """Test proper exception handling when request to metadata
        server fails"""
        mock_request.side_effect = requests.exceptions.RequestException
        with self._caplog.at_level(logging.DEBUG):
            result = gce.generateRegionSrvArgs()
        assert result is None
        msg = 'Unable to determine zone information from "'
        msg += "http://169.254.169.254/computeMetadata/v1/instance/zone"
        msg += '"'
        assert msg in self._caplog.text

    # ------------------------------------------------------------------------
    @patch("cloudregister.googlece.requests.get")
    def test_request_fail_parse_response(self, mock_request):
        """Test unexpected return value"""
        mock_request.return_value = _get_unexpected_response()
        with self._caplog.at_level(logging.DEBUG):
            result = gce.generateRegionSrvArgs()
        assert result is None
        msg = "Unable to form region string from text: "
        msg += "projects/284177885636/zones/us-central1"
        assert msg in self._caplog.text

    # ------------------------------------------------------------------------
    @patch("cloudregister.googlece.requests.get")
    def test_request_fail_response_error(self, mock_request):
        """Test unexpected return value"""
        mock_request.return_value = _get_error_response()
        with self._caplog.at_level(logging.DEBUG):
            result = gce.generateRegionSrvArgs()
        assert result is None
        msg = "\tMessage: Test server failure"
        assert msg in self._caplog.text

    # ------------------------------------------------------------------------
    @patch("cloudregister.googlece.requests.get")
    def test_request_succeed(self, mock_request):
        """Test behavior with expected return value"""
        mock_request.return_value = _get_expected_response()
        result = gce.generateRegionSrvArgs()
        assert "regionHint=us-central1" == result


# ----------------------------------------------------------------------------
def _get_error_response():
    """Return an error code as the response of the request"""
    response = Response()
    response.status_code = 500
    response.text = "Test server failure"
    return response


# ----------------------------------------------------------------------------
def _get_expected_response():
    """Return an object mocking a expected response"""
    response = Response()
    response.status_code = 200
    response.text = "projects/284177885636/zones/us-central1-f"
    return response


# ----------------------------------------------------------------------------
def _get_unexpected_response():
    """Return an unexpected response, i.e. triggers a parse error"""
    response = Response()
    response.status_code = 200
    response.text = "projects/284177885636/zones/us-central1"
    return response
