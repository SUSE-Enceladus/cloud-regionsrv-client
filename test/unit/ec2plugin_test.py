# Copyright (c) 2024, SUSE LLC, All rights reserved.
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

import cloudregister.amazonec2 as ec2  # noqa

from cloudregister.logger import Logger

log_instance = Logger()
log = Logger.get_logger()


# ----------------------------------------------------------------------------
class Response:
    pass


# ----------------------------------------------------------------------------
class TestEC2PLugin:
    @fixture(autouse=True)
    def inject_fixtures(self, caplog):
        self._caplog = caplog

    # ------------------------------------------------------------------------
    @patch("cloudregister.amazonec2.requests.put")
    @patch("cloudregister.amazonec2.requests.get")
    def test_request_fail(self, mock_request_get, mock_request_put):
        """Test proper exception handling when request to metadata server
        fails"""
        mock_request_get.side_effect = requests.exceptions.RequestException
        mock_request_put.side_effect = requests.exceptions.RequestException
        with self._caplog.at_level(logging.DEBUG):
            result = ec2.generateRegionSrvArgs()
        assert result is None
        expected_msgs = [
            "Unable to retrieve IMDSv2 token using 169.254.169.254",
            "Unable to retrieve IMDSv2 token using fd00:ec2::254",
            "Falling back to IMDSv1",
        ]
        expected_urls = [
            "http://169.254.169.254/latest/meta-data/placement/region",
            "http://[fd00:ec2::254]/latest/meta-data/placement/region",
        ]
        for url in expected_urls:
            expected_msgs.append(
                'Unable to determine instance placement from "{}"'.format(url)
            )
        for msg in expected_msgs:
            assert msg in self._caplog

    # ------------------------------------------------------------------------
    @patch("cloudregister.amazonec2.requests.put")
    @patch("cloudregister.amazonec2.requests.get")
    def test_request_fail_response_error(
            self, mock_request_get, mock_request_put
    ):
        """Test unexpected return value"""
        # make sure loop has two IP addresses
        mock_request_put.side_effect = [
            _get_error_response(), _get_error_response()
        ]
        mock_request_get.side_effect = [
            _get_error_response(), _get_error_response()
        ]
        with self._caplog.at_level(logging.DEBUG):
            result = ec2.generateRegionSrvArgs()
        assert result is None
        expected_msgs = [
            "Falling back to IMDSv1",
            "Unable to get region metadata",
            "\tReturn code: 500",
            "\tMessage: Test server failure",
            "Unable to get region metadata",
            "\tReturn code: 500",
            "\tMessage: Test server failure",
        ]
        for msg in expected_msgs:
            assert msg in self._caplog

    # ------------------------------------------------------------------------
    @patch("cloudregister.amazonec2.requests.put")
    @patch("cloudregister.amazonec2.requests.get")
    def test_request_succeed(self, mock_request_get, mock_request_put):
        """Test behavior with expected return value"""
        mock_request_put.return_value = _get_expected_region_response()
        mock_request_get.return_value = _get_expected_region_response()
        result = ec2.generateRegionSrvArgs()
        assert "regionHint=us-east-1" == result


# ------------------------------------------------------------------------
def _get_error_response():
    """Return an error code as the response of the request"""
    response = Response()
    response.status_code = 500
    response.text = "Test server failure"
    return response


# ------------------------------------------------------------------------
def _get_expected_region_response():
    """Return an object mocking a expected response"""
    response = Response()
    response.status_code = 200
    response.text = "us-east-1"
    return response


# ------------------------------------------------------------------------
def _get_unexpected_response():
    """Return an unexpected response, i.e. triggers a parse error"""
    response = Response()
    response.status_code = 200
    response.text = ""
    return response
