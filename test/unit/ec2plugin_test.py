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

import inspect
import os
import requests
import sys

from unittest.mock import patch, call

test_path = os.path.abspath(
    os.path.dirname(inspect.getfile(inspect.currentframe())))
code_path = os.path.abspath('%s/../lib/cloudregister' % test_path)

sys.path.insert(0, code_path)

import cloudregister.amazonec2 as ec2 # noqa


# ----------------------------------------------------------------------------
class Response():
    pass


# ----------------------------------------------------------------------------
@patch('cloudregister.amazonec2.requests.put')
@patch('cloudregister.amazonec2.requests.get')
@patch('cloudregister.amazonec2.logging')
def test_request_fail(mock_logging, mock_request_get, mock_request_put):
    """Test proper exception handling when request to metadata server fails"""
    mock_request_get.side_effect = requests.exceptions.RequestException
    mock_request_put.side_effect = requests.exceptions.RequestException
    result = ec2.generateRegionSrvArgs()
    assert result is None
    assert mock_logging.info.call_args_list == [
        call('Unable to retrieve IMDSv2 token using 169.254.169.254'),
        call('Unable to retrieve IMDSv2 token using fd00:ec2::254')
    ]
    expected_urls = [
        'http://169.254.169.254/latest/meta-data/placement/region',
        'http://[fd00:ec2::254]/latest/meta-data/placement/region'
    ]
    assert mock_logging.warning.call_args_list == [
        call('Falling back to IMDSv1'),
        call('Unable to determine instance placement from "{}"'.format(
            expected_urls[0]
        )),
        call('Unable to determine instance placement from "{}"'.format(
            expected_urls[1]
        ))
    ]


# ----------------------------------------------------------------------------
@patch('cloudregister.amazonec2.requests.put')
@patch('cloudregister.amazonec2.requests.get')
@patch('cloudregister.amazonec2.logging')
def test_request_fail_response_error(
        mock_logging, mock_request_get, mock_request_put
):
    """Test unexpected return value"""
    # make sure loop has two IP addresses
    mock_request_put.side_effect = [
        _get_error_response(),
        _get_error_response()
    ]
    mock_request_get.side_effect = [
        _get_error_response(),
        _get_error_response()
    ]
    result = ec2.generateRegionSrvArgs()
    assert result is None
    assert mock_logging.warning.called
    assert mock_logging.warning.call_args_list == [
        call('Falling back to IMDSv1'),
        call('Unable to get region metadata'),
        call('\tReturn code: 500'),
        call('\tMessage: Test server failure'),
        call('Unable to get region metadata'),
        call('\tReturn code: 500'),
        call('\tMessage: Test server failure')
    ]


# ----------------------------------------------------------------------------
@patch('cloudregister.amazonec2.requests.put')
@patch('cloudregister.amazonec2.requests.get')
def test_request_succeed(mock_request_get, mock_request_put):
    """Test behavior with expected return value"""
    mock_request_put.return_value = _get_expected_region_response()
    mock_request_get.return_value = _get_expected_region_response()
    result = ec2.generateRegionSrvArgs()
    assert 'regionHint=us-east-1' == result


# ----------------------------------------------------------------------------
def _get_error_response():
    """Return an error code as the response of the request"""
    response = Response()
    response.status_code = 500
    response.text = 'Test server failure'
    return response


# ----------------------------------------------------------------------------
def _get_expected_region_response():
    """Return an object mocking a expected response"""
    response = Response()
    response.status_code = 200
    response.text = 'us-east-1'
    return response


# ----------------------------------------------------------------------------
def _get_unexpected_response():
    """Return an unexpected response, i.e. triggers a parse error"""
    response = Response()
    response.status_code = 200
    response.text = ''
    return response
