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

from mock import patch, call

test_path = os.path.abspath(
    os.path.dirname(inspect.getfile(inspect.currentframe())))
code_path = os.path.abspath('%s/../lib/cloudregister' % test_path)

sys.path.insert(0, code_path)

import amazonec2 as ec2


# ----------------------------------------------------------------------------
class Response():
    pass


# ----------------------------------------------------------------------------
@patch('amazonec2.requests.put')
@patch('amazonec2.requests.get')
@patch('amazonec2.logging')
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
        'http://169.254.169.254/latest/meta-data/placement/availability-zone',
        'http://[fd00:ec2::254]/latest/meta-data/placement/availability-zone'
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
@patch('amazonec2.requests.put')
@patch('amazonec2.requests.get')
@patch('amazonec2.logging')
def test_request_fail_response_error(
        mock_logging, mock_request_get, mock_request_put
):
    """Test unexpected return value"""
    mock_request_get.return_value = _get_error_response()
    result = ec2.generateRegionSrvArgs()
    assert result is None
    assert mock_logging.warning.called
    msg = '\tMessage: Test server failure'
    mock_logging.warning.assert_called_with(msg)


# ----------------------------------------------------------------------------
@patch('amazonec2.requests.put')
@patch('amazonec2.requests.get')
def test_request_succeed_gov_part(mock_request_get, mock_request_put):
    """Test behavior with expected return value"""
    mock_request_put.return_value = _get_expected_response_gov_part()
    mock_request_get.return_value = _get_expected_response_gov_part()
    result = ec2.generateRegionSrvArgs()
    assert 'regionHint=us-gov-east-1' == result


# ----------------------------------------------------------------------------
@patch('amazonec2.requests.put')
@patch('amazonec2.requests.get')
def test_request_succeed_std_part(mock_request_get, mock_request_put):
    """Test behavior with expected return value"""
    mock_request_put.return_value = _get_expected_response_std_part()
    mock_request_get.return_value = _get_expected_response_std_part()
    result = ec2.generateRegionSrvArgs()
    assert 'regionHint=us-east-1' == result


# ----------------------------------------------------------------------------
@patch('amazonec2.requests.put')
@patch('amazonec2.requests.get')
def test_request_succeed_local_zone(mock_request_get, mock_request_put):
    """Test behavior with expected return value"""
    mock_request_put.return_value = _get_expected_response_local_zone()
    mock_request_get.return_value = _get_expected_response_local_zone()
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
def _get_expected_response_local_zone():
    """Return an object mocking a expected response"""
    response = Response()
    response.status_code = 200
    response.text = 'us-east-1-bos-1a'
    return response


# ----------------------------------------------------------------------------
def _get_expected_response_gov_part():
    """Return an object mocking a expected response"""
    response = Response()
    response.status_code = 200
    response.text = 'us-gov-east-1a'
    return response


# ----------------------------------------------------------------------------
def _get_expected_response_std_part():
    """Return an object mocking a expected response"""
    response = Response()
    response.status_code = 200
    response.text = 'us-east-1f'
    return response


# ----------------------------------------------------------------------------
def _get_unexpected_response():
    """Return an unexpected response, i.e. triggers a parse error"""
    response = Response()
    response.status_code = 200
    response.text = ''
    return response
