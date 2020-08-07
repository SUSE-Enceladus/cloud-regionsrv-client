# Copyright (c) 2017, SUSE LLC, All rights reserved.
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


def generateRegionSrvArgs():
    """
    Generate arguments to be sent to the region server.
    """
    token_url = 'http://169.254.169.254/latest/api/token'
    token_header = {'X-aws-ec2-metadata-token-ttl-seconds': '21600'}

    zone_req_header = {}
    
    try:
        tokenResp = requests.put(token_url, headers=token_header)
        if tokenResp.status_code == 200:
            zone_req_header = {'X-aws-ec2-metadata-token': tokenResp.text}
    except requests.exceptions.RequestException:
        msg = 'Unable to retrieve IMDSv2 token falling back to IMDSv1'
        logging.warning(msg)
    
    metaDataUrl = 'http://169.254.169.254/latest/meta-data/'
    zoneInfo = 'placement/availability-zone'

    try:
        zoneResp = requests.get(
            metaDataUrl + zoneInfo, headers=zone_req_header
        )
    except requests.exceptions.RequestException:
        msg = 'Unable to determine instance placement from "%s"'
        logging.warning(msg % (metaDataUrl + zoneInfo))
        return

    if zoneResp.status_code == 200:
        # Remove the trailing availability zone letter identifier to get the
        # region
        region = zoneResp.text[:-1]
    else:
        logging.warning('Unable to get availability zone metadata')
        logging.warning('\tReturn code: %d' % zoneResp.status_code)
        logging.warning('\tMessage: %s' % zoneResp.text)
        return

    return 'regionHint=' + region
