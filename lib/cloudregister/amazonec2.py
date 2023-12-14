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
    # IPv4 first as IPv6 IMDs access requires a special flag whne the instance
    # gets launched which is not as likely to be set.
    # Yes, we know the standard says IPv6 should be first...
    imds_ips = ('169.254.169.254', 'fd00:ec2::254')
    token_url = 'http://%s/latest/api/token'
    token_header = {'X-aws-ec2-metadata-token-ttl-seconds': '21600'}

    zone_req_header = {}

    imds_addr = ''
    for imds_ip in imds_ips:
        imds_addr = imds_ip
        if ':' in imds_ip:
            imds_addr = '[%s]' %imds_ip
        try:
            token_resp = requests.put(
                token_url %imds_addr,
                headers=token_header
            )
            if token_resp.status_code == 200:
                zone_req_header = {'X-aws-ec2-metadata-token': token_resp.text}
            else:
                continue
        except requests.exceptions.RequestException:
            msg = 'Unable to retrieve IMDSv2 token using %s' %imds_ip
            logging.warning(msg)
            continue
        break
    else:
        logging.warning('Falling back to IMDSv1')

    metadata_url = 'http://%s/latest/meta-data/' %imds_addr
    zone_info = 'placement/availability-zone'

    try:
        zone_resp = requests.get(
            metadata_url + zone_info, headers=zone_req_header
        )
    except requests.exceptions.RequestException:
        msg = 'Unable to determine instance placement from "%s"'
        logging.warning(msg % (metadata_url + zone_info))
        return

    if zone_resp.status_code == 200:
        # For local zones the format is geo-loc-regionid-metro-regionidaz
        # For example us-east-1-iah-1a
        # For regions the format is geo-loc-regionidaz
        # For example us-east-1f
        # What we need is geo-loc-regionid, i.e. us-east-1 as the region hint
        region_data = zone_resp.text.split('-', 3)
        region_id_az = region_data[2]
        region_id = ''
        for c in region_id_az:
            if c.isdigit():
                region_id += c
        region = '-'.join(region_data[:2] + [region_id])
    else:
        logging.warning('Unable to get availability zone metadata')
        logging.warning('\tReturn code: %d' % zone_resp.status_code)
        logging.warning('\tMessage: %s' % zone_resp.text)
        return

    return 'regionHint=' + region
