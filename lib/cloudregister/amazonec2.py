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
            imds_addr = '[%s]' % imds_ip
        try:
            token_resp = requests.put(
                token_url % imds_addr,
                headers=token_header
            )
            if token_resp.status_code == 200:
                zone_req_header = {'X-aws-ec2-metadata-token': token_resp.text}
            else:
                continue
        except requests.exceptions.RequestException:
            msg = 'Unable to retrieve IMDSv2 token using %s' % imds_ip
            logging.info(msg)
            continue
        break
    else:
        logging.warning('Falling back to IMDSv1')

    # If we suceeded getting a token then we use the IP address that
    # provided the token
    if zone_req_header:
        imds_ips = (imds_addr,)

    for imds_ip in imds_ips:
        imds_addr = imds_ip
        if ':' in imds_ip and '[' not in imds_ip:
            imds_addr = '[%s]' % imds_ip
        metadata_url = 'http://%s/latest/meta-data/' % imds_addr
        zone_info = 'placement/availability-zone'

        try:
            zone_resp = requests.get(
                metadata_url + zone_info, headers=zone_req_header
            )
        except requests.exceptions.RequestException:
            msg = 'Unable to determine instance placement from "%s"'
            logging.warning(msg % (metadata_url + zone_info))
            if imds_ip == imds_ips[-1]:
                return
            continue

        if zone_resp.status_code == 200:
            # For local zones the format is geo-loc-regionid-metro-regionidaz
            # For example us-east-1-iah-1a
            # For regions in the standard partition the format
            # is geo-loc-regionidaz
            # For example us-east-1f
            # For regions in the gov partition the format is
            # geo-gov-loc-regionidaz
            # For example us-gov-west-1a
            # What we need is geo-(gov)-loc-regionid,
            # i.e. us-east-1 or us-gov-west-1 as the region hint
            region_data = zone_resp.text.split('-')
            # Find the az (availability zone) indicator which is the first
            # entry starting with a number
            az_index = 0
            for entry in region_data:
                if entry[0].isdigit():
                    break
                az_index += 1
            region_id_az = region_data[az_index]
            region_id = ''
            for c in region_id_az:
                if c.isdigit():
                    region_id += c
            region = '-'.join(region_data[:az_index] + [region_id])
        else:
            logging.warning('Unable to get availability zone metadata')
            logging.warning('\tReturn code: %d' % zone_resp.status_code)
            logging.warning('\tMessage: %s' % zone_resp.text)
            if imds_ip == imds_ips[-1]:
                return
            continue

    return 'regionHint=' + region
