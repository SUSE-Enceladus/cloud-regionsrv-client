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

# https://docs.aws.amazon.com/vpc/latest/userguide/AmazonDNS-concepts.html
AWS_IPv4 = '169.254.169.253'
AWS_IPv6 = 'fd00:ec2::253'


def default_ipv4():
    """Return the default IPv4 address."""
    return AWS_IPv4


def default_ipv6():
    """Return the default IPv6 address."""
    return AWS_IPv6


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
        region_data = 'placement/region'

        try:
            region_resp = requests.get(
                metadata_url + region_data, headers=zone_req_header
            )
        except requests.exceptions.RequestException:
            msg = 'Unable to determine instance placement from "%s"'
            logging.warning(msg % (metadata_url + region_data))
            if imds_ip == imds_ips[-1]:
                return
            continue

        if not region_resp.status_code == 200:
            logging.warning('Unable to get region metadata')
            logging.warning('\tReturn code: %d' % region_resp.status_code)
            logging.warning('\tMessage: %s' % region_resp.text)
            if imds_ip == imds_ips[-1]:
                return

    return 'regionHint=' + region_resp.text
