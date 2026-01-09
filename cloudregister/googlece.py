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

import requests

from cloudregister.logger import Logger

log = Logger.get_logger()


def generateRegionSrvArgs():
    """
    Generate arguments to be sent to the region server.
    """
    metaDataUrl = 'http://169.254.169.254/computeMetadata/v1/'
    zoneInfo = 'instance/zone'
    headers = {'Metadata-Flavor': 'Google'}

    try:
        zoneResp = requests.get(metaDataUrl + zoneInfo, headers=headers)
    except requests.exceptions.RequestException:
        log.debug(
            'Unable to determine zone information from "{}"'.format(
                (metaDataUrl + zoneInfo)
            )
        )
        return

    if zoneResp.status_code == 200:
        try:
            country, region, zone = zoneResp.text.split('/')[-1].split('-')
        except Exception:
            log.debug(
                'Unable to form region string from text: {}'.format(
                    zoneResp.text
                )
            )
            return
    else:
        log.debug('Unable to get zone metadata')
        log.debug('\tReturn code: {}'.format(zoneResp.status_code))
        log.debug('\tMessage: {}'.format(zoneResp.text))
        return

    return 'regionHint=' + country + '-' + region
