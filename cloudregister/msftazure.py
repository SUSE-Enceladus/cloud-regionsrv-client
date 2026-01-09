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

import dns.resolver
import html
import requests
import re
import urllib.request
import urllib.parse
import urllib.error

from cloudregister.logger import Logger

extensionConfigRx = re.compile(
    r".*<ExtensionsConfig>(.*?)</ExtensionsConfig>.*", re.S | re.M
)
locationRx = re.compile(r".*<Location>(.*?)</Location>.*", re.S | re.M)
log = Logger.get_logger()


def generateRegionSrvArgs():
    """
    Generate arguments to be sent to the region server.
    """
    meta_data_url = "http://169.254.169.254/metadata/instance/"
    zone_info = "compute/location"
    headers = {"Metadata": "true"}
    params = {"format": "text", "api-version": "2017-04-02"}

    zone_response = None
    try:
        zone_response = requests.get(
            meta_data_url + zone_info, headers=headers, params=params, timeout=5
        )
    except requests.exceptions.RequestException:
        msg = "Unable to determine instance placement from metadata "
        msg += 'server "%s"'
        log.debug(msg % (meta_data_url + zone_info))

    if zone_response:
        if zone_response.status_code == 200:
            return "regionHint=" + zone_response.text.lower()
        else:
            log.debug("Unable to get availability zone metadata")
            log.debug("\tReturn code: %d" % zone_response.status_code)
            log.debug("\tMessage: %s" % zone_response.text)
    else:
        log.debug("Falling back to XML data from wire server")
        resolver = dns.resolver.get_default_resolver()
        for nameserver in resolver.nameservers:
            wireServer = "http://%s/" % nameserver
            headers = {
                "x-ms-agent-name": "WALinuxAgent",
                "x-ms-version": "2012-11-30",
            }
            try:
                goalStateInfo = "machine/?comp=goalstate"
                goalStatResp = requests.get(
                    wireServer + goalStateInfo, headers=headers, timeout=15
                )
            except requests.exceptions.RequestException:
                msg = "Could not retrieve goal state XML from %s" % nameserver
                log.debug(msg)
                continue
            if not goalStatResp.status_code == 200:
                msg = "%s error for goal state request: %s"
                log.debug(msg % (nameserver, goalStatResp.status_code))
                continue
            match = extensionConfigRx.match(goalStatResp.text)
            if not match:
                log.debug('No "<ExtensionsConfig>" in goal state XML')
                continue
            extensionsURI = urllib.parse.unquote(
                html.unescape(match.groups()[0])
            )
            try:
                extensionsResp = requests.get(
                    extensionsURI, headers=headers, timeout=15
                )
            except requests.exceptions.RequestException:
                msg = 'Could not get extensions information from "%s"'
                log.debug(msg % extensionsURI)
                continue
            if not extensionsResp.status_code == 200:
                msg = "Extensions request failed with: %s"
                log.debug(msg % extensionsResp.status_code)
                continue
            match = locationRx.match(extensionsResp.text)
            if not match:
                log.debug('No "<Location>" in extensions XML')
                continue
            location = match.groups()[0]

            return "regionHint=" + location.lower()

        msg = 'Could not determine location from any of the endpoints: "%s"'
        log.debug(msg % resolver.nameservers)
