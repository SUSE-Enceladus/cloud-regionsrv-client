#!/usr/bin/python3

# Copyright (c) 2019, SUSE LLC, All rights reserved.
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

"""This script provides the repositories for on-demand instances."""

import base64
import os
import requests
import sys

from lxml import etree
from requests.auth import HTTPBasicAuth

from cloudregister.logger import Logger
from cloudregister.defaults import LOG_FILE
import cloudregister.registerutils as utils

log_instance = Logger()
log_instance.set_logfile(LOG_FILE)
log = Logger.get_logger()


def print_repo_data(update_server, activation, available_repos):
    """Print repository data from product activation info."""
    service_revert_file = os.path.join(utils.REGISTRATION_DATA_DIR, 'installservice')
    service_info = activation.get('service')
    service_name = service_info.get('name')
    service_url = service_info.get('url')
    is_plugin_url = False
    if service_url.startswith('plugin:'):
        is_plugin_url = True
        if not os.path.exists('%s.lock' % service_revert_file):
            if os.path.exists(service_revert_file):
                # If the system was registered to RMT with the old client
                # we have a link for every service to this file, for every
                # service we go through all the activations
                # Each service should be set as trigger only once
                lines = open(service_revert_file).readlines()
                for line in lines:
                    if line.strip() == service_name:
                        break
                else:
                    with open(service_revert_file, 'a') as trigger:
                        trigger.write("%s\n" % service_name)
            else:
                with open(service_revert_file, 'a') as trigger:
                    trigger.write("%s\n" % service_name)

    product_info = service_info.get('product')
    credentials_file = os.path.basename(
        utils.get_credentials_file(
            update_server,
            service_name
        )
    )
    for repo in product_info.get('repositories'):
        name = repo.get('name')
        if name not in available_repos:
            continue
        refresh = repo.get('autorefresh')
        enabled = repo.get('enabled')
        url = repo.get('url')
        if url.startswith('plugin:'):
            base_url = url
            if credentials_file:
                base_url += '&credentials=%s' % credentials_file
        elif url.startswith('http'):
            relative_path = url.split('repo')[-1]
            base_url = 'plugin:susecloud?'
            if credentials_file:
                base_url += 'credentials=%s&' % credentials_file
            base_url += 'path=/repo%s' % relative_path
        print('[%s]' % name)
        print('name=%s' % name)
        print('enabled=%d' % int(bool(enabled)))
        print('autorefresh=%s' % int(bool(refresh)))
        print('baseurl=%s' % base_url)

    return is_plugin_url


def app():
    utils.set_proxy()

    # Make sure we are pointing to a reachable server
    update_server = utils.get_smt()
    if not update_server:
        log.info('[Repo-Service] No update server found cannot provide repos')
        sys.exit(1)

    # Get the available repos from the server
    user, password = utils.get_credentials(
        utils.get_credentials_file(update_server)
    )
    auth_creds = HTTPBasicAuth(user, password)
    instance_data = bytes(utils.get_instance_data(utils.get_config()), 'utf-8')
    headers = {'X-Instance-Data': base64.b64encode(instance_data)}
    res = requests.get(
        'https://%s/repo/repoindex.xml' % update_server.get_FQDN(),
        auth=auth_creds,
        headers=headers
    )
    if not res.status_code == 200:
        log.info('[Repo-Service] Unable to retrieve update server repo data')
        sys.exit(1)

    repo_info_xml = res.text
    repo_info_start = repo_info_xml.index('<repoindex>')
    repo_data = etree.fromstring(repo_info_xml[repo_info_start:])

    available_repos = []
    for repo in repo_data.findall('repo'):
        available_repos.append(repo.get('name'))

    # Get activated products for repo processing
    # We have to process the activation information as otherwise it is difficult
    # to relate services to repositories since the repoindex.xml file
    # does not provide such correlation.
    product_activations = utils.get_activations()
    if not product_activations:
        log.error(
            '[Repo-Service] Unable to retrieve product activations '
            'from "%s"' % update_server.get_FQDN()
        )
        sys.exit(1)

    for activation in product_activations:
        print_repo_data(
            update_server, activation, available_repos
        )
