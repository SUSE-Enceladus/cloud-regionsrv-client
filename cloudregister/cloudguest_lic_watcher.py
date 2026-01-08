#!/usr/bin/python3

# Copyright (c) 2025, SUSE LLC, All rights reserved.
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

import os

import instance_billing_flavor_check.utils as inst_flvr_utils
import cloudregister.registerutils as utils
from cloudregister.logger import Logger
from cloudregister.defaults import LOG_FILE

CACHE_LICENSE_PATH = os.path.join(utils.get_state_dir(), 'cached_license')
SERVICE_NAME = 'guestregister.service'

log_instance = Logger()
log_instance.set_logfile(LOG_FILE)
log = Logger.get_logger()


def update_license_cache(license_type):
    """Update the cache to track the license type"""
    with open(CACHE_LICENSE_PATH, 'w') as cached_license:
        cached_license.write(license_type)


def has_license_changed(license_type):
    """Check license type changes against metadata info"""
    if os.path.exists(CACHE_LICENSE_PATH):
        with open(CACHE_LICENSE_PATH, 'r') as cached_license:
            old_license = cached_license.read()
            return license_type != old_license
    else:
        update_license_cache(license_type)
        maybe_drop_registration(license_type)
        maybe_register_system(license_type)


def maybe_drop_registration(license_type):
    """Clean up registration data if needed"""
    if license_type == 'BYOS':
        if not utils.get_current_smt():
            # There is no target registration server, nothing to do
            return
        if not utils.uses_rmt_as_scc_proxy():
            log.info('Detected flavor change to BYOS, clean up registration')
            utils.clean_all_standard()
            utils.exec_subprocess(['systemctl', 'disable', SERVICE_NAME])


def maybe_register_system(license_type):
    """Register the system if needed handle the folowing cases
    - System is not registered at all
    - System is registered as BYOS to update server
    - System is registered to SCC
    """
    if license_type == 'PAYG':
        current_target = utils.get_current_smt()
        base_msg = 'Detected flavor change to PAYG, {status}'
        if current_target and utils.uses_rmt_as_scc_proxy():
            # The system is registered to the update infrastructure using
            # a registration code. Now that the system is PAYG we have to
            # clean up that registration
            utils.clean_all_standard()
            log.info(
                base_msg.format(
                    status='removed registration to update infra as BYOS'
                )
            )
            current_target = None
        if not current_target and utils.is_scc_connected():
            # The system is registered to the SUSE Customer center. Now
            # that the system is PAYG we have to clean up that registration
            utils.clean_all_standard()
            log.info(
                base_msg.format(status='removed registration to SCC as BYOS')
            )
            current_target = None
        if not current_target or not utils.is_registered(
            current_target.get_FQDN()
        ):
            # The system is not registered to the update infrastructure
            log.info(base_msg.format(status='registering'))
            utils.exec_subprocess(['registercloudguest'])
            utils.exec_subprocess(['systemctl', 'enable', SERVICE_NAME])
            return
        # Everything is as it is expected to be
        log.info(base_msg.format(status='already registered, nothing to do'))


def app():
    current_flavor = inst_flvr_utils.check_payg_byos()[0]
    if has_license_changed(current_flavor):
        maybe_drop_registration(current_flavor)
        maybe_register_system(current_flavor)
        update_license_cache(current_flavor)
