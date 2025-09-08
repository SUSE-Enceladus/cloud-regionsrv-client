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

"""Switch any RIS service registered to the update infrastructure to
   a plugin based service or switch from plugin service to RIS"""

import glob
import logging
import os
import subprocess
import sys
import time

import cloudregister.registerutils as utils

def app():
    utils.start_logging()
    utils.set_proxy()

    service_revert_file = os.path.join(
        utils.REGISTRATION_DATA_DIR, 'installservice'
    )

    if os.path.exists(service_revert_file):
        # Server side now provides the setup to use RIS service, we no longer
        # need the service plugin
        while utils.get_zypper_pid():
            time.sleep(5)
        os.system('touch %s.lock' % service_revert_file)
        # Special case for when we switch from SMT to RMT
        # We know that SMT will never deliver URLs with "plugin:" syntax. Also
        # RMT does not deliver the old service name
        # SMT-http_smt-$FRAMEWORK_susecloud_net. Therefore we have to get
        # rid of this service plugin symlink
        old_services = glob.glob('/usr/lib/zypp/plugins/services/SMT-http*')
        for old_service in old_services:
            os.unlink(old_service)
        # zypper creates a weird date stamped service file, we need to get rid
        # of it later. Keep track of services that are not under our control
        current_services = glob.glob('/etc/zypp/services.d/*.service')
        switch_services = open(service_revert_file, 'r').readlines()
        product_activations = utils.get_activations()
        if not product_activations:
            logging.error('[Serviceswitch] Unable to retrieve product activations')
            sys.exit(1)
        service_plugins = dict(
            (os.path.basename(plugin), plugin) for plugin in glob.glob(
                '/usr/lib/zypp/plugins/services/*')
        )
        for service in switch_services:
            service_name = service.strip()
            for activation in product_activations:
                product_service = activation.get('service')
                product_service_name = product_service.get('name')
                if service_name == product_service_name:
                    break
            if not service_name:
                continue
            plugin = service_plugins.get(service_name)
            if plugin:
                logging.info(
                    '[Serviceswitch] Removing service plugin "%s"' % service_name
                )
                os.unlink(plugin)
            cred_file = '/etc/zypp/credentials.d/%s' % service_name
            if not os.path.exists(cred_file):
                update_server = utils.get_smt()
                user, password = utils.get_credentials(
                    utils.get_credentials_file(update_server)
                )
                with open(cred_file, 'w') as creds:
                    creds.write('username=%s\n' % user)
                    creds.write('password=%s\n' % password)
                os.chmod(cred_file, 0o600)
            service_url = product_service.get('url')
            cmd = [
                'zypper',
                '--non-interactive',
                'addservice',
                '--refresh',
                service_url,
                service_name
            ]
            # zypper is slow, wait loop
            while utils.get_zypper_pid():
                time.sleep(5)
            result = utils.exec_subprocess(cmd)
            if result:
                logging.info(
                    '[Serviceswitch] Adding RIS for "%s" failed' % service_url
                )
                link_dest = os.path.join(
                    '/usr/lib/zypp/plugins/services/',
                    service_name
                )
                os.symlink('/usr/sbin/cloudguest-repo-service', link_dest)
                logging.info(
                    '[Serviceswitch] Re-created service plugin "%s"' % service_name
                )
            else:
                current_services.append(
                    '/etc/zypp/services.d/%s.service' % service_name
                )

        all_services = glob.glob('/etc/zypp/services.d/*.service')
        for service in all_services:
            if service not in current_services:
                os.unlink(service)
        os.unlink(service_revert_file)
        os.unlink("%s.lock" % service_revert_file)
        # zypper is slow, wait loop
        while utils.get_zypper_pid():
            time.sleep(5)
        utils.exec_subprocess(['zypper', '--non-interactive', 'refs', '-f'])
    else:
        utils.switch_services_to_plugin()
