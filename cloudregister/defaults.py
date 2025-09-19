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
#
#
LOG_FILE = '/var/log/cloudregister'

# etc content
ZYPP_SERVICES = '/etc/zypp/services.d'
HOSTSFILE_PATH = '/etc/hosts'
REGISTRY_CREDENTIALS_PATH = '/etc/containers/config.json'
PROFILE_LOCAL_PATH = '/etc/profile.local'
REGISTRIES_CONF_PATH = '/etc/containers/registries.conf'
DOCKER_CONFIG_PATH = '/etc/docker/daemon.json'
SUMA_REGISTRY_CONF_PATH = '/etc/uyuni/uyuni-tools.yaml'
BASE_PRODUCT_PATH = '/etc/products.d/baseproduct'
ZYPP_CREDENTIALS_PATH = '/etc/zypp/credentials.d'

# var content
OLD_REGISTRATION_DATA_DIR = '/var/lib/cloudregister'
REGISTRATION_DATA_DIR = '/var/cache/cloudregister'

# constants
AVAILABLE_SMT_SERVER_DATA_FILE_NAME = 'availableSMTInfo_%s.obj'
BASE_CREDENTIALS_NAME = 'SCCcredentials'
FRAMEWORK_IDENTIFIER = 'framework_info'
NEW_REGISTRATION_MARKER = 'newregistration'
REGISTRATION_COMPLETED_MARKER = 'registrationcompleted'
REGISTERED_SMT_SERVER_DATA_FILE_NAME = 'currentSMTInfo.obj'
RMT_AS_SCC_PROXY_MARKER = 'rmt_is_scc_proxy'
SUSE_REGISTRY = 'registry.suse.com'
REGSHARING_SYNC_TIME = 30
