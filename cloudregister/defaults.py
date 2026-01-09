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
BASE_PRODUCT_PATH = '/etc/products.d/baseproduct'
DOCKER_CONFIG_PATH = '/etc/docker/daemon.json'
HOSTSFILE_PATH = '/etc/hosts'
PROFILE_LOCAL_PATH = '/etc/profile.local'
REGISTRIES_CONF_PATH = '/etc/containers/registries.conf'
REGISTRY_CREDENTIALS_PATH = '/etc/containers/config.json'
SUMA_REGISTRY_CONF_PATH = '/etc/uyuni/uyuni-tools.yaml'
ZYPP_CREDENTIALS_PATH = '/etc/zypp/credentials.d'
ZYPP_SERVICES = '/etc/zypp/services.d'

# var content
OLD_REGISTRATION_DATA_DIR = '/var/lib/cloudregister'
REGISTRATION_DATA_DIR = '/var/cache/cloudregister'

# constants
AVAILABLE_SMT_SERVER_DATA_FILE_NAME = 'availableSMTInfo_%s.obj'
BASE_CREDENTIALS_NAME = 'SCCcredentials'
FRAMEWORK_IDENTIFIER = 'framework_info'
NEW_REGISTRATION_MARKER = 'newregistration'
REGISTERED_SMT_SERVER_DATA_FILE_NAME = 'currentSMTInfo.obj'
REGISTRATION_COMPLETED_MARKER = 'registrationcompleted'
REGSHARING_SYNC_TIME = 30
RMT_AS_SCC_PROXY_MARKER = 'rmt_is_scc_proxy'
SUSE_REGISTRY = 'registry.suse.com'

# suseconnect exit codes we care about
LIBZYPP_ERROR = 4
SERVER_ACCESS_ERROR = 65
SERVER_CONNECTION_REFUSED = 64
SERVER_GENERAL_ERROR = 67
SERVER_RESPONSE_ERROR = 66
ZYPPER_IS_LOCKED = 7
ZYPPER_UNKNOWN_ERROR = 1
