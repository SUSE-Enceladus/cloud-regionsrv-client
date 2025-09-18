#!/usr/bin/env python
"""Setup module for cloud-regionsrv-client"""

# Copyright (c) 2015 SUSE LLC
#
# This file is part of regionServiceClient.
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
import sys

try:
    import setuptools
except ImportError:
    sys.stderr.write('Python setuptools required, please install.')
    sys.exit(1)

from cloudregister.registercloudguest import __version__

if __name__ == '__main__':
     pkg = setuptools.find_packages('cloudregister')
     setuptools.setup(
        name='cloudregister',
        description=('Register a cloud guest with an SMT server'),
        url='https://github.com/SUSE/pubcloud',
        license='LGPL-3.0',
        author='SUSE',
        author_email='public-cloud-dev@susecloud.net',
        version=__version__,
        packages=['cloudregister'],
        entry_points={
            'console_scripts': [
                'registercloudguest = cloudregister.registercloudguest:app',
                'cloudguestregistryauth = cloudregister.cloudguestregistryauth:app',
                'cloudguest-lic-watcher = cloudregister.cloudguest_lic_watcher:app',
                'updatesmtcache = cloudregister.updatesmtcache:app',
                'createregioninfo = cloudregister.createregioninfo:app',
                'containerbuild-regionsrv = cloudregister.containerbuild_regionsrv:app',
                'cloudguest-repo-service = cloudregister.cloudguest_repo_service:app'
            ],
        }
     )
