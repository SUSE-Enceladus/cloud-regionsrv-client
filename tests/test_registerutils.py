# Copyright (c) 2021 SUSE Software Solutions Germany GmbH. All rights reserved.
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

import inspect
import os
import sys

test_path = os.path.abspath(
    os.path.dirname(inspect.getfile(inspect.currentframe())))
code_path = os.path.abspath('%s/../lib' % test_path)

sys.path.insert(0, code_path)

from cloudregister.registerutils import (
    get_config,
    is_registration_supported
)

cfg = get_config('../etc/regionserverclnt.cfg')


def test_is_registration_supported_SUSE_Family():
    cfg.set('service', 'supportsPackageBackend', 'zypper')
    assert is_registration_supported(cfg) is True


def test_is_registration_supported_RHEL_Family():
    cfg.set('service', 'supportsPackageBackend', 'dnf')
    assert is_registration_supported(cfg) is False
