#!/usr/bin/python3

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

"""
Totally trivial wrapper to support re-authentication for the registry
feature.

The script is used in a sudo rule to allow its use by a non root user
"""

import os
import sys

from cloudregister.registerutils import get_activations, exec_subprocess


def app():
    error_message = 'Could not refresh credentials'
    if os.geteuid():
        if exec_subprocess(['sudo', sys.argv[0]]):
            # geteuid is not root and
            # the command was called with sudo
            # and failed
            sys.exit(error_message)
    elif not get_activations():
        sys.exit(error_message)

    print('Credentials refreshed')
