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


class CloudRegister(Exception):
    """
    Case class for CloudRegister exceptions
    """
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return format(self.message)


class CloudRegisterPathError(CloudRegister):
    """
    Exception raised if a Path operation e.g mkdir failed
    """


class CloudRegisterScopeError(CloudRegister):
    """
    Exception raised if a managed file is outside the git scope
    """


class CloudRegisterGitError(CloudRegister):
    """
    Exceptin raised if a git operation failed
    """
