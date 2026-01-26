# Copyright (c) 2026, SUSE LLC, All rights reserved.
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
import fcntl
import os

from cloudregister.logger import Logger

log = Logger.get_logger()


class Lock:
    """
    Setup process locking
    """

    def __init__(self):
        self.lock_file = '/var/lock/registercloudguest.lock'

    @staticmethod
    def sameProcess():
        return -1

    def acquire(self):
        """
        Acquire file lock to the process lock file
        This call blocks if the file is already locked on
        different caller arguments. If the exact same caller
        arguments are found the sameProcess identifier is
        returned.
        """
        open_mode = 'r+' if os.path.exists(self.lock_file) else 'w'
        fd = open(self.lock_file, open_mode)
        caller_pid = format(os.getpid())
        try:
            fcntl.flock(fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            fd.write('{}'.format(caller_pid))
            fd.flush()
        except IOError:
            lock_pid = fd.read()
            cmdline_lock = self._read_cmdline(lock_pid)
            cmdline_call = self._read_cmdline(caller_pid)
            if cmdline_lock == cmdline_call:
                log.warning(
                    '{} already running as PID: {}'.format(
                        cmdline_lock, lock_pid
                    )
                )
                return Lock.sameProcess()
            else:
                log.warning(
                    '{} is locked by PID: {}, '
                    'waiting to acquire lock...'.format(cmdline_call, lock_pid)
                )
                fcntl.flock(fd.fileno(), fcntl.LOCK_EX)
        return fd

    def is_locked(self):
        """
        Check if the registration process has a lock.
        """
        return os.path.exists(self.lock_file)

    def release(self, fd):
        """
        Release file lock from process lock file
        """
        if fd and not fd == Lock.sameProcess():
            fcntl.flock(fd.fileno(), fcntl.LOCK_UN)

    def _read_cmdline(self, pid):
        with open('/proc/{}/cmdline'.format(pid)) as cmdline_fd:
            return cmdline_fd.read()
