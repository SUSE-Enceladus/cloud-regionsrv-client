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
import os
from pathlib import Path
from collections import namedtuple

from tempfile import NamedTemporaryFile
from cloudregister.logger import Logger
from cloudregister.registerutils import (
    exec_subprocess,
    get_state_dir,
    clean_all_standard
)
from cloudregister.defaults import (
    REGISTERED_SMT_SERVER_DATA_FILE_NAME
)
from cloudregister.exceptions import (
    CloudRegisterPathError,
    CloudRegisterScopeError,
    CloudRegisterGitError
)

log = Logger.get_logger()

managed_file_type = namedtuple(
    'managed_file_type', ['new', 'done']
)


class Git:
    """
    Use git for content management of data changed by cloudregister
    """
    def __init__(self, directory):
        self.bind_mounts = []
        self.managed_dir = directory
        self.managed_dir_git = '{}/.git'.format(directory)
        self.managed_files = {}
        registration_smt_cache_file_name = os.path.normpath(
            os.sep.join(
                [get_state_dir(), REGISTERED_SMT_SERVER_DATA_FILE_NAME]
            )
        )
        self.git_cmd = [
            'git',
            '--work-tree', self.managed_dir,
            '--git-dir', self.managed_dir_git
        ]
        if not os.path.isdir(self.managed_dir_git) and \
           os.path.isfile(registration_smt_cache_file_name):
            # The system is already registered but is not using the
            # git content manager. The origin state is therefore
            # dirty and needs to be cleaned up first with the
            # standard cleanup code. From there the new git based
            # content management can be established.
            clean_all_standard()

        try:
            if not os.path.isdir(self.managed_dir_git):
                exec_subprocess(['git', 'init', self.managed_dir])
                exec_subprocess(
                    self.git_cmd + ['config', 'user.email', 'public-cloud-dev@susecloud.net']
                )
                exec_subprocess(
                    self.git_cmd + ['config', 'user.name', 'Public Cloud Team']
                )
        except Exception as issue:
            raise CloudRegisterGitError(
                'Cannot init git at: {}: {}'.format(
                    self.managed_dir, issue
                )
            )

    def __enter__(self):
        return self

    def manage(self, filename, as_empty_file=False):
        if not self._is_managed(filename):
            if not os.path.exists(filename) or as_empty_file:
                self._manage_new(filename, as_empty_file)
            else:
                self._manage_existing(filename)

    def done(self, lookup_filename=None):
        """
        Mark file as being fully processed, this excludes it from
        the cleanup phase until explicitly requested via cleanup().
        If no lookup_filename is given, all files known to the
        instance will be marked as done
        """
        for filename, managed in self.managed_files.items():
            if filename and lookup_filename != filename:
                next
            self.managed_files[filename] = managed_file_type(
                new=managed.new, done=True
            )

    def is_empty(self, filename):
        """
        Check if file is empty. If file does not exist it's also empty
        """
        if os.path.exists(filename):
            return not bool(Path(filename).stat().st_size)
        return True

    def cleanup(self):
        """
        Checkout all origin versions from managed directory
        Please note; Files created as net new files from us
        will stay as empty files in the system
        """
        stdout, stderr, failed = exec_subprocess(
            self.git_cmd + ['ls-files', '-m']
        )
        if not failed:
            for modified in stdout.decode().split(os.linesep):
                if modified:
                    filename = '{}/{}'.format(self.managed_dir, modified)
                    log.info('Restore file: {}'.format(filename))
                    stdout, stderr, failed = exec_subprocess(
                        self.git_cmd + ['checkout', filename]
                    )
                    if self.is_empty(filename):
                        log.info('Deleting empty file: {}'.format(filename))
                        Path(filename).unlink()
        if failed:
            log.error('Could not checkout origin: {}:{}'.format(
                stdout, stderr)
            )

    def _is_managed(self, filename):
        if not filename.startswith(self.managed_dir):
            raise CloudRegisterScopeError(
                'Given filename {} is outside git scope dir: {}'.format(
                    filename, self.managed_dir
                )
            )
        if self.managed_files.get(filename):
            return True
        return False

    def _manage_new(self, filename, as_empty_file=False):
        """
        Commit a net new file as empty version to the git
        """
        failed = False
        log.info('Manage new file: {}'.format(filename))
        self.managed_files[filename] = managed_file_type(
            new=True, done=False
        )
        try:
            if os.path.exists(filename) and as_empty_file:
                temp_filename = NamedTemporaryFile()
                _, _, failed = exec_subprocess(
                    ['mount', '--bind', temp_filename.name, filename]
                )
                self.bind_mounts.append(temp_filename.name)
            else:
                with open(filename, 'w'):
                    pass
        except Exception as issue:
            raise CloudRegisterPathError(
                'Failed to create new file: {}'.format(issue)
            )
        if not failed:
            stdout, stderr, failed = exec_subprocess(
                self.git_cmd + ['add', filename]
            )
        if not failed:
            stdout, stderr, failed = exec_subprocess(
                self.git_cmd + [
                    'commit', '--allow-empty', '-m',
                    'origin:{}'.format(filename)
                ]
            )
        if os.path.exists(filename) and as_empty_file:
            exec_subprocess(['umount', filename])
        if failed:
            raise CloudRegisterGitError(
                'Failed to add managed file to git: {}:{}'.format(
                    stdout, stderr
                )
            )

    def _manage_existing(self, filename):
        """
        Commit an existing file as origin version to the git once
        such that it can be restored
        """
        log.info('Manage existing file: {}'.format(filename))
        self.managed_files[filename] = managed_file_type(
            new=False, done=False
        )
        if self._known_to_git(filename):
            log.info('File {} already managed'.format(filename))
            return
        stdout, stderr, failed = exec_subprocess(
            self.git_cmd + ['add', filename]
        )
        if not failed:
            stdout, stderr, failed = exec_subprocess(
                self.git_cmd + ['commit', '-m', 'origin:{}'.format(filename)]
            )
        if failed:
            raise CloudRegisterGitError(
                'Failed to add managed file to git: {}:{}'.format(
                    stdout, stderr
                )
            )

    def _known_to_git(self, filename):
        _, _, failed = exec_subprocess(
            self.git_cmd + ['ls-files', '--error-unmatch', filename]
        )
        if not failed:
            return True
        return False

    def _cleanup(self):
        """
        Cleanup all unfinished files
        """
        for filename in self.bind_mounts:
            _, _, failed = exec_subprocess(['mountpoint', '-q', filename])
            if not failed:
                exec_subprocess(['umount', filename])
        for filename, managed in self.managed_files.items():
            if not managed.done:
                log.info('Cleaning up unfinished file: {}'.format(filename))
                stdout, stderr, failed = exec_subprocess(
                    self.git_cmd + ['checkout', filename]
                )
                if self.is_empty(filename):
                    log.info('Deleting empty file: {}'.format(filename))
                    Path(filename).unlink()
                if failed:
                    log.error('Could not checkout origin {}: {}:{}'.format(
                        filename, stdout, stderr)
                    )

    def __exit__(self, exc_type, exc_value, traceback):
        self._cleanup()
