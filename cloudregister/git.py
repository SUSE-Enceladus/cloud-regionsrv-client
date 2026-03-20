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
import shutil
import pathlib
from collections import namedtuple

from cloudregister.logger import Logger
from cloudregister.registerutils import (
    exec_subprocess,
    get_state_dir,
    clean_all_standard,
)
from cloudregister.defaults import Defaults
from cloudregister.defaults import REGISTERED_SMT_SERVER_DATA_FILE_NAME
from cloudregister.exceptions import (
    CloudRegisterPathError,
    CloudRegisterScopeError,
    CloudRegisterGitError,
)

log = Logger.get_logger()

managed_file_type = namedtuple('managed_file_type', ['new', 'done'])


class Git:
    """
    Use git for content management of data changed by cloudregister
    """

    def __init__(self, directory):
        self.cleanup_called = False
        self.managed_dir = directory
        self.managed_dir_git = os.path.normpath(
            os.sep.join([directory, '.git'])
        )
        self.managed_dir_gitignore = os.path.normpath(
            os.sep.join([directory, '.gitignore'])
        )
        self.managed_files = {}
        registration_smt_cache_file_name = os.path.normpath(
            os.sep.join([get_state_dir(), REGISTERED_SMT_SERVER_DATA_FILE_NAME])
        )
        self.git_cmd = [
            'git',
            '--work-tree',
            self.managed_dir,
            '--git-dir',
            self.managed_dir_git,
        ]
        if not os.path.isdir(self.managed_dir_git) and os.path.isfile(
            registration_smt_cache_file_name
        ):
            # The system is already registered but is not using the
            # git content manager. The origin state is therefore
            # dirty and needs to be cleaned up first with the
            # standard cleanup code. From there the new git based
            # content management can be established.
            clean_all_standard()

        failed = False
        if not os.path.isdir(self.managed_dir_git):
            # git cannot manage empty directories
            # make sure there are none
            _, error, failed = exec_subprocess(
                [
                    'find',
                    self.managed_dir,
                    '-type',
                    'd',
                    '-empty',
                    '-exec',
                    'touch',
                    '{}/.gitignore',
                    ';',
                ]
            )
            if not failed:
                _, error, failed = exec_subprocess(
                    ['git', 'init', self.managed_dir]
                )
            if not failed:
                _, error, failed = exec_subprocess(
                    self.git_cmd
                    + ['config', 'user.email', 'public-cloud-dev@susecloud.net']
                )
            if not failed:
                _, error, failed = exec_subprocess(
                    self.git_cmd + ['config', 'user.name', 'Public Cloud Team']
                )
            if not failed:
                _, error, failed = exec_subprocess(
                    self.git_cmd + ['checkout', '-b', 'main']
                )
            if not failed:
                managed_system_files = Defaults.get_managed_files(
                    self.managed_dir
                )
                if managed_system_files:
                    _, error, failed = exec_subprocess(
                        self.git_cmd + ['add'] + managed_system_files
                    )
            if not failed:
                _, error, failed = exec_subprocess(
                    self.git_cmd + ['commit', '--allow-empty', '-m', 'origin']
                )
        if not failed:
            _, error, failed = exec_subprocess(
                self.git_cmd + ['checkout', 'registercloudguest']
            )
            if failed:
                _, error, failed = exec_subprocess(
                    self.git_cmd + ['checkout', '-b', 'registercloudguest']
                )
        if failed:
            raise CloudRegisterGitError(
                'Cannot init git at: {}: {}'.format(self.managed_dir, error)
            )

    def __enter__(self):
        return self

    def manage(self, filename):
        if not self._is_managed(filename):
            if not os.path.exists(filename):
                self._manage_new(filename)
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

    def cleanup(self, with_patch=True):
        """
        Track modifications not done by us in a patch file.
        Next go back to the main origin and delete the branch,
        followed by the deletion of the git itself.
        """
        try:
            self.cleanup_called = True
            _, error, failed = exec_subprocess(
                self.git_cmd + ['checkout', 'main']
            )
            if failed:
                if with_patch:
                    # There are local modifications not done by us
                    # We preserve them as a patch file
                    patch_file = '/var/tmp/cloudregister.patch'
                    log.warning(
                        'Changes detected in cloudregister managed files'
                    )
                    log.warning(
                        'Please apply {} to not loose them'.format(patch_file)
                    )
                    exec_subprocess(
                        self.git_cmd
                        + [
                            'diff',
                            '--diff-filter=M',
                            '--output={}'.format(patch_file),
                        ]
                    )
                exec_subprocess(self.git_cmd + ['checkout', '.'])
                exec_subprocess(self.git_cmd + ['checkout', 'main'])
            exec_subprocess(
                self.git_cmd + ['branch', '-D', 'registercloudguest']
            )
        finally:
            shutil.rmtree(self.managed_dir_git)
            pathlib.Path(self.managed_dir_gitignore).unlink(missing_ok=True)

    def reset(self):
        """
        Reset all local modifications and go back to the main
        origin. Recreate the work branch registercloudguest
        and switch to it
        """
        exec_subprocess(self.git_cmd + ['checkout', '.'])
        exec_subprocess(self.git_cmd + ['checkout', 'main'])
        exec_subprocess(self.git_cmd + ['branch', '-D', 'registercloudguest'])
        exec_subprocess(self.git_cmd + ['checkout', '-b', 'registercloudguest'])
        self.managed_files = {}

    @staticmethod
    def git_managed(directory):
        return os.path.isdir('{}/.git'.format(directory))

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

    def _manage_new(self, filename):
        """
        Commit a net new file to the git
        """
        failed = False
        log.info('Manage new file: {}'.format(filename))
        self.managed_files[filename] = managed_file_type(new=True, done=False)
        try:
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
                self.git_cmd
                + [
                    'commit',
                    '--allow-empty',
                    '-m',
                    'origin:{}'.format(filename),
                ]
            )
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
        self.managed_files[filename] = managed_file_type(new=False, done=False)
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

    def _finalize(self):
        """
        Cleanup context manager
        """
        registration_success = True
        for filename, managed in self.managed_files.items():
            if not managed.done:
                registration_success = False
        if not registration_success:
            self.cleanup(with_patch=False)
        elif registration_success and self.managed_files:
            exec_subprocess(self.git_cmd + ['commit', '-a', '-m', 'registered'])

    def __exit__(self, exc_type, exc_value, traceback):
        if not self.cleanup_called:
            self._finalize()
