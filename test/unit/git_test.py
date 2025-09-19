from unittest.mock import (
    patch, call, Mock
)
from pytest import (
    raises, fixture
)
from cloudregister.logger import Logger
from cloudregister.git import (
    Git,
    managed_file_type
)
from cloudregister.exceptions import (
    CloudRegisterGitError,
    CloudRegisterScopeError,
    CloudRegisterPathError
)

log_instance = Logger()
log = Logger.get_logger()


class TestGit:
    @fixture(autouse=True)
    def inject_fixtures(self, caplog):
        self._caplog = caplog

    @patch('os.path.isdir')
    @patch('os.path.isfile')
    @patch('cloudregister.git.exec_subprocess')
    @patch('cloudregister.git.clean_all_legacy')
    @patch('cloudregister.git.Path')
    @patch.object(Git, 'is_empty')
    def setup(
        self, mock_is_empty, mock_Path, mock_clean_all_legacy,
        mock_exec_subprocess, mock_os_path_isfile, mock_os_path_isdir
    ):
        mock_exec_subprocess.return_value = (b'stdout', b'stderr', 1)
        mock_os_path_isdir.return_value = False
        mock_os_path_isfile.return_value = True
        self.git = Git('/some')

        # test legacy cleanup and init
        mock_clean_all_legacy.assert_called_once_with()
        assert mock_exec_subprocess.call_args_list == [
            call(['git', 'init', '/some']),
            call(
                [
                    'git', '--work-tree', '/some', '--git-dir', '/some/.git',
                    'config', 'user.email', 'public-cloud-dev@susecloud.net'
                ]
            ),
            call(
                [
                    'git', '--work-tree', '/some', '--git-dir', '/some/.git',
                    'config', 'user.name', 'Public Cloud Team'
                ]
            )
        ]

        # test context manager cleanup
        mock_is_empty.return_value = True
        with Git('/some') as some_manage:
            some_manage.managed_files['some'] = managed_file_type(
                new=True, done=False
            )
        mock_Path.return_value.unlink.assert_called_once_with()

        # test init exception
        mock_exec_subprocess.side_effect = Exception
        with raises(CloudRegisterGitError):
            self.git = Git('/some')

    @patch('os.path.isdir')
    @patch('os.path.isfile')
    @patch('cloudregister.git.exec_subprocess')
    @patch('cloudregister.git.clean_all_legacy')
    @patch('cloudregister.git.Path')
    @patch.object(Git, 'is_empty')
    def setup_method(
        self, cls, mock_is_empty, mock_Path, mock_clean_all_legacy,
        mock_exec_subprocess, mock_os_path_isfile, mock_os_path_isdir
    ):
        self.setup()

    @patch('cloudregister.git.exec_subprocess')
    def test_known_to_git(self, mock_exec_subprocess):
        mock_exec_subprocess.return_value = (b'', b'', 0)
        assert self.git._known_to_git('some') is True
        mock_exec_subprocess.assert_called_once_with(
            [
                'git',
                '--work-tree', '/some',
                '--git-dir', '/some/.git',
                'ls-files', '--error-unmatch',
                'some'
            ]
        )
        mock_exec_subprocess.return_value = (b'', b'', 1)
        assert self.git._known_to_git('some') is False

    @patch('os.path.exists')
    @patch('cloudregister.git.Path')
    def test_is_empty(self, mock_Path, mock_os_path_exists):
        path = Mock()
        path.stat.return_value = Mock(
            st_size=0
        )
        mock_Path.return_value = path
        mock_os_path_exists.return_value = False
        assert self.git.is_empty('some') is True
        mock_os_path_exists.return_value = True
        assert self.git.is_empty('some') is True
        path.stat.return_value = Mock(
            st_size=1
        )
        assert self.git.is_empty('some') is False

    @patch('os.path.exists')
    @patch.object(Git, '_is_managed')
    @patch.object(Git, '_manage_new')
    @patch.object(Git, '_manage_existing')
    def test_manage(
        self, mock_manage_existing, mock_manage_new,
        mock_is_managed, mock_os_path_exists
    ):
        mock_is_managed.return_value = False
        mock_os_path_exists.return_value = False
        self.git.manage('some')
        mock_manage_new.assert_called_once_with('some')
        mock_os_path_exists.return_value = True
        self.git.manage('some')
        mock_manage_existing.assert_called_once_with('some')

    def test_done(self):
        self.git.managed_files['some'] = managed_file_type(
            new=True, done=False
        )
        self.git.managed_files['other'] = managed_file_type(
            new=True, done=False
        )
        self.git.done()
        assert self.git.managed_files['some'].done is True

    @patch('cloudregister.git.exec_subprocess')
    @patch('cloudregister.git.Path')
    @patch.object(Git, 'is_empty')
    def test_cleanup(self, mock_is_empty, mock_Path, mock_exec_subprocess):
        mock_exec_subprocess.return_value = (b'some_modified_file', b'', 0)
        mock_is_empty.return_value = True
        self.git.cleanup()
        assert mock_exec_subprocess.call_args_list == [
            call(
                [
                    'git',
                    '--work-tree', '/some',
                    '--git-dir', '/some/.git',
                    'ls-files', '-m'
                ]
            ),
            call(
                [
                    'git',
                    '--work-tree', '/some',
                    '--git-dir', '/some/.git',
                    'checkout', '/some/some_modified_file'
                ]
            )
        ]
        mock_exec_subprocess.return_value = (b'some_modified_file', '', 1)
        self.git.cleanup()
        assert 'Could not checkout origin' in self._caplog.text

    def test_is_managed(self):
        assert self.git._is_managed('/some') is False
        with raises(CloudRegisterScopeError):
            self.git._is_managed('other')
        self.git.managed_files['/some'] = managed_file_type(
            new=True, done=False
        )
        assert self.git._is_managed('/some') is True

    @patch('cloudregister.git.exec_subprocess')
    def test_manage_new(self, mock_exec_subprocess):
        mock_exec_subprocess.return_value = (b'', b'', 0)
        with patch('builtins.open', create=True) as mock_open:
            mock_open.side_effect = Exception
            with raises(CloudRegisterPathError):
                self.git._manage_new('some')

        with patch('builtins.open', create=True):
            self.git._manage_new('some')
            assert mock_exec_subprocess.call_args_list == [
                call(
                    [
                        'git',
                        '--work-tree', '/some',
                        '--git-dir', '/some/.git',
                        'add', 'some'
                    ]
                ),
                call(
                    [
                        'git',
                        '--work-tree', '/some',
                        '--git-dir', '/some/.git',
                        'commit', '--allow-empty', '-m',
                        'origin:some'
                    ]
                )
            ]

        mock_exec_subprocess.return_value = (b'', b'', 1)
        with patch('builtins.open', create=True):
            with raises(CloudRegisterGitError):
                self.git._manage_new('some')

    @patch('cloudregister.git.exec_subprocess')
    @patch.object(Git, '_known_to_git')
    def test_manage_existing(self, mock_known_to_git, mock_exec_subprocess):
        mock_known_to_git.return_value = True
        self.git._manage_existing('some')
        assert 'already managed' in self._caplog.text
        mock_known_to_git.return_value = False
        mock_exec_subprocess.return_value = (b'', b'', 1)
        with raises(CloudRegisterGitError):
            self.git._manage_existing('some')
        mock_exec_subprocess.reset_mock()
        mock_exec_subprocess.return_value = (b'', b'', 0)
        self.git._manage_existing('some')
        assert mock_exec_subprocess.call_args_list == [
            call(
                [
                    'git',
                    '--work-tree', '/some',
                    '--git-dir', '/some/.git',
                    'add', 'some'
                ]
            ),
            call(
                [
                    'git',
                    '--work-tree', '/some',
                    '--git-dir', '/some/.git',
                    'commit', '-m', 'origin:some'
                ]
            )
         ]
