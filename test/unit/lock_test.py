import io
import fcntl
from unittest.mock import patch, MagicMock, Mock
from pytest import fixture
from cloudregister.lock import Lock


class TestLock:
    @fixture(autouse=True)
    def inject_fixtures(self, caplog):
        self._caplog = caplog

    def setup_method(self, cls):
        self.lock = Lock()

    @patch('fcntl.flock')
    @patch('os.getpid')
    @patch('os.path.exists')
    def test_lock_acquire(
        self, mock_os_path_exists, mock_os_getpid, mock_flock
    ):
        mock_os_path_exists.return_value = False
        mock_os_getpid.return_value = 42
        with patch('builtins.open', create=True) as mock_open:
            fd = MagicMock(spec=io.IOBase)
            fd.write = Mock()
            fd.flush = Mock()
            mock_open.return_value = fd
            assert self.lock.acquire() == fd
            fd.write.assert_called_once_with('42')
            fd.flush.assert_called_once_with()
            mock_flock.assert_called_once_with(
                fd.fileno.return_value, fcntl.LOCK_EX | fcntl.LOCK_NB
            )

    @patch('fcntl.flock')
    @patch('os.getpid')
    @patch('os.path.exists')
    @patch.object(Lock, '_read_cmdline')
    def test_lock_acquire_already_locked_different_call_args(
        self, mock_read_cmdline, mock_os_path_exists, mock_os_getpid, mock_flock
    ):
        mock_os_path_exists.return_value = True
        mock_os_getpid.return_value = 42

        def read_cmdline_call(pid):
            if pid == '99':
                return 'some_locked'
            else:
                return 'some_call'

        def flock_call(fileno, attrs):
            if attrs == fcntl.LOCK_EX | fcntl.LOCK_NB:
                raise IOError

        mock_flock.side_effect = flock_call
        mock_read_cmdline.side_effect = read_cmdline_call

        with patch('builtins.open', create=True) as mock_open:
            fd = MagicMock(spec=io.IOBase)
            fd.read = Mock(return_value='99')
            mock_open.return_value = fd
            assert self.lock.acquire() == fd
            assert 'is locked by PID: 99' in self._caplog.text

    @patch('fcntl.flock')
    @patch('os.getpid')
    @patch('os.path.exists')
    @patch.object(Lock, '_read_cmdline')
    def test_lock_acquire_already_locked_same_call_args(
        self, mock_read_cmdline, mock_os_path_exists, mock_os_getpid, mock_flock
    ):
        mock_os_path_exists.return_value = True
        mock_os_getpid.return_value = 42

        def read_cmdline_call(pid):
            return 'some_same_call'

        def flock_call(fileno, attrs):
            if attrs == fcntl.LOCK_EX | fcntl.LOCK_NB:
                raise IOError

        mock_flock.side_effect = flock_call
        mock_read_cmdline.side_effect = read_cmdline_call

        with patch('builtins.open', create=True) as mock_open:
            fd = MagicMock(spec=io.IOBase)
            fd.read = Mock(return_value='99')
            mock_open.return_value = fd
            assert self.lock.acquire() == Lock.sameProcess()
            assert 'already running as PID: 99' in self._caplog.text

    @patch('os.path.exists')
    def test_lock_is_locked_locked(self, mock_path):
        mock_path.return_value = True
        assert self.lock.is_locked() is True

    @patch('os.path.exists')
    def test_lock_is_locked_unlocked(self, mock_path):
        mock_path.return_value = False
        assert self.lock.is_locked() is False

    def test_read_cmdline(self):
        with patch('builtins.open', create=True) as mock_open:
            mock_open.return_value = MagicMock(spec=io.IOBase)
            file_handle = mock_open.return_value.__enter__.return_value
            file_handle.read.return_value = 'some'
            assert self.lock._read_cmdline('42') == 'some'

    @patch('fcntl.flock')
    def test_release(self, mock_flock):
        fd = MagicMock(spec=io.IOBase)
        self.lock.release(fd)
        mock_flock.assert_called_once_with(
            fd.fileno.return_value, fcntl.LOCK_UN
        )
