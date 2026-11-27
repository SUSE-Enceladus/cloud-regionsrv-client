from unittest.mock import patch
from cloudregister.defaults import Defaults


class TestDefaults:
    @patch('os.path.exists')
    def test_get_managed_files(self, mock_os_path_exists):
        mock_os_path_exists.return_value = True
        assert Defaults.get_managed_files('/etc') == [
            '/etc/zypp',
            '/etc/pki/trust/anchors',
            '/etc/uyuni/uyuni-tools.yaml',
            '/etc/docker/daemon.json',
            '/etc/containers/registries.conf',
            '/etc/profile.local',
            '/etc/containers/config.json',
            '/etc/hosts',
        ]
