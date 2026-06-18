import os
import stat
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from response.ansible_exec import _write_secure_file, _ensure_secure_dir


class TestAnsibleSecretHandling:
    def test_ensure_secure_dir_sets_0700(self, tmp_path):
        target = tmp_path / "playbooks" / "test"
        _ensure_secure_dir(target)
        assert target.exists()
        mode = stat.S_IMODE(target.stat().st_mode)
        assert mode == 0o700

    def test_write_secure_file_sets_0600(self, tmp_path):
        target = tmp_path / "inventory.ini"
        _write_secure_file(target, "ansible_ssh_pass='secret'\n")
        assert target.exists()
        mode = stat.S_IMODE(target.stat().st_mode)
        assert mode == 0o600
        content = target.read_text()
        assert "secret" in content

    def test_inventory_does_not_contain_password_in_api_response(self):
        # Placeholder: actual API response test would need full FastAPI test client
        # This documents the requirement.
        pass
