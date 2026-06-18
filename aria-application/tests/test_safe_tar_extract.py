import tarfile
import pytest
from pathlib import Path
from io import BytesIO
from response.ansible_exec import _safe_extract_tar


class TestSafeTarExtract:
    def test_normal_tar_extracts(self, tmp_path):
        tar_path = tmp_path / "normal.tar"
        dest = tmp_path / "dest"
        with tarfile.open(tar_path, "w") as tar:
            data = b"hello world"
            info = tarfile.TarInfo(name="hello.txt")
            info.size = len(data)
            tar.addfile(info, BytesIO(data))
        _safe_extract_tar(tar_path, dest)
        assert (dest / "hello.txt").read_text() == "hello world"

    def test_traversal_blocked(self, tmp_path):
        tar_path = tmp_path / "bad.tar"
        dest = tmp_path / "dest"
        with tarfile.open(tar_path, "w") as tar:
            data = b"evil"
            info = tarfile.TarInfo(name="../../../tmp/evil.txt")
            info.size = len(data)
            tar.addfile(info, BytesIO(data))
        with pytest.raises(ValueError, match="path traversal"):
            _safe_extract_tar(tar_path, dest)

    def test_absolute_path_blocked(self, tmp_path):
        tar_path = tmp_path / "bad.tar"
        dest = tmp_path / "dest"
        with tarfile.open(tar_path, "w") as tar:
            data = b"evil"
            info = tarfile.TarInfo(name="/etc/passwd")
            info.size = len(data)
            tar.addfile(info, BytesIO(data))
        with pytest.raises(ValueError, match="path traversal"):
            _safe_extract_tar(tar_path, dest)
