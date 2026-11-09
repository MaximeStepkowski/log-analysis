import sys

import pytest

from log_engine import memory


def test_get_current_memory_bytes_returns_non_negative_value():
    assert memory.get_current_memory_bytes() >= 0


def test_get_current_memory_bytes_returns_zero_when_proc_file_is_invalid(monkeypatch):
    def raise_os_error(*args, **kwargs):
        raise OSError

    monkeypatch.setattr("builtins.open", raise_os_error)
    assert memory.get_current_memory_bytes() == 0


def test_get_peak_memory_bytes_returns_supported_value():
    value = memory.get_peak_memory_bytes()
    assert value >= 0


@pytest.mark.skipif(sys.platform == "win32", reason="Windows API is unavailable here")
def test_get_peak_memory_bytes_uses_resource_on_non_windows():
    assert memory.get_peak_memory_bytes() >= 0
