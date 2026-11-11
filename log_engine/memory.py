"""Utilities for reading the current and peak process memory usage."""

import ctypes
import os
import sys

try:
    import resource
except ImportError:  # pragma: no cover - disponible sous Unix uniquement
    resource = None


if sys.platform == "win32":
    from ctypes import wintypes

    class MemoryCounters(ctypes.Structure):
        """Windows structure used by GetProcessMemoryInfo."""

        _fields_ = [
            ("cb", ctypes.c_ulong),
            ("PageFaultCount", ctypes.c_ulong),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    _KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _PSAPI = ctypes.WinDLL("psapi", use_last_error=True)

    _KERNEL32.GetCurrentProcess.argtypes = []
    _KERNEL32.GetCurrentProcess.restype = wintypes.HANDLE
    _PSAPI.GetProcessMemoryInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(MemoryCounters),
        wintypes.DWORD,
    ]
    _PSAPI.GetProcessMemoryInfo.restype = wintypes.BOOL


def get_windows_memory() -> tuple[int, int]:
    """Return the current and peak RSS on Windows."""
    counters = MemoryCounters()
    counters.cb = ctypes.sizeof(counters)
    success = _PSAPI.GetProcessMemoryInfo(
        _KERNEL32.GetCurrentProcess(),
        ctypes.byref(counters),
        counters.cb,
    )
    if not success:
        raise ctypes.WinError(ctypes.get_last_error())
    return counters.WorkingSetSize, counters.PeakWorkingSetSize


def get_current_memory_bytes() -> int:
    """Return the process's current resident memory."""
    if sys.platform == "win32":
        return get_windows_memory()[0]

    try:
        with open("/proc/self/statm", encoding="ascii") as statm_file:
            resident_pages = int(statm_file.readline().split()[1])
        return resident_pages * os.sysconf("SC_PAGE_SIZE")
    except (OSError, IndexError, ValueError):
        return 0


def get_peak_memory_bytes() -> int:
    """Return the peak RSS in bytes for the current operating system."""
    if sys.platform == "win32":
        return get_windows_memory()[1]

    if resource is None:
        return 0

    peak_memory = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "linux":
        return peak_memory * 1024
    return peak_memory
