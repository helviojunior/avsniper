import os
import sys
import time
from ctypes import *
from pathlib import Path

from avsniper.util.logger import Logger
from avsniper.util.tools import Tools
from avsniper.config import Configuration

WORD = c_ushort
DWORD = c_ulong
LPBYTE = POINTER(c_ubyte)
LPTSTR = POINTER(c_char)
HANDLE = c_void_p


class ExeRunner(object):

    @staticmethod
    def execute(file_name: str) -> bool:

        if os.name != 'nt':
            return False

        exe_file = str(Path(file_name).resolve())
        kernel32 = windll.kernel32
        CREATE_NEW_CONSOLE = 0x00000010
        CREATE_SUSPENDED = 0x00000004
        creation_flags = CREATE_NEW_CONSOLE | CREATE_SUSPENDED

        startupinfo = STARTUPINFO()
        processinfo = PROCESS_INFORMATION()
        startupinfo.cb = sizeof(startupinfo)

        # In Python 3.x you should use not CreateProcessA but CreateProcessW function because all string is in unicode
        if kernel32.CreateProcessW(
                None, exe_file, None, None, None, creation_flags, None, None,
                byref(startupinfo), byref(processinfo)):
            kernel32.CloseHandle(processinfo.hProcess)
            kernel32.CloseHandle(processinfo.hThread)
            time.sleep(0.1)
            os.kill(processinfo.dwProcessId, 9)
            return True
        else:
            if Configuration.verbose >= 3:
                Tools.clear_line()
                Logger.pl('{!} {R}CreateProcessW failed with an error: "{O}%s{R}"{W}' %
                          f"0x{kernel32.GetLastError():08x}")
            return False


class STARTUPINFO(Structure):
    _fields_ = [
        ('cb', DWORD),
        ('lpReserved', LPTSTR),
        ('lpDesktop', LPTSTR),
        ('lpTitle', LPTSTR),
        ('dwX', DWORD),
        ('dwY', DWORD),
        ('dwXSize', DWORD),
        ('dwYSize', DWORD),
        ('dwXCountChars', DWORD),
        ('dwYCountChars', DWORD),
        ('dwFillAttribute', DWORD),
        ('dwFlags', DWORD),
        ('wShowWindow', WORD),
        ('cbReserved2', WORD),
        ('lpReserved2', LPBYTE),
        ('hStdInput', HANDLE),
        ('hStdOutput', HANDLE),
        ('hStdError', HANDLE),
    ]


class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ('hProcess', HANDLE),
        ('hThread', HANDLE),
        ('dwProcessId', DWORD),
        ('dwThreadId', DWORD),
    ]
