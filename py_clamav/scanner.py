"""
LibClamAV ctypes binding
"""

from enum import Enum
from pathlib import Path
from ctypes import c_int, c_uint, cdll, c_void_p, c_char_p, byref, Structure, POINTER, c_ulong, create_string_buffer
from ctypes.util import find_library
from typing import NewType, Optional, Union, Tuple

ClEngineP = NewType('ClEngineP', c_void_p)
c_int_p = POINTER(c_int)
c_uint_p = POINTER(c_uint)
c_ulong_p = POINTER(c_ulong)
c_char_pp = POINTER(c_char_p)


class ClScanOptions(Structure):  # pylint: disable=too-few-public-methods
    """
    cl_scan_options structure
    """
    _fields_ = [
        ('general', c_uint),
        ('parse', c_uint),
        ('heuristic', c_uint),
        ('mail', c_uint),
        ('dev', c_uint),
    ]


ClScanOptionsP = POINTER(ClScanOptions)


class ClamavStatuses(Enum):
    """
    ClamAV results
    """
    CL_SUCCESS = 0
    CL_VIRUS = 1
    CL_ENULLARG = 2
    CL_EARG = 3
    CL_EMALFDB = 4
    CL_ECVD = 5
    CL_EVERIFY = 6
    CL_EUNPACK = 7
    CL_EOPEN = 8
    CL_ECREAT = 9
    CL_EUNLINK = 10
    CL_ESTAT = 11
    CL_EREAD = 12
    CL_ESEEK = 13
    CL_EWRITE = 14
    CL_EDUP = 15
    CL_EACCES = 16
    CL_ETMPFILE = 17
    CL_ETMPDIR = 18
    CL_EMAP = 19
    CL_EMEM = 20
    CL_ETIMEOUT = 21
    CL_BREAK = 22
    CL_EMAXREC = 23
    CL_EMAXSIZE = 24
    CL_EMAXFILES = 25
    CL_EFORMAT = 26
    CL_EPARSE = 27
    CL_EBYTECODE = 28
    CL_EBYTECODE_TESTFAIL = 29
    CL_ELOCK = 30
    CL_EBUSY = 31
    CL_ESTATE = 32
    CL_ELAST_ERROR = 33


class Scanner:
    """
    LibClamAV file scanner
    """
    _lib_path: Optional[c_char_p]
    _signo: c_uint

    def __init__(self, lib_path: Optional[str] = None):
        self._lib_path = None
        if lib_path:
            self._lib_path = create_string_buffer(lib_path.encode('utf-8'))

        self._signo = c_uint(0)

        self._lib = find_library('clamav') or find_library('libclamav') or 'libclamav'

        self._libclamav = cdll[self._lib]

        ret = ClamavStatuses(self._libclamav.cl_init(0))
        if ret != ClamavStatuses.CL_SUCCESS:
            raise RuntimeError(self._error('cl_init', ret))

        self._libclamav.cl_engine_new.argtypes = None
        self._libclamav.cl_engine_new.restype = ClEngineP
        self._engine = self._libclamav.cl_engine_new()
        if not self._engine:
            raise RuntimeError(self._error('cl_engine_new', ret))

        self._libclamav.cl_strerror.argtypes = (c_int,)
        self._libclamav.cl_strerror.restype = c_char_p

        self._libclamav.cl_retver.argtypes = None
        self._libclamav.cl_retver.restype = c_char_p

    def load(self):
        """
        Load clamav bases
        """
        self._libclamav.cl_retdbdir.argtypes = None
        self._libclamav.cl_retdbdir.restype = c_char_p

        if not self._lib_path:
            self._lib_path: c_char_p = self._libclamav.cl_retdbdir()

        ret = ClamavStatuses(self._libclamav.cl_load(self._lib_path, self._engine, byref(self._signo), c_uint(0)))
        if ret != ClamavStatuses.CL_SUCCESS:
            raise RuntimeError(self._error('cl_load', ret))

        ret = ClamavStatuses(self._libclamav.cl_engine_compile(self._engine))
        if ret != ClamavStatuses.CL_SUCCESS:
            raise RuntimeError(self._error('cl_engine_compile', ret))

    def __enter__(self):
        self.load()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.free()

    def free(self):
        """
        Free clamav engine
        """
        if self._lib_path:
            del self._lib_path
            self._lib_path = None
        if self._engine:
            ret = ClamavStatuses(self._libclamav.cl_engine_free(self._engine))
            if ret != ClamavStatuses.CL_SUCCESS:
                raise RuntimeError(self._error('cl_engine_free', ret))

    def scan_file(self, file_path: Union[str, Path]):
        """
        Scan file by path
        """
        if not self._engine:
            raise RuntimeError('No lib loaded')

        virname = c_char_p()
        scan_options = ClScanOptions()

        ret = ClamavStatuses(
            self._libclamav.cl_scanfile(
                create_string_buffer((file_path if isinstance(file_path, str) else str(file_path)).encode('utf-8')),
                byref(virname),
                None,
                self._engine,
                byref(scan_options)))
        if ret not in (ClamavStatuses.CL_SUCCESS, ClamavStatuses.CL_VIRUS):
            raise RuntimeError(self._error('cl_scanfile', ret))

        return ret == ClamavStatuses.CL_VIRUS, virname.value.decode('utf-8') if virname.value else None

    def scan_fileno(self, fileno: int, file_path: Optional[Union[str, Path]] = None):
        """
        Scan file by fileno
        """
        if not self._engine:
            raise RuntimeError('No lib loaded')
        virname = c_char_p()
        scan_options = ClScanOptions()

        ret = ClamavStatuses(
            self._libclamav.cl_scandesc(c_int(fileno),
                                        create_string_buffer(((file_path if isinstance(file_path, str) else str(
                                            file_path)).encode('utf-8'))) if file_path else None,
                                        byref(virname),
                                        None,
                                        self._engine,
                                        byref(scan_options))
        )
        if ret not in (ClamavStatuses.CL_SUCCESS, ClamavStatuses.CL_VIRUS):
            raise RuntimeError(self._error('cl_scandesc', ret))

        return ret == ClamavStatuses.CL_VIRUS, virname.value.decode('utf-8') if virname.value else None

    def __del__(self):
        self.free()

    def _error(self, func_name, ret_code: ClamavStatuses):
        err = self._libclamav.cl_strerror(ret_code.value)
        return f'Error {func_name}(): {err.decode("utf-8") if err else None} / {ret_code}'

    @property
    def ver(self) -> Tuple[int, int, int]:
        """
        Clamav bases version
        """
        major, minor, build = self._libclamav.cl_retver().decode('ascii').split('.')
        return int(major), int(minor), int(build)
