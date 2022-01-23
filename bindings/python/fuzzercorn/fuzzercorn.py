import ctypes
from typing import Any, Callable, List, Tuple
import pkg_resources
import sys
import distutils
import distutils.sysconfig
import os

from pathlib import Path
from unicorn import Uc, UcError

_lib = {'darwin': 'libfuzzercorn.dylib',
        'linux': 'libfuzzercorn.so',
        'linux2': 'libfuzzercorn.so'}.get(sys.platform, "libfuzzercorn.so")

_path_list = [Path(pkg_resources.resource_filename(__name__, 'lib')),
              Path(os.path.realpath(__file__)).parent / "lib",
              Path(''),
              Path(distutils.sysconfig.get_python_lib()),
              Path("/usr/local/lib/" if sys.platform ==
                   'darwin' else '/usr/lib64'),
              Path(os.getenv('PATH', ''))]


def _load_lib(path: Path):
    try:
        return ctypes.cdll.LoadLibrary(path / _lib)
    except OSError as e:
        return None


_fuzzercorn = None

for _p in _path_list:
    _fuzzercorn = _load_lib(_p)
    if _fuzzercorn is not None:
        break
else:
    raise ImportError("Fail to load the dynamic library for fuzzercorn.")

FUZZERCORN_ERR_OK = 0
FUZZERCORN_ERR_CALLED_TWICE = 1
FUZZERCORN_ERR_MEM = 2
FUZZERCORN_ERR_ARG = 3
FUZZERCORN_ERR_UC_VER = 4
FUZZERCORN_ERR_UC_ERR = 5

class FuzzerCornError(Exception):

    def __init__(self, errno: int):
        self.errno = errno
    
    def __str__(self) -> str:
        mp = {
            FUZZERCORN_ERR_CALLED_TWICE : "FuzzerCornFuzz is called twice. Not a real error.",
            FUZZERCORN_ERR_MEM : "Run out of memory.",
            FUZZERCORN_ERR_ARG : "Wrong arguments.",
            FUZZERCORN_ERR_UC_VER : "Wrong Unicorn version.",
            FUZZERCORN_ERR_UC_ERR : "Unicorn went wrong.",
        }
        return mp.get(self.errno, f"{self.errno}")


class InstrumentRange(ctypes.Structure):
    _fields_ = [("begin", ctypes.c_uint64),
                ("end", ctypes.c_uint64)]


PArgcType = ctypes.POINTER(ctypes.c_int)
PArgvType = ctypes.POINTER(ctypes.POINTER(ctypes.c_char_p))
PUint8 = ctypes.c_void_p # By design to reduce ctypes.cast

_fuzzercorn.FuzzerCornFuzz.restype = ctypes.c_int
_fuzzercorn.FuzzerCornFuzz.argtypes = (
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,  # Uc, Argc, Argv exits
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, # Callbacks
    ctypes.c_void_p, ctypes.c_size_t, # Ranges
    ctypes.c_void_p, ctypes.c_bool, ctypes.c_void_p, ctypes.c_size_t) # UserData, AlwaysValidate, ExitCode, CounterCount

InitCB = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, PArgcType, PArgvType, ctypes.c_void_p)
InputCB = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, PUint8, ctypes.c_size_t, ctypes.c_void_p)
ValidateCB = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_int, PUint8, ctypes.c_size_t, ctypes.c_void_p)
MutatorCB = ctypes.CFUNCTYPE(ctypes.c_size_t, ctypes.c_void_p, PUint8, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_uint, ctypes.c_void_p)
CrossOverCB = ctypes.CFUNCTYPE(ctypes.c_size_t, ctypes.c_void_p,
    PUint8, ctypes.c_size_t,
    PUint8, ctypes.c_size_t, 
    PUint8, ctypes.c_size_t, 
    ctypes.c_uint, ctypes.c_void_p)

def FuzzerCornFuzz(UC: Uc, 
                   Argv: List[str],
                   Exits: List[int],
                   PlaceInputCallback: Callable[[Uc, ctypes.Array, Any], int],
                   InitializeCallback: Callable[[Uc, List[ctypes.c_char_p], Any], int] = None,
                   ValidateCallback: Callable[[Uc, UcError, ctypes.Array], Any] = None,
                   CustomMutatorCallback: Callable[[Uc, ctypes.Array, int, int, Any], int] = None,
                   CustomCrossOverCallback: Callable[[Uc, ctypes.Array, ctypes.Array, ctypes.Array, int, Any], int] = None,
                   Ranges: List[Tuple[int, int]] = None,
                   UserData: Any = None,
                   AlwaysValidate: bool = False,
                   CountersCount: int = 8192):
    
    def _ret_none_wrapper(f):

        def _func(*args, **kwargs):
            ret = f(*args, **kwargs)
            if ret is None:
                return 0
            else:
                return ret
        
        return _func

    @_ret_none_wrapper
    def _validate_wrapper(_: int, err:int, data: PUint8, size: int, __: Any):
        return ValidateCallback(UC, UcError(err), (ctypes.c_uint8 * size).from_address(data), UserData )

    @_ret_none_wrapper
    def _place_input_wrapper(_: int, data: PUint8, size: int, __: Any):
        return PlaceInputCallback(UC, (ctypes.c_uint8 * size).from_address(data), UserData)

    @_ret_none_wrapper
    def _initialize_wrapper(_: int, pargc: PArgcType, pargv: PArgvType, __: Any):
        argc = pargc.contents.value
        argv = (ctypes.c_char_p * (argc + 1)).from_address(ctypes.cast(pargv.contents, ctypes.c_void_p).value)
        return InitializeCallback(UC, argv, UserData)
    
    @_ret_none_wrapper
    def _custom_mutator_wrapper(_: int, data: PUint8, size: int, max_size: int, seed: int, __: Any):
        return CustomMutatorCallback(UC, (ctypes.c_uint8 * size).from_address(data), max_size, seed, UserData)
    
    @_ret_none_wrapper
    def _custom_cross_over_wrapper(_: int,
        data1: PUint8, size1: int, 
        data2: PUint8, size2: int, 
        out: PUint8, out_size: int, 
        seed: int, __: Any):
        return CustomCrossOverCallback(UC,
            (ctypes.c_uint8 * size1).from_address(data1),
            (ctypes.c_uint8 * size2).from_address(data2),
            (ctypes.c_uint8 * out_size).from_address(out),
            seed, UserData
        )

    argc = ctypes.c_int(len(Argv))
    argv = (ctypes.c_void_p * (len(Argv) + 1))()

    for idx, arg in enumerate(Argv):
        argv[idx] = ctypes.cast(ctypes.create_string_buffer(arg.encode("utf-8")), ctypes.c_void_p)

    # ctypes.cast(argv, ctypes.c_void_p) -> char** (recall argv was an array!) &(char*[]) -> char**
    argv = ctypes.cast(argv, ctypes.c_void_p)
    # ctypes.cast(argv, ctypes.c_void_p) -> char*** since argv is a pointer now &char** -> char***
    
    if Ranges:
        ranges = (InstrumentRange * len(Ranges))()

        for idx, range in enumerate(Ranges):
            ranges[idx].begin, ranges[idx].end = range

    exits = (ctypes.c_uint64 * len(Exits))()
     
    for idx, exit in enumerate(Exits):
        exits[idx] = exit

    exit_code = ctypes.c_int()

    err = _fuzzercorn.FuzzerCornFuzz(UC._uch,
            ctypes.cast(ctypes.addressof(argc), ctypes.c_void_p), 
            ctypes.cast(ctypes.addressof(argv), ctypes.c_void_p),
            ctypes.cast(exits, ctypes.c_void_p),
            len(Exits),
            ctypes.cast(InputCB(_place_input_wrapper), ctypes.c_void_p) if PlaceInputCallback else None,
            ctypes.cast(InitCB(_initialize_wrapper), ctypes.c_void_p) if InitializeCallback else None,
            ctypes.cast(ValidateCB(_validate_wrapper), ctypes.c_void_p) if ValidateCallback else None,
            ctypes.cast(MutatorCB(_custom_mutator_wrapper), ctypes.c_void_p) if CustomMutatorCallback else None,
            ctypes.cast(CrossOverCB(_custom_cross_over_wrapper), ctypes.c_void_p) if CustomCrossOverCallback else None,
            ctypes.cast(ctypes.addressof(ranges), ctypes.c_void_p) if Ranges else None,
            len(Ranges) if Ranges else 0,
            None,
            AlwaysValidate,
            ctypes.cast(ctypes.addressof(exit_code), ctypes.c_void_p),
            CountersCount)
    
    if err != FUZZERCORN_ERR_OK:
        raise FuzzerCornError(err)
    
    return exit_code.value