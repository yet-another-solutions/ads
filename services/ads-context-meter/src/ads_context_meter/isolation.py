"""Linux kernel-enforced no-network boundary for the counting subprocess."""

import ctypes
import ctypes.util
import errno


def deny_network() -> None:
    """Install a permanent seccomp filter; fail closed if unavailable.

    Pool pipes already exist. New sockets, outbound socket operations, and exec
    are forbidden, including in native tokenizer/Hugging Face code and threads.
    The filter is inherited by any child thread/process.
    """
    library = ctypes.util.find_library("seccomp")
    if library is None:
        raise RuntimeError("libseccomp is required for the offline context meter worker")
    lib = ctypes.CDLL(library, use_errno=True)
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    lib.seccomp_rule_add.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_uint,
    ]
    lib.seccomp_rule_add.restype = ctypes.c_int
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_load.restype = ctypes.c_int
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    context = lib.seccomp_init(0x7FFF0000)  # SCMP_ACT_ALLOW
    if not context:
        raise RuntimeError("cannot initialize worker seccomp filter")
    try:
        for name in (
            b"socket",
            b"socketpair",
            b"connect",
            b"sendto",
            b"sendmsg",
            b"sendmmsg",
            b"execve",
            b"execveat",
        ):
            syscall = lib.seccomp_syscall_resolve_name(name)
            if (
                syscall == -1
                or lib.seccomp_rule_add(
                    context,
                    0x00050000 | errno.EPERM,
                    syscall,
                    0,  # SCMP_ACT_ERRNO
                )
                != 0
            ):
                raise RuntimeError("cannot configure worker seccomp filter")
        if lib.seccomp_load(context) != 0:
            raise RuntimeError("cannot activate worker seccomp filter")
    finally:
        lib.seccomp_release(context)
