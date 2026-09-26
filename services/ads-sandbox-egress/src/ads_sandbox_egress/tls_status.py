"""Bounded public-ABI OCSP byte ownership, not a status verification decision.

OpenSSL 4's extended stack represents missing chain entries as NULL. Ownership
of a newly constructed stack transfers to SSL; acquisition borrows native
objects and returns independent DER bytes. No private-key or native pointer
escapes this module.
"""

from __future__ import annotations

from typing import Any

from ads_sandbox_egress.tls import TLSFailure, TLSLibrary


def acquire_staples(library: TLSLibrary, connection: Any) -> tuple[bytes | None, ...]:
    ffi, ssl, crypto = library.ffi, library.ssl, library.crypto
    pointer = ffi.new("OPENSSL_STACK **")
    count = ssl.SSL_ctrl(connection, 142, 0, pointer)
    if count == -1:
        return ()
    if not 0 <= count <= 16 or count and pointer[0] == ffi.NULL:
        raise TLSFailure("origin_status_count")
    result: list[bytes | None] = []
    total = 0
    for index in range(count):
        response = ffi.cast("OCSP_RESPONSE *", crypto.OPENSSL_sk_value(pointer[0], index))
        if response == ffi.NULL:
            result.append(None)
            continue
        length = crypto.i2d_OCSP_RESPONSE(response, ffi.NULL)
        total += length
        if not 1 <= length <= 65536 or total > 131072:
            raise TLSFailure("origin_status_limit")
        buffer = ffi.new("unsigned char[]", length)
        output = ffi.new("unsigned char **", buffer)
        if crypto.i2d_OCSP_RESPONSE(response, output) != length:
            raise TLSFailure("origin_status_encoding")
        result.append(bytes(ffi.buffer(buffer, length)))
    return tuple(result)


def install_staples(
    library: TLSLibrary, connection: Any, responses: tuple[bytes | None, ...]
) -> None:
    if len(responses) > 16 or sum(len(r) for r in responses if r is not None) > 131072:
        raise TLSFailure("tls_status_limit")
    if not responses:
        return
    ffi, ssl, crypto = library.ffi, library.ssl, library.crypto
    stack = crypto.OPENSSL_sk_new_null()
    library.require(stack, "tls_status_allocation")
    retained = []
    try:
        for value in responses:
            response = ffi.NULL
            if value is not None:
                if not isinstance(value, bytes) or not 1 <= len(value) <= 65536:
                    raise TLSFailure("tls_status_limit")
                buffer = ffi.new("unsigned char[]", value)
                pointer = ffi.new("const unsigned char **", buffer)
                response = crypto.d2i_OCSP_RESPONSE(ffi.NULL, pointer, len(value))
                library.require(response, "tls_status_decode")
                retained.append(response)
                if pointer[0] != buffer + len(value):
                    raise TLSFailure("tls_status_trailing_data")
            library.require(crypto.OPENSSL_sk_push(stack, response), "tls_status_allocation")
        library.require(ssl.SSL_ctrl(connection, 143, 0, stack), "tls_status_install")
        # SSL now owns every response and the stack. Never free them twice.
        retained.clear()
        stack = ffi.NULL
    finally:
        for response in retained:
            crypto.OCSP_RESPONSE_free(response)
        crypto.OPENSSL_sk_free(stack)
