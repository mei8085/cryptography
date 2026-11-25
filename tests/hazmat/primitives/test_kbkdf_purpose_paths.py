# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import hashlib
import hmac
import typing

import pytest

from cryptography.exceptions import AlreadyFinalized, InvalidKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.kbkdf import (
    KBKDFCMAC,
    KBKDFHMAC,
    CounterLocation,
    Mode,
)

_LENGTHS = (1, 15, 16, 17, 32, 33, 64, 65, 128, 129)
_LOCATIONS = (
    CounterLocation.BeforeFixed,
    CounterLocation.AfterFixed,
    CounterLocation.MiddleFixed,
)
_PURPOSES = (
    b"authentication/credential/encryption",
    b"authentication/credential/signing",
    b"authentication/credential/wrapping",
)
_CONTEXT = b"principal=alice;session=unit-test"
_AES_MASK = (1 << 128) - 1


def _hmac_reference(
    digest: typing.Callable[[], typing.Any],
) -> typing.Callable[[bytes, bytes], bytes]:
    def prf(key: bytes, data: bytes) -> bytes:
        return hmac.new(key, data, digest).digest()

    return prf


def _xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def _aes_ecb(key: bytes, block: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()


def _cmac_double(subkey: bytes) -> bytes:
    carry = subkey[0] & 0x80
    value = (int.from_bytes(subkey, "big") << 1) & _AES_MASK
    if carry:
        value ^= 0x87
    return value.to_bytes(16, "big")


def _aes_cmac(key: bytes, data: bytes) -> bytes:
    """Independent RFC 4493 AES-CMAC construction over AES-ECB."""
    k1 = _cmac_double(_aes_ecb(key, bytes(16)))
    k2 = _cmac_double(k1)

    full_block_count, remainder = divmod(len(data), 16)
    if remainder or not data:
        final_data = data[full_block_count * 16 :]
        padded = final_data + b"\x80"
        padded += bytes(16 - len(padded))
        final_block = _xor_bytes(padded, k2)
        complete_block_end = full_block_count * 16
    else:
        final_block = _xor_bytes(data[-16:], k1)
        complete_block_end = len(data) - 16

    block = bytes(16)
    for offset in range(0, complete_block_end, 16):
        block = _aes_ecb(key, _xor_bytes(block, data[offset : offset + 16]))
    return _aes_ecb(key, _xor_bytes(block, final_block))


def _reference_counter_kdf(
    prf: typing.Callable[[bytes, bytes], bytes],
    prf_output_size: int,
    key_material: bytes,
    length: int,
    rlen: int,
    fixed: bytes,
    location: CounterLocation,
    break_location: int | None = None,
) -> bytes:
    if location == CounterLocation.BeforeFixed:
        before_counter, after_counter = b"", fixed
    elif location == CounterLocation.AfterFixed:
        before_counter, after_counter = fixed, b""
    else:
        assert break_location is not None
        before_counter = fixed[:break_location]
        after_counter = fixed[break_location:]

    result = b""
    rounds = (length + prf_output_size - 1) // prf_output_size
    for counter in range(1, rounds + 1):
        counter_bytes = counter.to_bytes(rlen, "big")
        prf_input = before_counter + counter_bytes + after_counter
        result += prf(key_material, prf_input)
    return result[:length]


def _encode_fixed_input(
    label: bytes, context: bytes, length: int, llen: int = 4
) -> bytes:
    return label + b"\x00" + context + (length * 8).to_bytes(llen, "big")


class _PrfSpec(typing.NamedTuple):
    spec_id: str
    kdf_class: typing.Any
    algorithm: typing.Any
    prf_output_size: int
    root_key: bytes
    prf: typing.Callable[[bytes, bytes], bytes]


_PRF_SPECS = (
    _PrfSpec(
        "hmac-sha256",
        KBKDFHMAC,
        hashes.SHA256(),
        hashes.SHA256.digest_size,
        b"shared authentication root key",
        _hmac_reference(hashlib.sha256),
    ),
    _PrfSpec(
        "hmac-sha512",
        KBKDFHMAC,
        hashes.SHA512(),
        hashes.SHA512.digest_size,
        b"shared authentication root key",
        _hmac_reference(hashlib.sha512),
    ),
    _PrfSpec(
        "cmac-aes128",
        KBKDFCMAC,
        algorithms.AES,
        algorithms.AES.block_size // 8,
        bytes(range(16)),
        _aes_cmac,
    ),
    _PrfSpec(
        "cmac-aes256",
        KBKDFCMAC,
        algorithms.AES,
        algorithms.AES.block_size // 8,
        bytes(range(32)),
        _aes_cmac,
    ),
)


def _make_kdf(
    spec: _PrfSpec,
    *,
    length: int = 32,
    location: CounterLocation = CounterLocation.BeforeFixed,
    label: bytes | None = b"unit-test-purpose",
    context: bytes | None = _CONTEXT,
    fixed: bytes | None = None,
    llen: int | None = 4,
    break_location: int | None = None,
) -> typing.Any:
    return spec.kdf_class(
        spec.algorithm,
        Mode.CounterMode,
        length,
        4,
        llen,
        location,
        label,
        context,
        fixed,
        break_location=break_location,
    )


def test_reference_aes_cmac_matches_rfc_4493_empty_vector() -> None:
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    expected = "bb1d6929e95937287fa37d129b756746"
    assert _aes_cmac(key, b"").hex() == expected


@pytest.mark.parametrize("length", _LENGTHS)
@pytest.mark.parametrize("location", _LOCATIONS)
@pytest.mark.parametrize(
    "spec", _PRF_SPECS, ids=[spec.spec_id for spec in _PRF_SPECS]
)
class TestKBKDFReferenceDerivation:
    def test_label_context_fixed_and_buffer_match_reference(
        self,
        spec: _PrfSpec,
        location: CounterLocation,
        length: int,
    ) -> None:
        label = b"unit-test-purpose"
        break_location = (
            len(label) + 1 if location == CounterLocation.MiddleFixed else None
        )
        fixed = _encode_fixed_input(label, _CONTEXT, length)
        expected = _reference_counter_kdf(
            spec.prf,
            spec.prf_output_size,
            spec.root_key,
            length,
            4,
            fixed,
            location,
            break_location,
        )

        label_context_kdf = _make_kdf(
            spec,
            length=length,
            location=location,
            label=label,
            break_location=break_location,
        )
        assert label_context_kdf.derive(spec.root_key) == expected

        fixed_kdf = _make_kdf(
            spec,
            length=length,
            location=location,
            label=None,
            context=None,
            fixed=fixed,
            llen=None,
            break_location=break_location,
        )
        assert fixed_kdf.derive(spec.root_key) == expected

        buffer_kdf = _make_kdf(
            spec,
            length=length,
            location=location,
            label=label,
            break_location=break_location,
        )
        output = bytearray(length)
        written = buffer_kdf.derive_into(spec.root_key, output)
        assert written == length
        assert bytes(output) == expected

    def test_purpose_isolation_across_lengths_and_locations(
        self,
        spec: _PrfSpec,
        location: CounterLocation,
        length: int,
    ) -> None:
        credentials = {}
        for purpose in _PURPOSES:
            break_location = (
                len(purpose) + 1
                if location == CounterLocation.MiddleFixed
                else None
            )
            kdf = _make_kdf(
                spec,
                length=length,
                location=location,
                label=purpose,
                break_location=break_location,
            )
            credentials[purpose] = kdf.derive(spec.root_key)

        assert len(set(credentials.values())) == len(_PURPOSES)

        for purpose, credential in credentials.items():
            break_location = (
                len(purpose) + 1
                if location == CounterLocation.MiddleFixed
                else None
            )
            _make_kdf(
                spec,
                length=length,
                location=location,
                label=purpose,
                break_location=break_location,
            ).verify(spec.root_key, credential)

            for other_purpose in _PURPOSES:
                if other_purpose == purpose:
                    continue
                other_break = (
                    len(other_purpose) + 1
                    if location == CounterLocation.MiddleFixed
                    else None
                )
                with pytest.raises(InvalidKey):
                    _make_kdf(
                        spec,
                        length=length,
                        location=location,
                        label=other_purpose,
                        break_location=other_break,
                    ).verify(spec.root_key, credential)


@pytest.mark.parametrize(
    "spec", _PRF_SPECS, ids=[spec.spec_id for spec in _PRF_SPECS]
)
class TestKBKDFFailedDerivationIsFinalized:
    @pytest.mark.parametrize(
        ("label", "context"),
        [
            (b"label", None),
            (None, b"context"),
            (b"label", b"context"),
        ],
    )
    def test_conflicting_fixed_and_purpose_data_returns_no_instance(
        self,
        spec: _PrfSpec,
        label: bytes | None,
        context: bytes | None,
    ) -> None:
        kdf = None
        with pytest.raises(ValueError, match="fixed data"):
            kdf = _make_kdf(
                spec,
                label=label,
                context=context,
                fixed=b"already encoded",
            )
        assert kdf is None

    def test_missing_llen_returns_no_instance(self, spec: _PrfSpec) -> None:
        kdf = None
        with pytest.raises(ValueError, match="Please specify an llen"):
            kdf = _make_kdf(spec, llen=None)
        assert kdf is None

    def test_invalid_middle_break_finalizes_instance(
        self, spec: _PrfSpec
    ) -> None:
        fixed = b"fixed-data"
        kdf = _make_kdf(
            spec,
            location=CounterLocation.MiddleFixed,
            label=None,
            context=None,
            fixed=fixed,
            llen=None,
            break_location=len(fixed) + 1,
        )

        with pytest.raises(ValueError, match="break_location offset"):
            kdf.derive(spec.root_key)

        with pytest.raises(AlreadyFinalized):
            kdf.derive(spec.root_key)
        with pytest.raises(AlreadyFinalized):
            kdf.verify(spec.root_key, bytes(32))

        output = bytearray(32)
        with pytest.raises(AlreadyFinalized):
            kdf.derive_into(spec.root_key, output)
        assert bytes(output) == bytes(32)

    def test_failed_verify_finalizes_instance(self, spec: _PrfSpec) -> None:
        credential = _make_kdf(spec).derive(spec.root_key)
        wrong_credential = bytearray(credential)
        wrong_credential[0] ^= 1

        kdf = _make_kdf(spec)
        with pytest.raises(InvalidKey):
            kdf.verify(spec.root_key, bytes(wrong_credential))

        with pytest.raises(AlreadyFinalized):
            kdf.verify(spec.root_key, credential)
        with pytest.raises(AlreadyFinalized):
            kdf.derive(spec.root_key)

    @pytest.mark.parametrize("buffer_length", [31, 33])
    def test_incorrect_buffer_finalizes_without_writing(
        self, spec: _PrfSpec, buffer_length: int
    ) -> None:
        kdf = _make_kdf(spec, length=32)
        original = b"\xa5" * buffer_length
        output = bytearray(original)

        with pytest.raises(ValueError, match="buffer must be 32 bytes"):
            kdf.derive_into(spec.root_key, output)

        assert bytes(output) == original
        with pytest.raises(AlreadyFinalized):
            kdf.derive_into(spec.root_key, bytearray(32))


class TestKBKDFCMACConfiguration:
    def test_invalid_block_cipher_key_finalizes_instance(self) -> None:
        kdf = KBKDFCMAC(
            algorithms.AES,
            Mode.CounterMode,
            32,
            4,
            4,
            CounterLocation.BeforeFixed,
            b"label",
            b"context",
            None,
        )

        with pytest.raises(ValueError, match="Invalid key size"):
            kdf.derive(b"bad-key")

        with pytest.raises(AlreadyFinalized):
            kdf.derive(bytes(32))
