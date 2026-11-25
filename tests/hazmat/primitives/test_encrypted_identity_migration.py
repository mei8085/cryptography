# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import functools
import os
import warnings
from collections.abc import Callable
from typing import Any, Union

import pytest

from cryptography import utils
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_der_private_key,
    load_pem_private_key,
    load_ssh_private_key,
    ssh,
)
from cryptography.hazmat.primitives.serialization.pkcs12 import (
    load_pkcs12,
    serialize_key_and_certificates,
)

from ...utils import load_vectors_from_file

_PASSWORD = b"password"
_WRONG_PASSWORD = b"not-the-password"

pytestmark = pytest.mark.skipif(
    not ssh._bcrypt_supported,
    reason="Password-protected OpenSSH identity vectors require bcrypt",
)

Loader = Callable[..., Any]
ExpectedError = Union[type[BaseException], tuple[type[BaseException], ...]]

_DSA_IDENTITY_KEY = pytest.param(
    "dsa-psw.key",
    dsa.DSAPrivateKey,
    id="dsa",
    marks=pytest.mark.supported(
        only_if=lambda backend: backend.dsa_supported(),
        skip_message="Does not support DSA.",
    ),
)
_IDENTITY_KEYS = [
    pytest.param("rsa-psw.key", rsa.RSAPrivateKey, id="rsa"),
    _DSA_IDENTITY_KEY,
    pytest.param("ecdsa-psw.key", ec.EllipticCurvePrivateKey, id="ecdsa"),
    pytest.param("ed25519-psw.key", ed25519.Ed25519PrivateKey, id="ed25519"),
]
_CLASSIC_IDENTITY_KEYS = [
    pytest.param("rsa-psw.key", rsa.RSAPrivateKey, id="rsa"),
    _DSA_IDENTITY_KEY,
    pytest.param("ecdsa-psw.key", ec.EllipticCurvePrivateKey, id="ecdsa"),
]
_PKCS8_LOADERS = [
    pytest.param(
        Encoding.PEM, load_pem_private_key, load_der_private_key, id="pem"
    ),
    pytest.param(
        Encoding.DER, load_der_private_key, load_pem_private_key, id="der"
    ),
]
_INVALID_SERIALIZATION_COMBINATIONS = [
    pytest.param(
        Encoding.DER,
        PrivateFormat.OpenSSH,
        NoEncryption(),
        ValueError,
        id="openssh-der",
    ),
    pytest.param(
        Encoding.PEM,
        PrivateFormat.PKCS12,
        BestAvailableEncryption(_PASSWORD),
        ValueError,
        id="pkcs12-enum-on-private-bytes",
    ),
    pytest.param(
        Encoding.DER,
        PrivateFormat.TraditionalOpenSSL,
        BestAvailableEncryption(_PASSWORD),
        ValueError,
        id="traditional-der-encrypted",
    ),
    pytest.param(
        Encoding.Raw,
        PrivateFormat.Raw,
        BestAvailableEncryption(_PASSWORD),
        ValueError,
        id="raw-encrypted",
    ),
]


def _vector_bytes(filename: str) -> bytes:
    return load_vectors_from_file(
        os.path.join("asymmetric", "OpenSSH", filename),
        lambda f: f.read(),
        mode="rb",
    )


@functools.cache
def _load_identity(filename: str) -> tuple[bytes, Any, bytes]:
    original = _vector_bytes(filename)
    public_identity = b" ".join(_vector_bytes(filename + ".pub").split()[:2])

    if filename.startswith("dsa-"):
        with pytest.warns(utils.CryptographyDeprecationWarning):
            key = load_ssh_private_key(original, _PASSWORD)
    else:
        key = load_ssh_private_key(original, _PASSWORD)

    return original, key, public_identity


def _spki(key: Any) -> bytes:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", utils.CryptographyDeprecationWarning)
        return key.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )


def _ssh_public_identity(key: Any) -> bytes:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", utils.CryptographyDeprecationWarning)
        return key.public_key().public_bytes(
            Encoding.OpenSSH, PublicFormat.OpenSSH
        )


def _assert_failure_without_result(
    expected_error: ExpectedError, operation: Callable[[], Any]
) -> None:
    sentinel = object()
    result = sentinel
    with pytest.raises(expected_error):
        result = operation()
    assert result is sentinel


def _assert_password_failures(
    loader: Loader,
    data: bytes,
    wrong_password_error: ExpectedError,
    *,
    missing_password_error: ExpectedError = TypeError,
) -> None:
    for missing_password in (None, b""):
        _assert_failure_without_result(
            missing_password_error,
            functools.partial(loader, data, missing_password),
        )

    _assert_failure_without_result(
        wrong_password_error,
        functools.partial(loader, data, _WRONG_PASSWORD),
    )


def _assert_same_identity(
    loaded_key: Any,
    expected_spki: bytes,
    expected_ssh_identity: bytes | None = None,
) -> None:
    assert _spki(loaded_key) == expected_spki
    if expected_ssh_identity is not None:
        assert _ssh_public_identity(loaded_key) == expected_ssh_identity


@pytest.mark.parametrize(("key_file", "key_type"), _IDENTITY_KEYS)
def test_legacy_ssh_identity_still_loads_in_original_format(
    key_file: str, key_type: type[Any]
) -> None:
    original, key, ssh_identity = _load_identity(key_file)
    expected_spki = _spki(key)

    assert isinstance(key, key_type)
    assert _ssh_public_identity(key) == ssh_identity

    _assert_password_failures(
        load_ssh_private_key,
        original,
        (ValueError, InvalidTag),
    )

    reloaded = load_ssh_private_key(original, _PASSWORD)
    _assert_same_identity(reloaded, expected_spki, ssh_identity)


@pytest.mark.parametrize(("key_file", "key_type"), _IDENTITY_KEYS)
@pytest.mark.parametrize(
    ("encoding", "loader", "mismatched_loader"), _PKCS8_LOADERS
)
def test_encrypted_identity_migrates_to_pkcs8(
    key_file: str,
    key_type: type[Any],
    encoding: Encoding,
    loader: Loader,
    mismatched_loader: Loader,
) -> None:
    _, source_key, ssh_identity = _load_identity(key_file)
    assert isinstance(source_key, key_type)
    expected_spki = _spki(source_key)

    migrated = source_key.private_bytes(
        encoding,
        PrivateFormat.PKCS8,
        BestAvailableEncryption(_PASSWORD),
    )
    assert migrated

    if encoding is Encoding.PEM:
        assert b"-----BEGIN ENCRYPTED PRIVATE KEY-----" in migrated

    _assert_password_failures(loader, migrated, ValueError)

    loaded_key = loader(migrated, _PASSWORD)
    _assert_same_identity(loaded_key, expected_spki, ssh_identity)

    _assert_failure_without_result(
        ValueError,
        lambda: mismatched_loader(migrated, _PASSWORD),
    )


@pytest.mark.parametrize(("key_file", "key_type"), _IDENTITY_KEYS)
@pytest.mark.parametrize(
    ("encoding", "loader", "_mismatched_loader"), _PKCS8_LOADERS
)
def test_unencrypted_pkcs8_migration_has_no_password_requirement(
    key_file: str,
    key_type: type[Any],
    encoding: Encoding,
    loader: Loader,
    _mismatched_loader: Loader,
) -> None:
    _, source_key, ssh_identity = _load_identity(key_file)
    assert isinstance(source_key, key_type)
    expected_spki = _spki(source_key)

    migrated = source_key.private_bytes(
        encoding, PrivateFormat.PKCS8, NoEncryption()
    )
    loaded_key = loader(migrated, None)
    _assert_same_identity(loaded_key, expected_spki, ssh_identity)

    _assert_failure_without_result(
        TypeError, lambda: loader(migrated, _PASSWORD)
    )


@pytest.mark.skip_fips(
    reason="Traditional OpenSSL encryption is unsupported in FIPS mode."
)
@pytest.mark.parametrize(("key_file", "key_type"), _CLASSIC_IDENTITY_KEYS)
def test_encrypted_identity_migrates_to_traditional_pem(
    key_file: str, key_type: type[Any]
) -> None:
    _, source_key, ssh_identity = _load_identity(key_file)
    assert isinstance(source_key, key_type)
    expected_spki = _spki(source_key)

    migrated = source_key.private_bytes(
        Encoding.PEM,
        PrivateFormat.TraditionalOpenSSL,
        BestAvailableEncryption(_PASSWORD),
    )
    assert b"PRIVATE KEY-----" in migrated
    assert b"ENCRYPTED PRIVATE KEY" not in migrated
    assert b"Proc-Type: 4,ENCRYPTED" in migrated
    assert b"DEK-Info:" in migrated

    _assert_password_failures(load_pem_private_key, migrated, ValueError)

    loaded_key = load_pem_private_key(migrated, _PASSWORD)
    _assert_same_identity(loaded_key, expected_spki, ssh_identity)


@pytest.mark.parametrize(("key_file", "key_type"), _IDENTITY_KEYS)
def test_encrypted_identity_migrates_to_openssh_format(
    key_file: str, key_type: type[Any]
) -> None:
    _, source_key, ssh_identity = _load_identity(key_file)
    assert isinstance(source_key, key_type)
    expected_spki = _spki(source_key)
    encryption = (
        PrivateFormat.OpenSSH.encryption_builder()
        .kdf_rounds(1)
        .build(_PASSWORD)
    )

    migrated = source_key.private_bytes(
        Encoding.PEM, PrivateFormat.OpenSSH, encryption
    )
    assert b"-----BEGIN OPENSSH PRIVATE KEY-----" in migrated

    _assert_password_failures(
        load_ssh_private_key,
        migrated,
        (ValueError, InvalidTag),
    )

    loaded_key = load_ssh_private_key(migrated, _PASSWORD)
    _assert_same_identity(loaded_key, expected_spki, ssh_identity)

    # The generic PEM loader understands PKCS#8/traditional PEM tags, not the
    # OpenSSH container.
    _assert_failure_without_result(
        ValueError,
        lambda: load_pem_private_key(migrated, _PASSWORD),
    )


def test_openssh_aesgcm_wrong_password_fails_authentication() -> None:
    original = _vector_bytes("ed25519-aesgcm-psw.key")
    key = load_ssh_private_key(original, _PASSWORD)
    expected_spki = _spki(key)

    _assert_failure_without_result(
        InvalidTag,
        lambda: load_ssh_private_key(original, _WRONG_PASSWORD),
    )
    _assert_failure_without_result(
        TypeError,
        lambda: load_ssh_private_key(original, None),
    )

    loaded_key = load_ssh_private_key(original, _PASSWORD)
    _assert_same_identity(loaded_key, expected_spki)


@pytest.mark.skip_fips(reason="PKCS12 is unsupported in FIPS mode.")
@pytest.mark.parametrize(("key_file", "key_type"), _IDENTITY_KEYS)
def test_encrypted_identity_migrates_to_pkcs12(
    key_file: str, key_type: type[Any]
) -> None:
    _, source_key, ssh_identity = _load_identity(key_file)
    assert isinstance(source_key, key_type)
    expected_spki = _spki(source_key)

    p12 = serialize_key_and_certificates(
        b"identity",
        source_key,
        None,
        None,
        BestAvailableEncryption(_PASSWORD),
    )

    _assert_password_failures(
        lambda data, password: load_pkcs12(data, password),
        p12,
        ValueError,
        missing_password_error=ValueError,
    )

    identity = load_pkcs12(p12, _PASSWORD)
    assert identity.key is not None
    _assert_same_identity(identity.key, expected_spki, ssh_identity)


@pytest.mark.parametrize(("key_file", "key_type"), _IDENTITY_KEYS)
@pytest.mark.parametrize(
    ("encoding", "private_format", "encryption", "expected_error"),
    _INVALID_SERIALIZATION_COMBINATIONS,
)
def test_unsupported_format_combinations_do_not_yield_key_material(
    key_file: str,
    key_type: type[Any],
    encoding: Encoding,
    private_format: PrivateFormat,
    encryption: Any,
    expected_error: ExpectedError,
) -> None:
    _, source_key, _ = _load_identity(key_file)
    assert isinstance(source_key, key_type)
    expected_spki = _spki(source_key)

    _assert_failure_without_result(
        expected_error,
        lambda: source_key.private_bytes(encoding, private_format, encryption),
    )

    # A rejected migration must not invalidate or partially replace the
    # loaded source key.
    assert _spki(source_key) == expected_spki


def test_traditional_format_rejects_ed25519_identity() -> None:
    _, source_key, _ = _load_identity("ed25519-psw.key")

    with pytest.raises(ValueError, match="format is invalid with this key"):
        source_key.private_bytes(
            Encoding.PEM,
            PrivateFormat.TraditionalOpenSSL,
            BestAvailableEncryption(_PASSWORD),
        )
