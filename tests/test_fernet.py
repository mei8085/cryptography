# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import base64
import datetime
import json
import os
import time
import typing

import pretend
import pytest

import cryptography_vectors
from cryptography.fernet import Fernet, InvalidToken, MultiFernet

# A Fernet token stamped at ``issued_at`` is accepted at ``now`` when
# ``issued_at - _MAX_CLOCK_SKEW <= now <= issued_at + ttl``. Both ends of
# the window are inclusive; the rotation tests below pin this contract down.
_MAX_CLOCK_SKEW = 60
_TTL = 100


def json_parametrize(keys, filename):
    vector_file = cryptography_vectors.open_vector_file(
        os.path.join("fernet", filename), "r"
    )
    with vector_file:
        data = json.load(vector_file)
        return pytest.mark.parametrize(
            keys,
            [tuple([entry[k] for k in keys]) for entry in data],
            ids=[f"{filename}[{i}]" for i in range(len(data))],
        )


class TestFernet:
    @json_parametrize(
        ("secret", "now", "iv", "src", "token"),
        "generate.json",
    )
    def test_generate(self, secret, now, iv, src, token):
        # secret is a str here and bytes in test_verify.
        f = Fernet(secret)
        actual_token = f._encrypt_from_parts(
            src.encode("ascii"),
            int(datetime.datetime.fromisoformat(now).timestamp()),
            bytes(iv),
        )
        assert actual_token == token.encode("ascii")

    @json_parametrize(
        ("secret", "now", "src", "ttl_sec", "token"),
        "verify.json",
    )
    def test_verify(self, secret, now, src, ttl_sec, token, monkeypatch):
        # secret & token are both str
        f = Fernet(secret.encode("ascii"))
        current_time = int(datetime.datetime.fromisoformat(now).timestamp())
        payload = f.decrypt_at_time(
            token,  # str
            ttl=ttl_sec,
            current_time=current_time,
        )
        assert payload == src.encode("ascii")

        payload = f.decrypt_at_time(
            token.encode("ascii"),  # bytes
            ttl=ttl_sec,
            current_time=current_time,
        )
        assert payload == src.encode("ascii")

        monkeypatch.setattr(time, "time", lambda: current_time)

        payload = f.decrypt(token, ttl=ttl_sec)  # str
        assert payload == src.encode("ascii")

        payload = f.decrypt(token.encode("ascii"), ttl=ttl_sec)  # bytes
        assert payload == src.encode("ascii")

    @json_parametrize(("secret", "token", "now", "ttl_sec"), "invalid.json")
    def test_invalid(self, secret, token, now, ttl_sec, monkeypatch):
        f = Fernet(secret.encode("ascii"))
        current_time = int(datetime.datetime.fromisoformat(now).timestamp())
        with pytest.raises(InvalidToken):
            f.decrypt_at_time(
                token.encode("ascii"),
                ttl=ttl_sec,
                current_time=current_time,
            )
        monkeypatch.setattr(time, "time", lambda: current_time)
        with pytest.raises(InvalidToken):
            f.decrypt(token.encode("ascii"), ttl=ttl_sec)

    def test_invalid_start_byte(self):
        f = Fernet(base64.urlsafe_b64encode(b"\x00" * 32))
        with pytest.raises(InvalidToken):
            f.decrypt(base64.urlsafe_b64encode(b"\x81"))

    def test_timestamp_too_short(self):
        f = Fernet(base64.urlsafe_b64encode(b"\x00" * 32))
        with pytest.raises(InvalidToken):
            f.decrypt(base64.urlsafe_b64encode(b"\x80abc"))

    def test_non_base64_token(self):
        f = Fernet(base64.urlsafe_b64encode(b"\x00" * 32))
        with pytest.raises(InvalidToken):
            f.decrypt(b"\x00")
        with pytest.raises(InvalidToken):
            f.decrypt("nonsensetoken")

    def test_invalid_types(self):
        f = Fernet(base64.urlsafe_b64encode(b"\x00" * 32))
        with pytest.raises(TypeError):
            f.encrypt(typing.cast(typing.Any, ""))
        with pytest.raises(TypeError):
            f.decrypt(typing.cast(typing.Any, 12345))

    def test_timestamp_ignored_no_ttl(self, monkeypatch):
        f = Fernet(base64.urlsafe_b64encode(b"\x00" * 32))
        pt = b"encrypt me"
        token = f.encrypt(pt)
        monkeypatch.setattr(time, "time", pretend.raiser(ValueError))
        assert f.decrypt(token, ttl=None) == pt

    def test_ttl_required_in_decrypt_at_time(self):
        f = Fernet(base64.urlsafe_b64encode(b"\x00" * 32))
        pt = b"encrypt me"
        token = f.encrypt(pt)
        with pytest.raises(ValueError):
            f.decrypt_at_time(
                token,
                ttl=typing.cast(typing.Any, None),
                current_time=int(time.time()),
            )

    @pytest.mark.parametrize("message", [b"", b"Abc!", b"\x00\xff\x00\x80"])
    def test_roundtrips(self, message):
        f = Fernet(Fernet.generate_key())
        assert f.decrypt(f.encrypt(message)) == message

    @pytest.mark.parametrize("key", [base64.urlsafe_b64encode(b"abc"), b"abc"])
    def test_bad_key(self, key):
        with pytest.raises(ValueError):
            Fernet(key)

    def test_extract_timestamp(self):
        f = Fernet(base64.urlsafe_b64encode(b"\x00" * 32))
        current_time = 1526138327
        token = f.encrypt_at_time(b"encrypt me", current_time)
        assert f.extract_timestamp(token) == current_time
        assert f.extract_timestamp(token.decode("ascii")) == current_time
        with pytest.raises(InvalidToken):
            f.extract_timestamp(b"nonsensetoken")


class TestMultiFernet:
    def test_encrypt(self):
        f1 = Fernet(base64.urlsafe_b64encode(b"\x00" * 32))
        f2 = Fernet(base64.urlsafe_b64encode(b"\x01" * 32))
        f = MultiFernet([f1, f2])

        assert f1.decrypt(f.encrypt(b"abc")) == b"abc"

    def test_decrypt(self):
        f1 = Fernet(base64.urlsafe_b64encode(b"\x00" * 32))
        f2 = Fernet(base64.urlsafe_b64encode(b"\x01" * 32))
        f = MultiFernet([f1, f2])

        # token as bytes
        assert f.decrypt(f1.encrypt(b"abc")) == b"abc"
        assert f.decrypt(f2.encrypt(b"abc")) == b"abc"

        # token as str
        assert f.decrypt(f1.encrypt(b"abc").decode("ascii")) == b"abc"
        assert f.decrypt(f2.encrypt(b"abc").decode("ascii")) == b"abc"

        with pytest.raises(InvalidToken):
            f.decrypt(b"\x00" * 16)

    def test_decrypt_ttl(self, monkeypatch):
        f1 = Fernet(base64.urlsafe_b64encode(b"\x00" * 32))
        f = MultiFernet([f1])
        current_time = 1526138327
        token = f.encrypt_at_time(b"encrypt me", current_time)

        monkeypatch.setattr(time, "time", lambda: current_time)
        assert f.decrypt(token, ttl=1) == b"encrypt me"

        monkeypatch.setattr(time, "time", lambda: current_time + 2)
        with pytest.raises(InvalidToken):
            f.decrypt(token, ttl=1)

    def test_decrypt_at_time(self):
        f1 = Fernet(base64.urlsafe_b64encode(b"\x00" * 32))
        f = MultiFernet([f1])
        pt = b"encrypt me"
        token = f.encrypt_at_time(pt, current_time=100)
        assert f.decrypt_at_time(token, ttl=1, current_time=100) == pt
        with pytest.raises(InvalidToken):
            f.decrypt_at_time(token, ttl=1, current_time=102)
        with pytest.raises(ValueError):
            f.decrypt_at_time(
                token,
                ttl=typing.cast(typing.Any, None),
                current_time=100,
            )

    def test_no_fernets(self):
        with pytest.raises(ValueError):
            MultiFernet([])

    def test_non_iterable_argument(self):
        with pytest.raises(TypeError):
            MultiFernet(typing.cast(typing.Any, None))

    def test_rotate_bytes(self):
        f1 = Fernet(base64.urlsafe_b64encode(b"\x00" * 32))
        f2 = Fernet(base64.urlsafe_b64encode(b"\x01" * 32))

        mf1 = MultiFernet([f1])
        mf2 = MultiFernet([f2, f1])

        plaintext = b"abc"
        mf1_ciphertext = mf1.encrypt(plaintext)

        assert mf2.decrypt(mf1_ciphertext) == plaintext

        rotated = mf2.rotate(mf1_ciphertext)

        assert rotated != mf1_ciphertext
        assert mf2.decrypt(rotated) == plaintext

        with pytest.raises(InvalidToken):
            mf1.decrypt(rotated)

    def test_rotate_str(self):
        f1 = Fernet(base64.urlsafe_b64encode(b"\x00" * 32))
        f2 = Fernet(base64.urlsafe_b64encode(b"\x01" * 32))

        mf1 = MultiFernet([f1])
        mf2 = MultiFernet([f2, f1])

        plaintext = b"abc"
        mf1_ciphertext = mf1.encrypt(plaintext).decode("ascii")

        assert mf2.decrypt(mf1_ciphertext) == plaintext
        rotated = mf2.rotate(mf1_ciphertext).decode("ascii")

        assert rotated != mf1_ciphertext
        assert mf2.decrypt(rotated) == plaintext

        with pytest.raises(InvalidToken):
            mf1.decrypt(rotated)

    def test_rotate_preserves_timestamp(self):
        f1 = Fernet(base64.urlsafe_b64encode(b"\x00" * 32))
        f2 = Fernet(base64.urlsafe_b64encode(b"\x01" * 32))

        mf1 = MultiFernet([f1])
        mf2 = MultiFernet([f2, f1])

        plaintext = b"abc"
        original_time = int(time.time()) - 5 * 60
        mf1_ciphertext = mf1.encrypt_at_time(plaintext, original_time)

        rotated_time, _ = Fernet._get_unverified_token_data(
            mf2.rotate(mf1_ciphertext)
        )

        assert int(time.time()) != rotated_time
        assert original_time == rotated_time

    def test_rotate_decrypt_no_shared_keys(self):
        f1 = Fernet(base64.urlsafe_b64encode(b"\x00" * 32))
        f2 = Fernet(base64.urlsafe_b64encode(b"\x01" * 32))

        mf1 = MultiFernet([f1])
        mf2 = MultiFernet([f2])

        with pytest.raises(InvalidToken):
            mf2.rotate(mf1.encrypt(b"abc"))

    def test_extract_timestamp_first_fernet_valid_token(self):
        f1 = Fernet(base64.urlsafe_b64encode(b"\x00" * 32))
        mf1 = MultiFernet([f1])
        current_time = 1526138327
        token = mf1.encrypt_at_time(b"encrypt me", current_time)
        assert mf1.extract_timestamp(token) == current_time

    def test_extract_timestamp_second_fernet_valid_token(self):
        f1 = Fernet(base64.urlsafe_b64encode(b"\x00" * 32))
        f2 = Fernet(base64.urlsafe_b64encode(b"\x01" * 32))
        mf1 = MultiFernet([f1, f2])
        current_time = 1526138327
        token = f2.encrypt_at_time(b"encrypt me", current_time)
        assert mf1.extract_timestamp(token) == current_time

    def test_extract_timestamp_no_valid_signature(self):
        f1 = Fernet(base64.urlsafe_b64encode(b"\x00" * 32))
        f2 = Fernet(base64.urlsafe_b64encode(b"\x01" * 32))
        mf1 = MultiFernet([f1])
        # Well-formed token, but signed by a key not in the MultiFernet.
        with pytest.raises(InvalidToken):
            mf1.extract_timestamp(f2.encrypt(b"encrypt me"))

    def test_extract_timestamp_invalid_token(self):
        f1 = Fernet(base64.urlsafe_b64encode(b"\x00" * 32))
        mf1 = MultiFernet([f1])
        with pytest.raises(InvalidToken):
            mf1.extract_timestamp(b"nonsensetoken")
        with pytest.raises(InvalidToken):
            mf1.extract_timestamp(b"\x80abc")
        with pytest.raises(InvalidToken):
            mf1.extract_timestamp(b"\x00")
        with pytest.raises(InvalidToken):
            mf1.extract_timestamp("nonsensetoken")
        with pytest.raises(InvalidToken):
            mf1.extract_timestamp("abc")
        with pytest.raises(InvalidToken):
            mf1.extract_timestamp("")


def _fernet(seed: int) -> Fernet:
    """A deterministic Fernet instance, distinct per ``seed``."""
    return Fernet(base64.urlsafe_b64encode(bytes([seed]) * 32))


class TestMultiFernetRotationTimeValidity:
    """Key rotation must not re-stamp a token.

    ``MultiFernet.rotate`` re-encrypts an existing token under the primary
    key but keeps its original issuance time, so the rotated token is bound
    to exactly the same TTL/clock-skew window as the token it replaced. It
    gains no new lifetime from being written under a new key. Newly issued
    tokens are always produced (and timestamped) by the primary key.
    """

    issued = 1526138327
    plaintext = b"encrypt me"

    def _rotated(self, issued_at: int) -> tuple[bytes, bytes, Fernet]:
        """Return ``(original, rotated, new_primary)`` for a token."""
        old = _fernet(0)
        new = _fernet(1)
        original = old.encrypt_at_time(self.plaintext, issued_at)
        rotated = MultiFernet([new, old]).rotate(original)
        return original, rotated, new

    @pytest.mark.parametrize("as_str", [False, True])
    def test_rotate_preserves_original_issuance_time(self, as_str):
        old = _fernet(0)
        new = _fernet(1)
        token = old.encrypt_at_time(self.plaintext, self.issued)
        msg = token.decode("ascii") if as_str else token

        rotated = MultiFernet([new, old]).rotate(msg)

        rotated_ts, _ = Fernet._get_unverified_token_data(rotated)
        assert rotated_ts == self.issued
        # The token really moved to the new primary key: the old key alone
        # can no longer read it, the new one can.
        assert MultiFernet([new]).decrypt(rotated) == self.plaintext
        with pytest.raises(InvalidToken):
            old.decrypt(rotated)

    def test_rotate_does_not_extend_validity(self):
        _, rotated, new = self._rotated(self.issued)
        mf = MultiFernet([new])

        # At the TTL boundary the rotated token is still usable.
        assert (
            mf.decrypt_at_time(
                rotated, ttl=_TTL, current_time=self.issued + _TTL
            )
            == self.plaintext
        )
        # One second later it is expired, exactly like the original would
        # have been had its key not been rotated.
        with pytest.raises(InvalidToken):
            mf.decrypt_at_time(
                rotated, ttl=_TTL, current_time=self.issued + _TTL + 1
            )

    @pytest.mark.parametrize(
        ("offset", "valid"),
        [
            (-_MAX_CLOCK_SKEW - 1, False),
            (-_MAX_CLOCK_SKEW, True),
            (-1, True),
            (0, True),
            (_TTL, True),
            (_TTL + 1, False),
        ],
        ids=[
            "too-far-in-future",
            "max-clock-skew",
            "just-before-issuance",
            "at-issuance",
            "at-ttl-boundary",
            "past-ttl",
        ],
    )
    def test_rotated_token_keeps_decryption_contract(self, offset, valid):
        original, rotated, new = self._rotated(self.issued)
        now = self.issued + offset

        # The rotated token is readable from the new primary key alone, and
        # keeps the original token's validity window.
        for mf in (MultiFernet([new]), MultiFernet([new, _fernet(0)])):
            if valid:
                assert (
                    mf.decrypt_at_time(rotated, ttl=_TTL, current_time=now)
                    == self.plaintext
                )
            else:
                with pytest.raises(InvalidToken):
                    mf.decrypt_at_time(rotated, ttl=_TTL, current_time=now)

        # The unrotated token obeys the same window while its key is still in
        # the rotation set.
        rotation_set = MultiFernet([new, _fernet(0)])
        if valid:
            assert (
                rotation_set.decrypt_at_time(
                    original, ttl=_TTL, current_time=now
                )
                == self.plaintext
            )
        else:
            with pytest.raises(InvalidToken):
                rotation_set.decrypt_at_time(
                    original, ttl=_TTL, current_time=now
                )

    @pytest.mark.parametrize(
        ("offset", "valid"),
        [
            (-_MAX_CLOCK_SKEW - 1, False),
            (-_MAX_CLOCK_SKEW, True),
            (0, True),
            (_TTL, True),
            (_TTL + 1, False),
        ],
    )
    def test_wall_clock_agrees_with_explicit_time_after_rotation(
        self, monkeypatch, offset, valid
    ):
        _, rotated, new = self._rotated(self.issued)
        mf = MultiFernet([new])
        now = self.issued + offset
        monkeypatch.setattr(time, "time", lambda: now)

        if valid:
            assert mf.decrypt(rotated, ttl=_TTL) == self.plaintext
        else:
            with pytest.raises(InvalidToken):
                mf.decrypt(rotated, ttl=_TTL)

        # The clock-based and explicit-time paths must agree.
        if valid:
            assert (
                mf.decrypt_at_time(rotated, ttl=_TTL, current_time=now)
                == self.plaintext
            )
        else:
            with pytest.raises(InvalidToken):
                mf.decrypt_at_time(rotated, ttl=_TTL, current_time=now)

    def test_rotate_of_expired_token_stays_expired(self):
        original, rotated, new = self._rotated(self.issued)
        mf = MultiFernet([new, _fernet(0)])
        expired_at = self.issued + _TTL + 1

        # Rotating is decryption-followed-by-encryption, so an expired token
        # can still be rotated (the TTL is not consulted), but rotation is
        # not a re-issuance...
        rotated_ts, _ = Fernet._get_unverified_token_data(rotated)
        assert rotated_ts == self.issued

        # ...so both the original and the rotated token remain expired.
        for token in (original, rotated):
            with pytest.raises(InvalidToken):
                mf.decrypt_at_time(token, ttl=_TTL, current_time=expired_at)
            # Without a TTL the timestamp is never consulted: expiry is the
            # caller's policy, not a property rotation bakes into the token.
            assert mf.decrypt(token) == self.plaintext

    def test_rotate_preserves_future_skew_violation(self):
        old = _fernet(0)
        new = _fernet(1)
        mf = MultiFernet([new, old])
        future = self.issued + 3600
        rotated = mf.rotate(old.encrypt_at_time(self.plaintext, future))

        rotated_ts, _ = Fernet._get_unverified_token_data(rotated)
        assert rotated_ts == future
        # Still too far in the future relative to "now" to be accepted.
        with pytest.raises(InvalidToken):
            mf.decrypt_at_time(rotated, ttl=_TTL, current_time=self.issued)
        # It becomes readable once the clock catches up to the skew window.
        assert (
            mf.decrypt_at_time(
                rotated,
                ttl=_TTL,
                current_time=future - _MAX_CLOCK_SKEW,
            )
            == self.plaintext
        )

    def test_repeated_rotation_never_refreshes_issue_time(self):
        k1, k2, k3 = _fernet(0), _fernet(1), _fernet(2)
        token = k1.encrypt_at_time(self.plaintext, self.issued)
        token = MultiFernet([k2, k1]).rotate(token)
        token = MultiFernet([k3, k2]).rotate(token)

        assert Fernet._get_unverified_token_data(token)[0] == self.issued
        assert (
            MultiFernet([k3]).decrypt_at_time(
                token, ttl=_TTL, current_time=self.issued + _TTL
            )
            == self.plaintext
        )
        with pytest.raises(InvalidToken):
            MultiFernet([k3]).decrypt_at_time(
                token, ttl=_TTL, current_time=self.issued + _TTL + 1
            )

    def test_old_token_readable_only_while_key_is_in_the_set(self):
        old, new = _fernet(0), _fernet(1)
        token = old.encrypt_at_time(self.plaintext, self.issued)
        rotation_set = MultiFernet([new, old])

        # The old token is readable through the rotation set, on its own
        # original schedule (without a TTL the timestamp is not consulted).
        assert rotation_set.decrypt(token) == self.plaintext
        assert rotation_set.extract_timestamp(token) == self.issued
        assert (
            rotation_set.decrypt_at_time(
                token, ttl=_TTL, current_time=self.issued + _TTL
            )
            == self.plaintext
        )
        # Once the old key is retired, the unrotated token is unreadable
        # even though its timestamp is still inside the TTL window.
        retired_set = MultiFernet([new])
        with pytest.raises(InvalidToken):
            retired_set.decrypt_at_time(
                token, ttl=_TTL, current_time=self.issued
            )
        with pytest.raises(InvalidToken):
            retired_set.extract_timestamp(token)

    def test_new_tokens_are_issued_by_primary_key_at_current_time(
        self, monkeypatch
    ):
        old, new = _fernet(0), _fernet(1)
        mf = MultiFernet([new, old])
        now = self.issued
        monkeypatch.setattr(time, "time", lambda: now)

        token = mf.encrypt(self.plaintext)

        assert mf.extract_timestamp(token) == now
        assert MultiFernet([new]).decrypt(token, ttl=_TTL) == self.plaintext
        # The old key is only a reader; it must not have signed the token.
        with pytest.raises(InvalidToken):
            old.decrypt(token)
        with pytest.raises(InvalidToken):
            MultiFernet([old]).decrypt(token, ttl=_TTL)

    def test_rotation_does_not_reissue_new_token_timestamp(self, monkeypatch):
        old, new = _fernet(0), _fernet(1)
        mf = MultiFernet([new, old])

        # Issue through the rotation set at the original time.
        monkeypatch.setattr(time, "time", lambda: self.issued)
        token = mf.encrypt(self.plaintext)

        # Rotate later; the issuance time must stay `self.issued`, not `now`.
        monkeypatch.setattr(time, "time", lambda: self.issued + _TTL // 2)
        rotated = mf.rotate(token)
        assert mf.extract_timestamp(rotated) == self.issued

        # Hence the rotated token expires on the *original* schedule.
        monkeypatch.setattr(time, "time", lambda: self.issued + _TTL + 1)
        with pytest.raises(InvalidToken):
            mf.decrypt(rotated, ttl=_TTL)
        monkeypatch.setattr(time, "time", lambda: self.issued + _TTL)
        assert mf.decrypt(rotated, ttl=_TTL) == self.plaintext
