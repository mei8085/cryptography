# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import base64
from urllib.parse import parse_qs, urlparse

import pytest

from cryptography.hazmat.primitives.hashes import SHA1, SHA256, SHA512
from cryptography.hazmat.primitives.twofactor import InvalidToken
from cryptography.hazmat.primitives.twofactor.hotp import HOTP

# Key from RFC 4226 Appendix D, together with its ten published 6-digit
# HOTP values (counters 0 through 9).
_RFC4226_KEY = b"12345678901234567890"
_RFC4226_CODES = (
    b"755224",
    b"287082",
    b"359152",
    b"969429",
    b"338314",
    b"254676",
    b"287922",
    b"162583",
    b"399871",
    b"520489",
)

# A distinct 160-bit key standing in for the replacement token issued
# during key rotation.  The values are pinned so accidental key/counter
# sharing between token instances cannot pass silently.
_ROTATION_KEY = b"0123456789abcdef0123"
_ROTATION_CODES = (
    b"907221",
    b"540349",
    b"811456",
    b"376251",
    b"436587",
    b"869778",
    b"976807",
    b"142194",
    b"070783",
    b"350078",
)

# A third key used when the rotating slot itself gets replaced.
_REPLACEMENT_KEY = b"fedcba9876543210fedc"

# RFC 6238 uses these longer secrets for its SHA-256/SHA-512 vectors.
_RFC6238_SHA256_KEY = b"12345678901234567890123456789012"
_RFC6238_SHA512_KEY = (
    b"1234567890123456789012345678901234567890123456789012345678901234"
)


def _accepts(token: HOTP, code: bytes, counter: int) -> bool:
    try:
        token.verify(code, counter)
    except InvalidToken:
        return False
    return True


def _uri_query(uri: str) -> dict[str, str]:
    return {
        key: values[0] for key, values in parse_qs(urlparse(uri).query).items()
    }


class _CallerCounterSlot:
    """Model of the persistent counter an application must maintain.

    This is test-only code representing the *caller's* responsibility.
    The ``HOTP`` primitive in this library is stateless -- the counter is
    supplied on every call and a successful verification consumes nothing.
    One-time authentication, bounded desynchronization recovery and replay
    rejection require caller-owned state such as this look-ahead slot.
    """

    def __init__(self, token: HOTP, next_counter: int, window: int) -> None:
        self.token = token
        self.next_counter = next_counter
        self.window = window

    def submit(self, code: bytes) -> int:
        """Return the matched counter, advancing only on success.

        The scan starts at ``next_counter`` so counters below it are
        replays and can never match.  A failed scan leaves the stored
        counter untouched.
        """
        for counter in range(
            self.next_counter, self.next_counter + self.window
        ):
            if _accepts(self.token, code, counter):
                self.next_counter = counter + 1
                return counter

        raise InvalidToken(
            "Supplied HOTP value is outside the acceptance window."
        )


class TestKeyCounterOwnership:
    """Generation, verification and URI config must agree on ownership."""

    def test_two_coexisting_keys_give_different_pinned_codes(self):
        old_token = HOTP(_RFC4226_KEY, 6, SHA1())
        new_token = HOTP(_ROTATION_KEY, 6, SHA1())

        # Same identity, same counter, different keys -> different codes.
        assert old_token.generate(0) == b"755224"
        assert new_token.generate(0) == b"907221"

        for counter, code in enumerate(_RFC4226_CODES):
            assert old_token.generate(counter) == code
        for counter, code in enumerate(_ROTATION_CODES):
            assert new_token.generate(counter) == code

    @pytest.mark.parametrize("counter", range(len(_RFC4226_CODES)))
    def test_code_verifies_only_under_its_own_key(self, counter):
        old_token = HOTP(_RFC4226_KEY, 6, SHA1())
        new_token = HOTP(_ROTATION_KEY, 6, SHA1())

        old_token.verify(_RFC4226_CODES[counter], counter)
        new_token.verify(_ROTATION_CODES[counter], counter)

        with pytest.raises(InvalidToken):
            new_token.verify(_RFC4226_CODES[counter], counter)
        with pytest.raises(InvalidToken):
            old_token.verify(_ROTATION_CODES[counter], counter)

    @pytest.mark.parametrize(
        ("key", "table"),
        [
            (_RFC4226_KEY, _RFC4226_CODES),
            (_ROTATION_KEY, _ROTATION_CODES),
        ],
    )
    def test_each_pinned_code_matches_exactly_its_own_counter(
        self, key, table
    ):
        token = HOTP(key, 6, SHA1())

        for counter, code in enumerate(table):
            matching_counters = [
                candidate
                for candidate in range(len(table))
                if _accepts(token, code, candidate)
            ]
            assert matching_counters == [counter]

    def test_provisioning_uri_names_its_own_key_and_counter(self):
        old_token = HOTP(_RFC4226_KEY, 6, SHA1())
        new_token = HOTP(_ROTATION_KEY, 6, SHA1())

        old_uri = old_token.get_provisioning_uri("alice", 3, "Example")
        new_uri = new_token.get_provisioning_uri("alice", 7, "Example")

        # Same identity label ...
        assert urlparse(old_uri).path == urlparse(new_uri).path

        # ... but each configuration carries its own secret and counter.
        old_query = _uri_query(old_uri)
        new_query = _uri_query(new_uri)

        assert base64.b32decode(old_query["secret"]) == _RFC4226_KEY
        assert base64.b32decode(new_query["secret"]) == _ROTATION_KEY
        assert old_query["counter"] == "3"
        assert new_query["counter"] == "7"
        assert old_query["secret"] != new_query["secret"]

    @pytest.mark.parametrize(
        ("key", "length", "algorithm", "algorithm_name", "counter"),
        [
            (_RFC4226_KEY, 6, SHA1(), "SHA1", 0),
            (_RFC4226_KEY, 8, SHA1(), "SHA1", 1),
            (_RFC6238_SHA256_KEY, 8, SHA256(), "SHA256", 1),
            (_RFC6238_SHA512_KEY, 8, SHA512(), "SHA512", 1),
            (_ROTATION_KEY, 6, SHA1(), "SHA1", 4),
        ],
    )
    def test_token_rebuilt_from_uri_generates_same_bytes(
        self, key, length, algorithm, algorithm_name, counter
    ):
        token = HOTP(key, length, algorithm)
        uri = token.get_provisioning_uri("alice", counter, "Example")
        query = _uri_query(uri)

        assert query["algorithm"] == algorithm_name
        assert int(query["digits"]) == length
        assert int(query["counter"]) == counter

        rebuilt = HOTP(
            base64.b32decode(query["secret"]),
            int(query["digits"]),
            algorithm,
        )
        expected = token.generate(counter)
        assert rebuilt.generate(counter) == expected
        rebuilt.verify(expected, counter)


class TestTokenReplacementIsolation:
    """Rotating/replacing one token must not perturb a coexisting token."""

    def test_replacing_one_token_keeps_other_codes_and_uri_fixed(self):
        kept_token = HOTP(_RFC4226_KEY, 6, SHA1())
        rotating_token = HOTP(_ROTATION_KEY, 6, SHA1())

        kept_codes_before = [kept_token.generate(c) for c in range(20)]
        kept_uri_before = kept_token.get_provisioning_uri(
            "alice", 7, "Example"
        )

        # Both tokens are valid before rotation ...
        assert rotating_token.generate(0) == b"907221"
        rotating_token.verify(b"540349", 1)

        # ... then the rotating token is retired and replaced, and the
        # replacement is exercised including failed attempts.
        replacement = HOTP(_REPLACEMENT_KEY, 8, SHA256())
        for counter in range(20):
            code = replacement.generate(counter)
            replacement.verify(code, counter)
        for counter in range(5):
            with pytest.raises(InvalidToken):
                replacement.verify(b"000000", counter)

        # The still-valid token's outputs and configuration representation
        # are byte-for-byte unchanged.
        assert [kept_token.generate(c) for c in range(20)] == (
            kept_codes_before
        )
        assert (
            kept_token.get_provisioning_uri("alice", 7, "Example")
            == kept_uri_before
        )
        for counter, code in enumerate(_RFC4226_CODES):
            kept_token.verify(code, counter)

    def test_independent_instances_do_not_share_counter_state(self):
        first = HOTP(_RFC4226_KEY, 6, SHA1())
        second = HOTP(_RFC4226_KEY, 6, SHA1())

        # Heavy, successful use of one instance cannot advance the other.
        for counter in range(10):
            first.verify(first.generate(counter), counter)

        assert second.generate(0) == b"755224"
        second.verify(b"755224", 0)


class TestStatelessVerifyVsCallerOneTimeResponsibility:
    def test_failed_verify_does_not_consume_any_counter(self):
        token = HOTP(_RFC4226_KEY, 6, SHA1())
        codes_before = [token.generate(c) for c in range(5)]

        for _ in range(3):
            with pytest.raises(InvalidToken):
                token.verify(b"000000", 0)
            # Right code, wrong counter is still a failed attempt.
            with pytest.raises(InvalidToken):
                token.verify(_RFC4226_CODES[0], 1)
            # Malformed length is likewise just a failed attempt.
            with pytest.raises(InvalidToken):
                token.verify(b"short", 0)

        # The exact same code at the exact same counter still verifies.
        token.verify(b"755224", 0)
        assert [token.generate(c) for c in range(5)] == codes_before

    def test_library_verify_is_stateless_and_allows_replay(self):
        token = HOTP(_RFC4226_KEY, 6, SHA1())

        # The primitive gives no one-time guarantee: repeating the same
        # valid (code, counter) pair succeeds indefinitely.
        for _ in range(3):
            token.verify(b"755224", 0)

        assert token.generate(0) == b"755224"

    def test_failed_submission_does_not_advance_caller_counter(self):
        slot = _CallerCounterSlot(
            HOTP(_RFC4226_KEY, 6, SHA1()), next_counter=0, window=10
        )

        for bad_code in (b"000000", b"bad", _ROTATION_CODES[0]):
            with pytest.raises(InvalidToken):
                slot.submit(bad_code)
            assert slot.next_counter == 0

        assert slot.submit(b"755224") == 0
        assert slot.next_counter == 1

    def test_desync_recovery_advances_only_the_matched_counter(self):
        slot = _CallerCounterSlot(
            HOTP(_RFC4226_KEY, 6, SHA1()), next_counter=0, window=4
        )

        # Client presents the counter-3 code while the caller expected 0,
        # still within the bounded window.
        assert slot.submit(b"969429") == 3
        assert slot.next_counter == 4

        # Recovery does not alter the primitive's future byte output.
        assert slot.token.generate(4) == b"338314"

        # The recovered code is now spent at the caller ...
        with pytest.raises(InvalidToken):
            slot.submit(b"969429")
        assert slot.next_counter == 4

        # ... while the following counter continues normally.
        assert slot.submit(b"338314") == 4
        assert slot.next_counter == 5

    def test_recovery_on_one_token_leaves_the_other_untouched(self):
        old_slot = _CallerCounterSlot(
            HOTP(_RFC4226_KEY, 6, SHA1()), next_counter=0, window=10
        )
        new_slot = _CallerCounterSlot(
            HOTP(_ROTATION_KEY, 6, SHA1()), next_counter=0, window=10
        )

        # The new token recovers from a 3-counter desynchronization.
        assert new_slot.submit(_ROTATION_CODES[3]) == 3
        assert new_slot.next_counter == 4

        # The old, still-valid token keeps its own counter attribution and
        # authenticates its current code exactly as before.
        assert old_slot.next_counter == 0
        assert old_slot.submit(_RFC4226_CODES[0]) == 0
        assert old_slot.next_counter == 1

        # The new token's primitive results are independent of the
        # caller's advanced counter bookkeeping.
        assert new_slot.token.generate(4) == _ROTATION_CODES[4]

    def test_replacing_key_in_one_slot_keeps_other_slot_state(self):
        stable_slot = _CallerCounterSlot(
            HOTP(_RFC4226_KEY, 6, SHA1()), next_counter=2, window=10
        )
        rotating_slot = _CallerCounterSlot(
            HOTP(_ROTATION_KEY, 6, SHA1()), next_counter=0, window=10
        )

        # Rotate the key behind the rotating slot and recover with a code
        # that is only valid under the replacement key.
        replacement = HOTP(_REPLACEMENT_KEY, 6, SHA1())
        rotating_slot.token = replacement
        replacement_code = replacement.generate(5)

        assert rotating_slot.submit(replacement_code) == 5
        assert rotating_slot.next_counter == 6

        # The stable slot's key and counter ownership are unchanged.
        assert stable_slot.next_counter == 2
        assert stable_slot.token.generate(2) == b"359152"
        assert stable_slot.submit(b"359152") == 2
        assert stable_slot.next_counter == 3

    def test_caller_rejects_replay_even_though_library_accepts_it(self):
        token = HOTP(_RFC4226_KEY, 6, SHA1())
        slot = _CallerCounterSlot(token, next_counter=0, window=10)

        assert slot.submit(b"755224") == 0
        assert slot.next_counter == 1

        # The caller's one-time state refuses the exact same bytes ...
        with pytest.raises(InvalidToken):
            slot.submit(b"755224")
        assert slot.next_counter == 1

        # ... even though the stateless library still validates the pair.
        token.verify(b"755224", 0)

        # The next counter's code authenticates once and then no more.
        assert slot.submit(b"287082") == 1
        with pytest.raises(InvalidToken):
            slot.submit(b"287082")

    def test_limited_window_rejects_far_desync_without_consuming(self):
        slot = _CallerCounterSlot(
            HOTP(_RFC4226_KEY, 6, SHA1()), next_counter=0, window=5
        )

        # Counter 9 lies outside the 0..4 acceptance window.
        with pytest.raises(InvalidToken):
            slot.submit(b"520489")
        assert slot.next_counter == 0

        # Counter 4 is at the edge of the window and recovers normally.
        assert slot.submit(b"338314") == 4
        assert slot.next_counter == 5

        # The matched code cannot be replayed; counter 5 is next.
        with pytest.raises(InvalidToken):
            slot.submit(b"338314")
        assert slot.submit(b"254676") == 5
        assert slot.next_counter == 6


class TestStandardAlgorithmByteVectors:
    """Legal algorithm vectors must retain their original byte results."""

    def test_rfc4226_appendix_d_full_table_as_exact_ascii_bytes(self):
        token = HOTP(_RFC4226_KEY, 6, SHA1())

        expected = [
            b"755224",
            b"287082",
            b"359152",
            b"969429",
            b"338314",
            b"254676",
            b"287922",
            b"162583",
            b"399871",
            b"520489",
        ]

        assert [token.generate(counter) for counter in range(10)] == expected

    @pytest.mark.parametrize(
        ("key", "algorithm", "counter", "expected"),
        [
            # RFC 6238 Appendix B at T=59 (HOTP counter T/30 = 1).
            (_RFC4226_KEY, SHA1(), 1, b"94287082"),
            (_RFC6238_SHA256_KEY, SHA256(), 1, b"46119246"),
            (_RFC6238_SHA512_KEY, SHA512(), 1, b"90693936"),
            # RFC 6238 Appendix B at T=1111111109 (counter 37037036).
            (_RFC4226_KEY, SHA1(), 37037036, b"07081804"),
            (_RFC6238_SHA256_KEY, SHA256(), 37037036, b"68084774"),
            (_RFC6238_SHA512_KEY, SHA512(), 37037036, b"25091201"),
            # RFC 6238 Appendix B at T=1234567890 (counter 41152263).
            (_RFC4226_KEY, SHA1(), 41152263, b"89005924"),
            (_RFC6238_SHA256_KEY, SHA256(), 41152263, b"91819424"),
            (_RFC6238_SHA512_KEY, SHA512(), 41152263, b"93441116"),
        ],
    )
    def test_rfc6238_vectors_as_hotp_counter_values(
        self, key, algorithm, counter, expected
    ):
        # TOTP is HOTP(key, floor(time / period)); these are the exact
        # published 8-digit byte strings for the corresponding counters.
        token = HOTP(key, 8, algorithm)
        assert token.generate(counter) == expected
        token.verify(expected, counter)
