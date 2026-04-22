"""Tests for shared utility helpers."""

from datetime import UTC, datetime

import pytest

from authsome.utils import (
    build_store_key,
    is_filesystem_safe,
    parse_rfc3339,
    to_rfc3339,
    utc_now,
)


class TestUtcHelpers:
    """Datetime formatting helpers."""

    def test_utc_now_is_timezone_aware(self) -> None:
        now = utc_now()
        assert now.tzinfo is not None

    def test_to_rfc3339_handles_naive_datetime(self) -> None:
        dt = datetime(2026, 4, 22, 12, 30, 45)
        assert to_rfc3339(dt) == "2026-04-22T12:30:45Z"

    def test_parse_rfc3339_roundtrip(self) -> None:
        dt = datetime(2026, 4, 22, 12, 30, 45, tzinfo=UTC)
        encoded = to_rfc3339(dt)
        decoded = parse_rfc3339(encoded)
        assert decoded == dt


class TestFilesystemSafety:
    """Filesystem safety checks."""

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("valid-name_1.2", True),
            ("1valid", True),
            ("", False),
            ("../escape", False),
            ("bad/name", False),
            (".hidden", False),
        ],
    )
    def test_is_filesystem_safe(self, name: str, expected: bool) -> None:
        assert is_filesystem_safe(name) is expected


class TestStoreKeys:
    """Store key generation helpers."""

    def test_build_definition_key(self) -> None:
        assert build_store_key(provider="github", record_type="definition") == "provider:github:definition"

    def test_build_connection_key(self) -> None:
        assert (
            build_store_key(
                profile="default",
                provider="github",
                record_type="connection",
                connection="personal",
            )
            == "profile:default:github:connection:personal"
        )

    def test_invalid_key_inputs(self) -> None:
        with pytest.raises(ValueError, match="Cannot build store key"):
            build_store_key(profile="default", provider="github", record_type="connection")
