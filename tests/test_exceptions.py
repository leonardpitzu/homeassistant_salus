"""Tests for Salus iT600 exception hierarchy."""

from __future__ import annotations

from custom_components.salus.exceptions import (
    IT600AuthenticationError,
    IT600CommandError,
    IT600ConnectionError,
    IT600Error,
)


class TestExceptionHierarchy:
    """Verify the exception class hierarchy."""

    def test_base_is_exception(self):
        assert issubclass(IT600Error, Exception)

    def test_authentication_error_inherits_base(self):
        assert issubclass(IT600AuthenticationError, IT600Error)

    def test_command_error_inherits_base(self):
        assert issubclass(IT600CommandError, IT600Error)

    def test_connection_error_inherits_base(self):
        assert issubclass(IT600ConnectionError, IT600Error)

    def test_can_catch_all_with_base(self):
        for exc_cls in (
            IT600AuthenticationError,
            IT600CommandError,
            IT600ConnectionError,
        ):
            try:
                raise exc_cls("test")
            except IT600Error:
                pass  # expected

    def test_message_preserved(self):
        err = IT600ConnectionError("host unreachable")
        assert str(err) == "host unreachable"
