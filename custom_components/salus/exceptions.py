"""Exceptions for Salus iT600 gateway communication."""

from __future__ import annotations


class IT600Error(Exception):
    """Base Salus iT600 exception."""


class IT600AuthenticationError(IT600Error):
    """Salus iT600 authentication exception (bad EUID)."""


class IT600CommandError(IT600Error):
    """Salus iT600 command exception (rejected request)."""


class IT600ConnectionError(IT600Error):
    """Salus iT600 connection exception (unreachable gateway)."""
