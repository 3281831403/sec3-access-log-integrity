"""Append-only access log integrity helpers."""

from .chain import (
    GENESIS,
    HASH_SIZE,
    append,
    check_gap,
    check_immutable,
    entry_hash,
    log_batch,
    log_digest,
    validate_log,
    verify,
)

__all__ = [
    "GENESIS",
    "HASH_SIZE",
    "append",
    "check_gap",
    "check_immutable",
    "entry_hash",
    "log_batch",
    "log_digest",
    "validate_log",
    "verify",
]