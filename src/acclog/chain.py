"""Hash-chained access log helpers.

A log is a list of record dictionaries.  Every record carries four keys:

    index: sequence number of the record inside the log
    prev: digest of the preceding record
    entry: caller supplied access event
    hash: digest of the record itself

The module exposes canonical hashing, append, verification, whole-log digest,
sequence-gap inspection, immutability inspection, structural validation and
batch verification.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

GENESIS = "0" * 64
HASH_SIZE = 64
_HEX_DIGITS = frozenset("0123456789abcdef")


def _canonical(value: Any) -> bytes:
    """Serialize a JSON-compatible value deterministically."""

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def entry_hash(prev: str, index: int, entry: Any) -> str:
    """Return the digest for an entry at a given position in a log.

    The digest binds all three inputs so that changing the sequence number,
    the previous digest or the event body changes the result.
    """

    material = {"entry": entry, "index": index, "prev": prev}
    return hashlib.sha256(_canonical(material)).hexdigest()


def append(log: list[dict], entry: Any) -> list:
    """Append one entry to the log and return the same list.

    Sequence numbers are owned solely by the log: they start at 1 and the
    next number is the last record's index plus one.  A caller-supplied
    ``index`` living inside ``entry`` is data and never controls placement.
    Existing records are never overwritten.
    """

    index = log[-1]["index"] + 1 if log else 1
    prev = log[-1]["hash"] if log else GENESIS
    record = {
        "index": index,
        "prev": prev,
        "entry": entry,
        "hash": entry_hash(prev, index, entry),
    }
    log.append(record)
    return log


def verify(log: list[dict]) -> dict:
    """Return a status mapping with ok and index for the log.

    Records are checked against their 1-based *position* in the list, which is
    what makes deletions locate the missing sequence number: after deleting
    number k, position k holds record k+1 and the mismatch is reported as k.
    The scan stops at the first break.
    """

    prev = GENESIS
    for position, record in enumerate(log, start=1):
        index = record.get("index")
        if index != position:
            return {"ok": False, "index": position}
        if record.get("prev") != prev:
            return {"ok": False, "index": position}
        expected = entry_hash(record.get("prev", ""), index, record.get("entry"))
        if record.get("hash") != expected:
            return {"ok": False, "index": position}
        prev = record.get("hash")
    return {"ok": True, "index": None}


def log_digest(log: list[dict]) -> str:
    """Return a stable digest covering every field of every record.

    Because the whole list is hashed, truncating the tail (which leaves the
    surviving chain internally valid) and any single-field tampering both
    change the digest.
    """

    material = [
        {
            "index": record.get("index"),
            "prev": record.get("prev"),
            "hash": record.get("hash"),
            "entry": record.get("entry"),
        }
        for record in log
    ]
    return hashlib.sha256(_canonical(material)).hexdigest()


def check_gap(log: list[dict]) -> list[int]:
    """Return the sequence numbers that are absent from the log."""

    indexes = [record.get("index") for record in log if isinstance(record.get("index"), int)]
    if not indexes:
        return []
    present = set(indexes)
    return [number for number in range(1, max(indexes) + 1) if number not in present]


def check_immutable(log: list[dict]) -> list[str]:
    """Return findings that suggest a record was replaced or reordered."""

    issues: list[str] = []
    last_index = 0
    seen: set[Any] = set()
    for record in log:
        index = record.get("index")
        if not isinstance(index, int) or index <= last_index:
            issues.append(f"index {index}: sequence does not increase")
        else:
            last_index = index
        digest = record.get("hash")
        if digest in seen:
            issues.append(f"index {index}: repeated digest")
        seen.add(digest)
    return issues


def validate_log(log: list[dict]) -> list[str]:
    """Return structural problems found in the log."""

    problems: list[str] = []
    seen: set[Any] = set()
    for record in log:
        if "index" not in record or not isinstance(record.get("index"), int):
            problems.append("index missing")
            continue
        index = record["index"]
        if index in seen:
            problems.append(f"duplicate index {index}")
        seen.add(index)
        digest = record.get("hash")
        if (
            not isinstance(digest, str)
            or len(digest) != HASH_SIZE
            or any(character not in _HEX_DIGITS for character in digest.lower())
        ):
            problems.append(f"hash invalid at index {index}")
    return problems


def log_batch(logs: dict[str, list[dict]]) -> dict[str, dict]:
    """Verify several named logs and return one result per name.

    Each call to :func:`verify` starts from the genesis digest, so no chain
    state is shared between logs.
    """

    return {name: verify(log) for name, log in logs.items()}
