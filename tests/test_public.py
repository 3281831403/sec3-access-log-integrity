"""Public acceptance tests for the append-only access log."""

from __future__ import annotations

from copy import deepcopy

from acclog import GENESIS, append, log_batch, log_digest, verify


def _build_log() -> list[dict]:
    log: list[dict] = []
    for event in ("boot", "login", "read"):
        log = append(log, {"event": event})
    return log


def test_append_records_in_order() -> None:
    log = _build_log()

    assert len(log) == 3
    assert [record["index"] for record in log] == [1, 2, 3]
    assert log[0]["prev"] == GENESIS
    assert log[1]["prev"] == log[0]["hash"]
    assert log[2]["prev"] == log[1]["hash"]
    assert all(len(record["hash"]) == 64 for record in log)


def test_complete_chain_verification() -> None:
    log = _build_log()

    assert verify(log) == {"ok": True, "index": None}

    tampered = deepcopy(log)
    tampered[0]["entry"] = {"event": "forged"}
    tampered[2]["entry"] = {"event": "forged"}

    result = verify(tampered)

    assert result["ok"] is False
    assert result["index"] == 1


def test_single_modified_record_is_detected() -> None:
    log = _build_log()
    tampered = deepcopy(log)
    tampered[1]["entry"] = {"event": "replaced"}

    result = verify(tampered)

    assert result["ok"] is False
    assert result["index"] == 2


def test_integrity_digest_is_stable() -> None:
    log = _build_log()

    assert log_digest(deepcopy(log)) == log_digest(log)

    changed = deepcopy(log)
    changed[0]["entry"] = {"event": "rewritten"}
    assert log_digest(changed) != log_digest(log)


def test_batch_logs_are_independent() -> None:
    first = _build_log()

    second: list[dict] = []
    for event in ("alpha", "beta", "gamma"):
        second = append(second, {"event": event})

    results = log_batch({"first": first, "second": second})

    assert set(results) == {"first", "second"}
    assert results["first"] == {"ok": True, "index": None}
    assert results["second"] == {"ok": True, "index": None}