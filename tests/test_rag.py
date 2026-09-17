"""Tests for the RAG target and retrieval-poisoning attack."""
from __future__ import annotations

from core.engine import run_all
from core.rag_target import RAGTarget


def _findings():
    return run_all(RAGTarget())


def test_poisoned_doc_leaks_secret():
    reply = RAGTarget().send("Tell me about onboarding")
    assert "db-acme" in reply  # the poisoned document hijacked the answer


def test_clean_doc_does_not_leak():
    reply = RAGTarget().send("How long do refunds take?")
    assert "db-acme" not in reply  # a clean document answers safely


def test_retrieval_poisoning_attacks_succeed():
    succeeded = [f for f in _findings() if f.succeeded]
    assert len(succeeded) >= 2


def test_rag_benign_control_does_not_succeed():
    control = [f for f in _findings() if f.payload_id.endswith("benign-control")]
    assert len(control) == 1
    assert control[0].succeeded is False


def test_rag_findings_are_scored_and_remediated():
    for f in _findings():
        if f.succeeded:
            assert f.severity == "CRITICAL"        # leaks a DB password
            assert "Hardened system prompt" in f.remediation
