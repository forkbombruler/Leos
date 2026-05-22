from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from leos_agent.memory import MemoryStore, MemoryType


class MemoryStoreRecallFilterTests(unittest.TestCase):
    def test_recall_filters_by_memory_type(self) -> None:
        store = MemoryStore()
        store.remember(
            "test_key", "fact_value", confidence=1.0, provenance="test",
            memory_type=MemoryType.FACT,
        )
        store.remember(
            "test_key", "procedure_value", confidence=1.0, provenance="test",
            memory_type=MemoryType.PROCEDURE,
        )
        store.remember(
            "test_key", "policy_value", confidence=1.0, provenance="test",
            memory_type=MemoryType.POLICY,
        )

        facts = store.recall("test_key", memory_type=MemoryType.FACT)
        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0]["value"], "fact_value")
        self.assertEqual(facts[0]["memory_type"], "fact")

        procedures = store.recall("test_key", memory_type=MemoryType.PROCEDURE)
        self.assertEqual(len(procedures), 1)
        self.assertEqual(procedures[0]["value"], "procedure_value")

        policies = store.recall("test_key", memory_type=MemoryType.POLICY)
        self.assertEqual(len(policies), 1)
        self.assertEqual(policies[0]["value"], "policy_value")

        all_records = store.recall("test_key")
        self.assertEqual(len(all_records), 3)

    def test_recall_memory_type_none_returns_all_types(self) -> None:
        store = MemoryStore()
        store.remember("key", "a", confidence=1.0, provenance="t", memory_type=MemoryType.FACT)
        store.remember("key", "b", confidence=1.0, provenance="t", memory_type=MemoryType.PREFERENCE)

        results = store.recall("key", memory_type=None)
        self.assertEqual(len(results), 2)

    def test_recall_memory_type_excludes_expired(self) -> None:
        store = MemoryStore()
        store.remember("key", "expired", confidence=1.0, provenance="t",
                       memory_type=MemoryType.FACT, ttl=0.0)
        store.remember("key", "fresh", confidence=1.0, provenance="t",
                       memory_type=MemoryType.FACT)

        results = store.recall("key", memory_type=MemoryType.FACT)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["value"], "fresh")

    def test_recall_memory_type_include_expired(self) -> None:
        store = MemoryStore()
        store.remember("key", "expired", confidence=1.0, provenance="t",
                       memory_type=MemoryType.FACT, ttl=0.0)
        store.remember("key", "fresh", confidence=1.0, provenance="t",
                       memory_type=MemoryType.FACT)

        results = store.recall("key", memory_type=MemoryType.FACT, include_expired=True)
        self.assertEqual(len(results), 2)

    def test_recall_memory_type_combined_with_scope_filter(self) -> None:
        store = MemoryStore()
        store.remember("key", "a", confidence=1.0, provenance="t",
                       memory_type=MemoryType.FACT, scope="global")
        store.remember("key", "b", confidence=1.0, provenance="t",
                       memory_type=MemoryType.FACT, scope="local")

        results = store.recall("key", memory_type=MemoryType.FACT, scope="local")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["value"], "b")

    def test_recall_memory_type_no_match_returns_empty(self) -> None:
        store = MemoryStore()
        store.remember("key", "val", confidence=1.0, provenance="t",
                       memory_type=MemoryType.FACT)

        results = store.recall("key", memory_type=MemoryType.POLICY)
        self.assertEqual(results, [])

    def test_persist_and_reload_preserves_memory_type(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "memory.json"
            store = MemoryStore(path)
            store.remember("k", "v", confidence=1.0, provenance="t",
                           memory_type=MemoryType.PROCEDURE)
            loaded = MemoryStore(path)
            results = loaded.recall("k", memory_type=MemoryType.PROCEDURE)
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["value"], "v")
            self.assertEqual(results[0]["memory_type"], "procedure")


if __name__ == "__main__":
    unittest.main()
