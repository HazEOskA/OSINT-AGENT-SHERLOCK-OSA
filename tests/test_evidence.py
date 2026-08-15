from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from sherlock_osa.evidence import EvidenceLedger, GENESIS_HASH


class EvidenceTests(unittest.TestCase):
    def test_append_and_verify_chain(self) -> None:
        with TemporaryDirectory() as directory:
            ledger = EvidenceLedger(Path(directory) / "evidence.jsonl")
            first = ledger.append("ONE", {"mission_id": "m1", "value": 1})
            second = ledger.append("TWO", {"mission_id": "m1", "value": 2})
            result = ledger.verify()
            self.assertTrue(result.valid)
            self.assertEqual(result.record_count, 2)
            self.assertEqual(first["previous_hash"], GENESIS_HASH)
            self.assertEqual(second["previous_hash"], first["hash"])
            self.assertEqual(result.head_hash, second["hash"])

    def test_tamper_is_detected_and_blocks_append(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.jsonl"
            ledger = EvidenceLedger(path)
            ledger.append("ONE", {"mission_id": "m1", "value": 1})
            record = json.loads(path.read_text(encoding="utf-8"))
            record["payload"]["value"] = 999
            path.write_text(json.dumps(record) + "\n", encoding="utf-8")
            self.assertFalse(ledger.verify().valid)
            with self.assertRaisesRegex(ValueError, "Odmowa append"):
                ledger.append("TWO", {"mission_id": "m1"})


if __name__ == "__main__":
    unittest.main()
