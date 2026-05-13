from __future__ import annotations

import unittest

from leos_agent.causal_contract import safe_file_write_causal_contract
from leos_agent.plans import ActionStep
from leos_agent.state import WorldState


class CausalContractTests(unittest.TestCase):
    def test_safe_file_write_contract_generates_file_written_prediction(self) -> None:
        contract = safe_file_write_causal_contract()
        predictions = contract.predictions(
            ActionStep("safe_file_write", {"file_written": "/tmp/x"}, "write"),
            WorldState(),
        )

        self.assertEqual(predictions[0].variable, "file_written")
        self.assertEqual(predictions[0].expected_after, "/tmp/x")

    def test_missing_required_observations_are_reported(self) -> None:
        contract = safe_file_write_causal_contract()

        self.assertEqual(contract.missing_required_observations({}), ["file_written"])
        self.assertEqual(contract.missing_required_observations({"file_written": "x"}), [])


if __name__ == "__main__":
    unittest.main()
