"""Extended rule loader coverage."""

from __future__ import annotations

from typing import Any


def test_load_rule_from_dict_with_response_procedure(metadata: dict[str, Any]) -> None:
    import opentide.loading.rule_loader as rule_loader_module

    payload = {
        "name": "Rule",
        "metadata": metadata,
        "description": "desc",
        "response": {
            "playbook": "Investigate",
            "procedure": {
                "analysis": "Review alerts",
                "searches": [
                    {
                        "purpose": "Hunt",
                        "system": "sentinel",
                        "query": "SecurityEvent | take 1",
                    }
                ],
            },
        },
        "configurations": {},
    }
    rule = rule_loader_module.load_rule_from_dict(payload)
    assert rule.response is not None
    assert rule.response.procedure is not None
    assert rule.response.procedure.searches is not None
    assert len(rule.response.procedure.searches) == 1
