from pathlib import Path
import json
from collections import Counter

from checkov import main as side_effect
from checkov.common.util.docs_generator import get_checks

from checkov.common.checks_infra.registry import (
    BaseRegistry as BaseGraphRegistry,
    get_graph_checks_registry,
)
from checkov.terraform.checks.data.registry import data_registry
from checkov.terraform.checks.module.registry import module_registry
from checkov.terraform.checks.provider.registry import provider_registry
from checkov.terraform.checks.resource.registry import resource_registry

NORMALIZED_PROVIDER_NAMES = {
    "aws": "aws",
    "azurerm": "azure",
    "google": "gcp",
}

import inspect


def get_check_map():
    checks = {}

    for registry in [
        data_registry,
        module_registry,
        provider_registry,
        resource_registry,
    ]:
        for entity, check in registry.all_checks():
            check_path = inspect.getfile(check.__class__)

            checks[check.id] = {
                "name": Path(check_path).name[:-3],
                "severity": check.check_fail_level,
                "path": check_path[check_path.index("checkov") + 8 :],
                "category": [c.name for c in check.categories].pop(),
            }
    graph_registry = get_graph_checks_registry("terraform")
    graph_registry.load_checks()

    for graph_check in graph_registry.checks:
        check_path = graph_check.check_path
        checks[graph_check.id] = {
            "name": Path(check_path).name[:-5],
            "path": check_path[check_path.index("checkov") + 8 :],
            "category": graph_check.category,
            "severity": graph_check.severity or "UNKNOWN",
        }
    return checks


def main():
    check_map = get_check_map()
    stats = Counter()
    rules = []
    rule_ids = set()
    for c in get_checks(frameworks=["terraform"]):
        rule = dict(zip(("id", "type", "resource", "name", "iac", "link"), c))
        if rule["id"] in rule_ids:
            continue

        provider = rule["resource"].split("_", 1)[0]
        if len(provider) == 1:
            # some of these do seem to have single letter resources, odd
            continue

        if provider not in ("aws", "azurerm", "google"):
            continue
        rule["provider"] = NORMALIZED_PROVIDER_NAMES[provider]
        rules.append(rule)
        rule["description"] = rule["name"]
        rule["name"] = check_map[rule["id"]]["name"]
        rule["category"] = check_map[rule["id"]]["category"]
        rule["path"] = check_map[rule["id"]]["path"]
        rule["severity"] = check_map[rule["id"]]["severity"]
        rule_ids.add(rule["id"])
        stats[provider] += 1

    Path("checkov_rules.jsonl").write_text(
        "\n".join(json.dumps(rule) for rule in rules)
    )
    print(stats)


if __name__ == "__main__":
    main()
