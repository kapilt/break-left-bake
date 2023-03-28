from pathlib import Path
import json
from collections import Counter

from checkov import main as side_effect
from checkov.common.util.docs_generator import get_checks

NORMALIZED_PROVIDER_NAMES = {
    'aws': 'aws',
    'azurerm': 'azure',
    'google': 'gcp',
}

def main():

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
        rule_ids.add(rule["id"])
        stats[provider] += 1

    Path('checkov_rules.jsonl').write_text('\n'.join(json.dumps(rule) for rule in rules))
    print(stats)


if __name__ == "__main__":
    main()
