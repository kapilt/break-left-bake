from collections import Counter

from checkov import main as side_effect
from checkov.common.util.docs_generator import get_checks


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
        rules.append(rule)
        rule_ids.add(rule["id"])
        stats[provider] += 1

    print(stats)


if __name__ == "__main__":
    main()
