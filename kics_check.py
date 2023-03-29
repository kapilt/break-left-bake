import json
from pathlib import Path
from collections import Counter


def main(path="kics"):
    terraform_checks = Path(path) / "assets" / "queries" / "terraform"

    stats = Counter()

    rules = []
    for provider in ("aws", "azure", "gcp"):
        provider_dir = terraform_checks / provider

        for check_path in provider_dir.rglob("metadata.json"):
            check = json.loads(check_path.read_text())

            stats[check["cloudProvider"]] += 1

            rules.append(
                dict(
                    id=check["id"],
                    provider=check["cloudProvider"],
                    severity=check["severity"].title(),
                    description=check["descriptionText"],
                    name=check["queryName"],
                )
            )

    Path('kics_rules.jsonl').write_text('\n'.join(json.dumps(rule) for rule in rules))
    print(stats)


if __name__ == "__main__":
    main()
