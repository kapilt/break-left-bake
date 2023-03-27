import json
from collections import Counter
from pathlib import Path


def main(path="terrascan"):

    check_dir = Path(path) / "pkg" / "policies" / "opa" / "rego"
    stats = Counter()
    rules = []

    for provider in ("aws", "azure", "gcp"):
        provider_dir = check_dir / provider

        checks = list(provider_dir.rglob("*.json"))
        defines = list(provider_dir.rglob("*.rego"))

        stats[provider] += len(checks)
        stats[provider + "_unique"] += len(defines)
        for cpath in checks:
            c = json.loads(cpath.read_text())
            rules.append(
                {
                    k: v
                    for k, v in c.items()
                    if k in ("policy_type", "severity", "description", "id", "category")
                }
            )
    print(stats)


#    print(len(rules))


if __name__ == "__main__":
    main()
