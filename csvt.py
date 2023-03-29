import csv
import json
from pathlib import Path


def main():
    cur_dir = Path(".")
    rows = []
    for name in ("checkov", "kics", "trivy", "terrascan"):
        check_path = cur_dir / (name + "_rules.jsonl")
        rules = [json.loads(l) for l in check_path.read_text().splitlines()]
        print(name)
        for r in rules:
            row = {
                "source": name,
                "provider": r["provider"].lower(),
                "id": r["id"],
                "severity": r["severity"].lower(),
                "category": r["category"].lower(),
                "name": r["name"],
                "description": r["description"],
                "path": r["path"],
            }
            rows.append(row)

    for provider in ("aws", "gcp", "azure"):
        with open(f"break-left-{provider}.csv", "w") as fh:
            writer = csv.DictWriter(fh, list(row), quoting=csv.QUOTE_MINIMAL)
            writer.writeheader()
            for r in rows:
                if r["provider"] != provider:
                    continue
                writer.writerow(r)


if __name__ == "__main__":
    main()
