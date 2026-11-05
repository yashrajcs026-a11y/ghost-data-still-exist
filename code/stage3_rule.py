
import csv
from pathlib import Path

# Locate the dataset folder
BASE_DIR = Path(__file__).resolve().parent.parent
DATASET_DIR = BASE_DIR / "dataset"


def load_deletion_rules():
    """Load and validate the deletion rules."""

    rules_file = DATASET_DIR / "deletion_rules.csv"

    rules = {}

    allowed_actions = {
        "DELETE",
        "REDACT",
        "ANONYMIZE",
        "RETAIN"
    }

    with rules_file.open(
        "r", encoding="utf-8-sig", newline=""
    ) as file:

        reader = csv.DictReader(file)

        for row in reader:
            category = row["data_category"].strip()
            action = row["required_action"].strip()

            if category in rules:
                raise ValueError(
                    f"Duplicate category found: {category}"
                )

            if action not in allowed_actions:
                raise ValueError(
                    f"Invalid action found: {action}"
                )

            rules[category] = {
                "rule_id": row["rule_id"],
                "condition": row["condition"],
                "required_action": action
            }

    return rules


if __name__ == "__main__":

    rules = load_deletion_rules()

    print("\nSTAGE 3A — DELETION RULE LOADER")
    print("=" * 45)

    print(f"Total rules loaded: {len(rules)}")

    for category, details in sorted(rules.items()):
        print(
            f"{category:25} "
            f"{details['required_action']}"
        )

    print("\nRule validation completed successfully.")
