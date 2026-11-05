
import csv
import json
from pathlib import Path
from collections import defaultdict


BASE_DIR = Path(__file__).resolve().parent.parent

REQUESTS_FILE = BASE_DIR / "dataset" / "deletion_requests.csv"
RESOURCE_FILE = BASE_DIR / "resource_evidence_index.csv"
MAPPING_FILE = BASE_DIR / "stage3b_evidence_mapping.csv"
INTERPRETATION_FILE = BASE_DIR / "stage3c_evidence_interpretation.csv"
ACTIVITY_FILE = BASE_DIR / "dataset" / "system_activity.csv"

OUTPUT_FILE = BASE_DIR / "stage4a_resource_inventory.csv"
UNLINKED_FILE = BASE_DIR / "stage4a_unlinked_evidence.csv"


def read_csv(path):
    """Read a CSV file and return its rows as dictionaries."""
    with open(path, "r", encoding="utf-8-sig", newline="") as file:
        return list(csv.DictReader(file))


def write_csv(path, rows, fieldnames):
    """Write dictionaries to a CSV file."""
    with open(path, "w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def split_values(value):
    """Split semicolon-separated IDs while removing empty values."""
    if not value:
        return []

    return [
        item.strip()
        for item in value.split(";")
        if item.strip()
    ]


def is_before_or_at(timestamp, audit_at):
    """Check whether a timestamp is at or before the audit time."""
    if not timestamp or not audit_at:
        return False

    return timestamp <= audit_at


def get_resource_id(row):
    """Prefer explicit resource IDs, then pipe-parsed IDs."""
    return (
        row.get("resource_id", "").strip()
        or row.get("pipe_resource_id", "").strip()
    )


def get_system_id(row):
    """Prefer explicit system IDs, then pipe-parsed IDs."""
    return (
        row.get("system_id", "").strip()
        or row.get("pipe_system_id", "").strip()
    )


def add_to_set(target, value):
    if value:
        target.add(value)


def main():
    print("STAGE 4A: BUILDING RESOURCE INVENTORY")
    print("--------------------------------------")

    requests = read_csv(REQUESTS_FILE)
    resource_rows = read_csv(RESOURCE_FILE)
    mapping_rows = read_csv(MAPPING_FILE)
    evidence_rows = read_csv(INTERPRETATION_FILE)
    activity_rows = read_csv(ACTIVITY_FILE)

    # One audit timestamp for each case.
    audit_times = {
        row["case_id"]: row.get("audit_at", "").strip()
        for row in requests
    }

    # Inventory structure:
    # inventory[case_id][resource_id] = resource information.
    inventory = defaultdict(dict)

    def get_resource(case_id, resource_id):
        """Create a resource entry if it does not already exist."""
        if not resource_id:
            return None

        if resource_id not in inventory[case_id]:
            inventory[case_id][resource_id] = {
                "case_id": case_id,
                "user_id": "",
                "resource_id": resource_id,
                "system_ids": set(),
                "observed_system_ids": set(),
                "categories": set(),
                "required_actions": set(),
                "mapping_sources": set(),
                "evidence_ids": set(),
                "direct_states": set(),
                "evidence_signals": set(),
                "activity_ids": set(),
                "activity_types": set(),
                "activity_results": set(),
                "latest_evidence_at": "",
                "latest_state_evidence_at": "",
                "latest_activity_at": "",
            }

        return inventory[case_id][resource_id]

    # --------------------------------------------------
    # 1. Load candidate resources from Stage 2B.
    # --------------------------------------------------

    for row in resource_rows:
        case_id = row.get("case_id", "").strip()
        resource_id = row.get("resource_id", "").strip()

        if not case_id or not resource_id:
            continue

        item = get_resource(case_id, resource_id)

        item["user_id"] = row.get("user_id", "").strip()

        for system in split_values(row.get("system_ids", "")):
            add_to_set(item["system_ids"], system)

        for activity_id in split_values(row.get("activity_ids", "")):
            add_to_set(item["activity_ids"], activity_id)

    # --------------------------------------------------
    # 2. Load category and rule mappings from Stage 3B.
    # --------------------------------------------------

    for row in mapping_rows:
        case_id = row.get("case_id", "").strip()

        if case_id not in audit_times:
            continue

        if not is_before_or_at(
            row.get("captured_at", "").strip(),
            audit_times[case_id]
        ):
            continue

        resource_ids = set()

        resource_id = row.get("resource_id", "").strip()
        if resource_id:
            resource_ids.add(resource_id)

        for value in split_values(row.get("resource_ids", "")):
            resource_ids.add(value)

        for resource_id in resource_ids:
            item = get_resource(case_id, resource_id)

            if not item:
                continue

            item["user_id"] = (
                item["user_id"]
                or row.get("user_id", "").strip()
            )

            add_to_set(
                item["categories"],
                row.get("mapped_category", "").strip()
            )

            add_to_set(
                item["required_actions"],
                row.get("required_action", "").strip()
            )

            add_to_set(
                item["mapping_sources"],
                row.get("mapping_source", "").strip()
            )

            add_to_set(
                item["observed_system_ids"],
                row.get("system_id", "").strip()
            )

    # --------------------------------------------------
    # 3. Attach interpreted evidence from Stage 3C.
    # --------------------------------------------------

    unlinked_evidence = []

    for row in evidence_rows:
        case_id = row.get("case_id", "").strip()

        if case_id not in audit_times:
            continue

        captured_at = row.get("captured_at", "").strip()
        audit_at = audit_times[case_id]

        # Evidence captured after the audit cannot establish
        # the state at the audit time.
        if not is_before_or_at(captured_at, audit_at):
            continue

        resource_ids = set()

        resource_id = get_resource_id(row)
        if resource_id:
            resource_ids.add(resource_id)

        for value in split_values(row.get("resource_ids", "")):
            resource_ids.add(value)

        if not resource_ids:
            unlinked_evidence.append({
                "case_id": case_id,
                "evidence_id": row.get("evidence_id", ""),
                "captured_at": captured_at,
                "system_id": get_system_id(row),
                "mapped_category": row.get("mapped_category", ""),
                "evidence_signals": row.get("evidence_signals", ""),
                "record_text": row.get("record_text", ""),
            })
            continue

        for resource_id in resource_ids:
            item = get_resource(case_id, resource_id)

            if not item:
                continue

            item["user_id"] = (
                item["user_id"]
                or row.get("user_id", "").strip()
            )

            add_to_set(
                item["observed_system_ids"],
                get_system_id(row)
            )

            add_to_set(
                item["categories"],
                row.get("mapped_category", "").strip()
            )

            add_to_set(
                item["evidence_ids"],
                row.get("evidence_id", "").strip()
            )

            add_to_set(
                item["evidence_signals"],
                row.get("evidence_signals", "").strip()
            )

            state = row.get("interpreted_state", "").strip()
            if state:
                item["direct_states"].add(state)

                if captured_at >= item["latest_state_evidence_at"]:
                    item["latest_state_evidence_at"] = captured_at

            if captured_at >= item["latest_evidence_at"]:
                item["latest_evidence_at"] = captured_at

    # --------------------------------------------------
    # 4. Attach system activity using explicit resource
    #    IDs and activity IDs already linked to each case.
    # --------------------------------------------------

    activities_by_id = {
        row.get("activity_id", "").strip(): row
        for row in activity_rows
        if row.get("activity_id", "").strip()
    }

    for case_id, resources in inventory.items():
        audit_at = audit_times.get(case_id, "")

        for resource_id, item in resources.items():

            for activity in activity_rows:
                activity_resource = activity.get(
                    "resource_id", ""
                ).strip()

                activity_id = activity.get(
                    "activity_id", ""
                ).strip()

                explicitly_linked = (
                    activity_id in item["activity_ids"]
                )

                directly_matched = (
                    activity_resource == resource_id
                )

                if not explicitly_linked and not directly_matched:
                    continue

                event_time = activity.get("event_time", "").strip()

                if not is_before_or_at(event_time, audit_at):
                    continue

                add_to_set(item["activity_ids"], activity_id)

                add_to_set(
                    item["activity_types"],
                    activity.get("event_type", "").strip()
                )

                add_to_set(
                    item["activity_results"],
                    activity.get("reported_result", "").strip()
                )

                if event_time >= item["latest_activity_at"]:
                    item["latest_activity_at"] = event_time

    # --------------------------------------------------
    # 5. Convert sets into stable CSV-friendly values.
    # --------------------------------------------------

    output_rows = []

    for case_id in sorted(inventory):
        for resource_id in sorted(inventory[case_id]):

            item = inventory[case_id][resource_id]

            observed_systems = sorted(item["observed_system_ids"])
            indexed_systems = sorted(item["system_ids"])

            # Prefer a system directly observed in evidence.
            # Keep all system candidates visible for review.
            system_id = (
                observed_systems[0]
                if observed_systems
                else indexed_systems[0]
                if indexed_systems
                else ""
            )

            output_rows.append({
                "case_id": item["case_id"],
                "user_id": item["user_id"],
                "resource_id": item["resource_id"],
                "system_id": system_id,
                "all_system_ids": ";".join(indexed_systems),
                "observed_system_ids": ";".join(observed_systems),
                "categories": ";".join(sorted(item["categories"])),
                "required_actions": ";".join(
                    sorted(item["required_actions"])
                ),
                "mapping_sources": ";".join(
                    sorted(item["mapping_sources"])
                ),
                "evidence_ids": ";".join(
                    sorted(item["evidence_ids"])
                ),
                "direct_states": ";".join(
                    sorted(item["direct_states"])
                ),
                "evidence_signals": ";".join(
                    sorted(item["evidence_signals"])
                ),
                "activity_ids": ";".join(
                    sorted(item["activity_ids"])
                ),
                "activity_types": ";".join(
                    sorted(item["activity_types"])
                ),
                "activity_results": ";".join(
                    sorted(item["activity_results"])
                ),
                "latest_evidence_at": item["latest_evidence_at"],
                "latest_state_evidence_at": (
                    item["latest_state_evidence_at"]
                ),
                "latest_activity_at": item["latest_activity_at"],
                "audit_at": audit_times.get(case_id, ""),
            })

    fields = [
        "case_id",
        "user_id",
        "resource_id",
        "system_id",
        "all_system_ids",
        "observed_system_ids",
        "categories",
        "required_actions",
        "mapping_sources",
        "evidence_ids",
        "direct_states",
        "evidence_signals",
        "activity_ids",
        "activity_types",
        "activity_results",
        "latest_evidence_at",
        "latest_state_evidence_at",
        "latest_activity_at",
        "audit_at",
    ]

    write_csv(OUTPUT_FILE, output_rows, fields)

    unlinked_fields = [
        "case_id",
        "evidence_id",
        "captured_at",
        "system_id",
        "mapped_category",
        "evidence_signals",
        "record_text",
    ]

    write_csv(UNLINKED_FILE, unlinked_evidence, unlinked_fields)

    # --------------------------------------------------
    # 6. Print summary.
    # --------------------------------------------------

    print("\nSTAGE 4A COMPLETED")
    print("--------------------------")
    print(f"Cases processed: {len(audit_times)}")
    print(f"Resource rows created: {len(output_rows)}")
    print(f"Unlinked evidence rows: {len(unlinked_evidence)}")

    print("\nOUTPUT FILES")
    print(f"Resource inventory: {OUTPUT_FILE}")
    print(f"Unlinked evidence: {UNLINKED_FILE}")

    print("\nCATEGORY COVERAGE")
    category_counts = defaultdict(int)

    for row in output_rows:
        for category in split_values(row["categories"]):
            category_counts[category] += 1

    for category in sorted(category_counts):
        print(f"{category}: {category_counts[category]}")


if __name__ == "__main__":
    main()
