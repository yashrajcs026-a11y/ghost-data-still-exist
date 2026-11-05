import csv
import json
import re
from pathlib import Path
from collections import defaultdict


BASE_DIR = Path(__file__).resolve().parent.parent

REQUESTS_FILE = BASE_DIR / "dataset" / "deletion_requests.csv"
IDENTITIES_FILE = BASE_DIR / "dataset" / "user_identities.csv"
USER_AUDIT_FILE = BASE_DIR / "dataset" / "user_audit_log.csv"

RESOURCE_FILE = BASE_DIR / "resource_evidence_index.csv"
MAPPING_FILE = BASE_DIR / "stage3b_evidence_mapping.csv"
INTERPRETATION_FILE = BASE_DIR / "stage3c_evidence_interpretation.csv"
ACTIVITY_FILE = BASE_DIR / "dataset" / "system_activity.csv"

OUTPUT_FILE = BASE_DIR / "stage4a_resource_inventory.csv"
UNLINKED_FILE = BASE_DIR / "stage4a_unlinked_evidence.csv"


COLLECTION_MAP = {
    "customer_profiles": "USER_PROFILE",
    "customer_search_documents": "SEARCH_INDEX_ENTRY",
    "customer_analytics_reports": "ANALYTICS_PROFILE",
    "customer_analytics_profiles": "ANALYTICS_PROFILE",
    "customer_export_jobs": "USER_EXPORT",
    "support_conversations": "SUPPORT_MESSAGE",
    "ticket_attachments": "SUPPORT_ATTACHMENT",
    "backup_catalog": "BACKUP_ARCHIVE",
    "security_audit_events": "SECURITY_AUDIT_LOG",
    "deleted_customer_references": "ACCOUNT_TOMBSTONE",
    "connector_configurations": "ACTIVE_DATA_FLOW",
    "retained_order_records": "LEGAL_HOLD_RECORD",
}


def read_csv(path):
    with open(path, "r", encoding="utf-8-sig", newline="") as file:
        return list(csv.DictReader(file))


def write_csv(path, rows, fieldnames):
    with open(path, "w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
            extrasaction="ignore"
        )
        writer.writeheader()
        writer.writerows(rows)


def split_values(value):
    if not value:
        return []

    return [
        item.strip()
        for item in value.split(";")
        if item.strip()
    ]


def add_to_set(target, value):
    if value:
        target.add(str(value).strip())


def is_before_or_at(timestamp, audit_at):
    if not timestamp or not audit_at:
        return False

    # Dataset timestamps use consistently formatted ISO-8601 strings.
    return timestamp <= audit_at


def normalize_email(value):
    return str(value or "").strip().lower()


def extract_log_fields(text):
    """Extract simple key=value fields from log records."""

    fields = {}

    if not isinstance(text, str):
        return fields

    pattern = r'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"([^"]*)"'

    for match in re.finditer(pattern, text):
        fields[match.group(1)] = match.group(2)

    pattern_unquoted = (
        r'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^\s|"]+)'
    )

    for match in re.finditer(pattern_unquoted, text):
        fields.setdefault(match.group(1), match.group(2))

    return fields


def extract_details(record_text):
    """
    Extract information from:
    - ordinary JSON
    - timestamp-prefixed JSON
    - nested JSON with row and record_json
    - key=value log records
    """

    details = {}

    if not isinstance(record_text, str):
        return details

    details.update(extract_log_fields(record_text))

    json_start = record_text.find("{")

    if json_start == -1:
        return details

    try:
        data = json.loads(record_text[json_start:])
    except (json.JSONDecodeError, TypeError):
        return details

    if not isinstance(data, dict):
        return details

    details["_json_root"] = data

    row = data.get("row", {})

    if isinstance(row, dict):
        details["_json_row"] = row

        for key, value in row.items():
            if not isinstance(value, (dict, list)):
                details.setdefault(key, value)

        record = row.get("record_json", {})

        if isinstance(record, dict):
            details["_record_json"] = record

            for key, value in record.items():
                if not isinstance(value, (dict, list)):
                    details.setdefault(key, value)

    return details


def get_nested_value(details, key):
    """Find a field in the outer JSON, row, or record_json."""

    for container_name in (
        "_record_json",
        "_json_row",
        "_json_root",
    ):
        container = details.get(container_name, {})

        if isinstance(container, dict):
            value = container.get(key)

            if value not in (None, ""):
                return str(value).strip()

    return ""


def get_resource_ids(row, details):
    resource_ids = set()

    for value in (
        row.get("resource_id", ""),
        row.get("pipe_resource_id", ""),
        get_nested_value(details, "resource_id"),
        details.get("resource_id", ""),
    ):
        add_to_set(resource_ids, value)

    for value in split_values(row.get("resource_ids", "")):
        add_to_set(resource_ids, value)

    return resource_ids


def get_system_id(row, details):
    return (
        row.get("system_id", "").strip()
        or row.get("pipe_system_id", "").strip()
        or get_nested_value(details, "origin_system")
        or details.get("origin_system", "")
    )


def get_storage_table(details):
    root = details.get("_json_root", {})

    if isinstance(root, dict):
        table = root.get("table")

        if table:
            return str(table).strip()

    return "LOGICAL_OR_UNSPECIFIED"


def get_collection_category(details):
    collection = get_nested_value(details, "collection_name")

    return COLLECTION_MAP.get(collection, "")


def build_identity_maps(identities, audit_log):
    """
    Map current and historical email addresses to user IDs.

    A historical email is associated with the user recorded
    in user_audit_log.csv.
    """

    email_to_users = defaultdict(set)
    user_to_emails = defaultdict(set)

    for row in identities:
        user_id = row.get("user_id", "").strip()
        email = normalize_email(row.get("email", ""))

        if user_id and email:
            email_to_users[email].add(user_id)
            user_to_emails[user_id].add(email)

    for row in audit_log:
        user_id = row.get("user_id", "").strip()

        if not user_id or row.get("field_name", "").strip() != "email":
            continue

        for field in ("old_value", "new_value"):
            email = normalize_email(row.get(field, ""))

            if email:
                email_to_users[email].add(user_id)
                user_to_emails[user_id].add(email)

    return email_to_users, user_to_emails


def resolve_case_users(requests, email_to_users):
    case_users = {}
    unresolved = set()
    ambiguous = set()

    for row in requests:
        case_id = row.get("case_id", "").strip()
        email = normalize_email(row.get("email", ""))

        matches = email_to_users.get(email, set())

        if len(matches) == 1:
            case_users[case_id] = next(iter(matches))
        elif len(matches) == 0:
            unresolved.add(case_id)
        else:
            ambiguous.add(case_id)

    return case_users, unresolved, ambiguous


def check_evidence_identity(details, expected_user, email_to_users):
    """
    Check explicit subject identifiers when present.

    Evidence without an explicit subject field is not automatically
    treated as a mismatch. Its case-level association is retained
    and marked as not explicitly checked.
    """

    identity_fields = []

    for field in ("subject_reference", "subject_selector"):
        value = get_nested_value(details, field)

        if value:
            identity_fields.append((field, value))

    correlation_key = (
        details.get("correlation_key", "")
        or get_nested_value(details, "correlation_key")
    )

    if correlation_key:
        identity_fields.append(("correlation_key", correlation_key))

    if not identity_fields:
        return "NOT_EXPLICITLY_CHECKED", ""

    if not expected_user:
        return "CASE_USER_UNRESOLVED", identity_fields[0][1]

    for field, value in identity_fields:
        normalized = value.strip()

        if normalized == expected_user:
            continue

        email = normalize_email(normalized)

        if email:
            matching_users = email_to_users.get(email, set())

            if matching_users == {expected_user}:
                continue

        return "MISMATCH", f"{field}={normalized}"

    return "MATCH", ""


def main():
    print("STAGE 4A: BUILDING COPY-AWARE RESOURCE INVENTORY")
    print("------------------------------------------------")

    requests = read_csv(REQUESTS_FILE)
    identities = read_csv(IDENTITIES_FILE)
    user_audit = read_csv(USER_AUDIT_FILE)

    resource_rows = read_csv(RESOURCE_FILE)
    mapping_rows = read_csv(MAPPING_FILE)
    evidence_rows = read_csv(INTERPRETATION_FILE)
    activity_rows = read_csv(ACTIVITY_FILE)

    audit_times = {
        row["case_id"]: row.get("audit_at", "").strip()
        for row in requests
    }

    email_to_users, user_to_emails = build_identity_maps(
        identities,
        user_audit
    )

    case_users, unresolved_users, ambiguous_users = resolve_case_users(
        requests,
        email_to_users
    )

    # Inventory key:
    # (case_id, resource_id, storage_location)
    #
    # This prevents primary and replica copies from being merged.
    inventory = {}

    def get_resource(case_id, resource_id, storage_location):
        if not case_id or not resource_id:
            return None

        key = (case_id, resource_id, storage_location)

        if key not in inventory:
            inventory[key] = {
                "case_id": case_id,
                "user_id": case_users.get(case_id, ""),
                "resource_id": resource_id,
                "storage_location": storage_location,
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
                "activity_scope": set(),
                "identity_checks": set(),
                "latest_evidence_at": "",
                "latest_state_evidence_at": "",
                "latest_activity_at": "",
            }

        return inventory[key]

    unlinked_evidence = []

    def record_unlinked(row, reason, details=None):
        details = details or {}

        unlinked_evidence.append({
            "case_id": row.get("case_id", ""),
            "evidence_id": row.get("evidence_id", ""),
            "captured_at": row.get("captured_at", ""),
            "system_id": get_system_id(row, details),
            "mapped_category": (
                row.get("mapped_category", "")
                or row.get("pipe_category", "")
                or get_collection_category(details)
            ),
            "evidence_signals": row.get("evidence_signals", ""),
            "reason": reason,
            "record_text": row.get("record_text", ""),
        })

    # --------------------------------------------------
    # 1. Seed logical resources from Stage 2B.
    # --------------------------------------------------

    for row in resource_rows:
        case_id = row.get("case_id", "").strip()
        resource_id = row.get("resource_id", "").strip()

        if not case_id or not resource_id:
            continue

        item = get_resource(
            case_id,
            resource_id,
            "LOGICAL_OR_UNSPECIFIED"
        )

        item["user_id"] = (
            item["user_id"]
            or row.get("user_id", "").strip()
        )

        for system in split_values(row.get("system_ids", "")):
            add_to_set(item["system_ids"], system)

        for activity_id in split_values(row.get("activity_ids", "")):
            add_to_set(item["activity_ids"], activity_id)

    # --------------------------------------------------
    # 2. Attach Stage 3B category and rule mappings.
    # --------------------------------------------------

    mapping_lookup = defaultdict(list)

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

        add_to_set(resource_ids, row.get("resource_id", ""))

        for value in split_values(row.get("resource_ids", "")):
            add_to_set(resource_ids, value)

        for resource_id in resource_ids:
            key = (
                case_id,
                row.get("evidence_id", "").strip(),
                resource_id
            )

            mapping_lookup[key].append(row)

            item = get_resource(
                case_id,
                resource_id,
                "LOGICAL_OR_UNSPECIFIED"
            )

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
    # 3. Attach interpreted evidence, including nested JSON.
    # --------------------------------------------------

    for row in evidence_rows:
        case_id = row.get("case_id", "").strip()

        if case_id not in audit_times:
            continue

        captured_at = row.get("captured_at", "").strip()

        if not is_before_or_at(captured_at, audit_times[case_id]):
            continue

        details = extract_details(row.get("record_text", ""))

        resource_ids = get_resource_ids(row, details)

        if not resource_ids:
            record_unlinked(row, "NO_RESOURCE_ID", details)
            continue

        expected_user = case_users.get(case_id, "")

        identity_status, identity_detail = check_evidence_identity(
            details,
            expected_user,
            email_to_users
        )

        if identity_status == "MISMATCH":
            record_unlinked(
                row,
                f"IDENTITY_MISMATCH: {identity_detail}",
                details
            )
            continue

        if identity_status == "CASE_USER_UNRESOLVED":
            record_unlinked(
                row,
                f"CASE_USER_UNRESOLVED: {identity_detail}",
                details
            )
            continue

        storage_location = get_storage_table(details)
        system_id = get_system_id(row, details)

        category = (
            row.get("mapped_category", "").strip()
            or row.get("pipe_category", "").strip()
            or get_collection_category(details)
        )

        state = row.get("interpreted_state", "").strip()
        evidence_id = row.get("evidence_id", "").strip()
        signal = row.get("evidence_signals", "").strip()

        for resource_id in resource_ids:
            item = get_resource(
                case_id,
                resource_id,
                storage_location
            )

            item["user_id"] = (
                item["user_id"]
                or expected_user
                or row.get("user_id", "").strip()
            )

            add_to_set(item["observed_system_ids"], system_id)
            add_to_set(item["categories"], category)
            add_to_set(item["evidence_ids"], evidence_id)
            add_to_set(item["evidence_signals"], signal)
            add_to_set(item["identity_checks"], identity_status)

            # Attach the corresponding Stage 3B rule mapping.
            mapping_key = (case_id, evidence_id, resource_id)

            for mapped_row in mapping_lookup.get(mapping_key, []):
                add_to_set(
                    item["categories"],
                    mapped_row.get("mapped_category", "")
                )
                add_to_set(
                    item["required_actions"],
                    mapped_row.get("required_action", "")
                )
                add_to_set(
                    item["mapping_sources"],
                    mapped_row.get("mapping_source", "")
                )

            if state:
                add_to_set(item["direct_states"], state)

                if captured_at >= item["latest_state_evidence_at"]:
                    item["latest_state_evidence_at"] = captured_at

            if captured_at >= item["latest_evidence_at"]:
                item["latest_evidence_at"] = captured_at

    # --------------------------------------------------
    # 4. Attach activities as resource-level claims.
    # --------------------------------------------------

    for activity in activity_rows:
        case_id = activity.get("case_id", "").strip()

        if case_id not in audit_times:
            continue

        event_time = activity.get("event_time", "").strip()

        if not is_before_or_at(event_time, audit_times[case_id]):
            continue

        resource_id = activity.get("resource_id", "").strip()
        activity_id = activity.get("activity_id", "").strip()

        if not resource_id:
            continue

        # Find all storage entries for this logical resource.
        matching_items = [
            item
            for key, item in inventory.items()
            if key[0] == case_id and key[1] == resource_id
        ]

        for item in matching_items:
            add_to_set(item["activity_ids"], activity_id)

            add_to_set(
                item["activity_types"],
                activity.get("event_type", "")
            )

            add_to_set(
                item["activity_results"],
                activity.get("reported_result", "")
            )

            add_to_set(
                item["activity_scope"],
                "RESOURCE_LEVEL_CLAIM_NOT_COPY_PROOF"
            )

            if event_time >= item["latest_activity_at"]:
                item["latest_activity_at"] = event_time

    # Also preserve activity IDs explicitly linked by Stage 2B
    # when an activity has no resource_id.
    activity_by_id = {
        row.get("activity_id", "").strip(): row
        for row in activity_rows
        if row.get("activity_id", "").strip()
    }

    for item in inventory.values():
        for activity_id in list(item["activity_ids"]):
            activity = activity_by_id.get(activity_id)

            if not activity:
                continue

            event_time = activity.get("event_time", "").strip()

            if not is_before_or_at(
                event_time,
                audit_times.get(item["case_id"], "")
            ):
                continue

            add_to_set(
                item["activity_types"],
                activity.get("event_type", "")
            )

            add_to_set(
                item["activity_results"],
                activity.get("reported_result", "")
            )

            add_to_set(
                item["activity_scope"],
                "RESOURCE_LEVEL_CLAIM_NOT_COPY_PROOF"
            )

            if event_time >= item["latest_activity_at"]:
                item["latest_activity_at"] = event_time

    # --------------------------------------------------
    # 5. Write the copy-aware inventory.
    # --------------------------------------------------

    output_rows = []

    for key in sorted(inventory):
        item = inventory[key]

        indexed_systems = sorted(item["system_ids"])
        observed_systems = sorted(item["observed_system_ids"])

        all_systems = sorted(
            set(indexed_systems) | set(observed_systems)
        )

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
            "storage_location": item["storage_location"],
            "system_id": system_id,
            "all_system_ids": ";".join(all_systems),
            "categories": ";".join(sorted(item["categories"])),
            "required_actions": ";".join(
                sorted(item["required_actions"])
            ),
            "mapping_sources": ";".join(
                sorted(item["mapping_sources"])
            ),
            "evidence_ids": ";".join(sorted(item["evidence_ids"])),
            "direct_states": ";".join(sorted(item["direct_states"])),
            "evidence_signals": ";".join(
                sorted(item["evidence_signals"])
            ),
            "identity_checks": ";".join(
                sorted(item["identity_checks"])
            ),
            "activity_ids": ";".join(sorted(item["activity_ids"])),
            "activity_types": ";".join(sorted(item["activity_types"])),
            "activity_results": ";".join(
                sorted(item["activity_results"])
            ),
            "activity_scope": ";".join(
                sorted(item["activity_scope"])
            ),
            "latest_evidence_at": item["latest_evidence_at"],
            "latest_state_evidence_at": (
                item["latest_state_evidence_at"]
            ),
            "latest_activity_at": item["latest_activity_at"],
            "audit_at": audit_times.get(item["case_id"], ""),
        })

    fields = [
        "case_id",
        "user_id",
        "resource_id",
        "storage_location",
        "system_id",
        "all_system_ids",
        "categories",
        "required_actions",
        "mapping_sources",
        "evidence_ids",
        "direct_states",
        "evidence_signals",
        "identity_checks",
        "activity_ids",
        "activity_types",
        "activity_results",
        "activity_scope",
        "latest_evidence_at",
        "latest_state_evidence_at",
        "latest_activity_at",
        "audit_at",
    ]

    write_csv(OUTPUT_FILE, output_rows, fields)

    # --------------------------------------------------
    # 6. Write evidence that could not safely be linked.
    # --------------------------------------------------

    unlinked_fields = [
        "case_id",
        "evidence_id",
        "captured_at",
        "system_id",
        "mapped_category",
        "evidence_signals",
        "reason",
        "record_text",
    ]

    write_csv(UNLINKED_FILE, unlinked_evidence, unlinked_fields)

    # --------------------------------------------------
    # 7. Print validation summary.
    # --------------------------------------------------

    print("\nSTAGE 4A COMPLETED")
    print("--------------------------")
    print(f"Cases processed: {len(audit_times)}")
    print(f"Resolved case identities: {len(case_users)}")
    print(f"Unresolved identities: {len(unresolved_users)}")
    print(f"Ambiguous identities: {len(ambiguous_users)}")
    print(f"Inventory rows: {len(output_rows)}")
    print(f"Unlinked evidence rows: {len(unlinked_evidence)}")

    storage_counts = defaultdict(int)

    for row in output_rows:
        storage_counts[row["storage_location"]] += 1

    print("\nSTORAGE LOCATION COVERAGE")

    for location in sorted(storage_counts):
        print(f"{location}: {storage_counts[location]}")

    category_counts = defaultdict(int)

    for row in output_rows:
        for category in split_values(row["categories"]):
            category_counts[category] += 1

    print("\nCATEGORY COVERAGE")

    for category in sorted(category_counts):
        print(f"{category}: {category_counts[category]}")

    reason_counts = defaultdict(int)

    for row in unlinked_evidence:
        reason_counts[row["reason"]] += 1

    print("\nUNLINKED EVIDENCE REASONS")

    for reason in sorted(reason_counts):
        print(f"{reason}: {reason_counts[reason]}")

    print("\nOUTPUT FILES")
    print(f"Resource inventory: {OUTPUT_FILE}")
    print(f"Unlinked evidence: {UNLINKED_FILE}")


if __name__ == "__main__":
    main()