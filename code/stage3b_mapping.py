
import csv
import json
import re
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

EVIDENCE_FILE = BASE_DIR / "case_evidence_index.csv"
RULES_FILE = BASE_DIR / "dataset" / "deletion_rules.csv"
OUTPUT_FILE = BASE_DIR / "stage3b_evidence_mapping.csv"


COLLECTION_MAP = {
    "customer_profiles": "USER_PROFILE",
    "customer_search_documents": "SEARCH_INDEX_ENTRY",
    "customer_analytics_reports": "ANALYTICS_PROFILE",
    "customer_export_jobs": "USER_EXPORT",
    "support_conversations": "SUPPORT_MESSAGE",
    "ticket_attachments": "SUPPORT_ATTACHMENT",
    "backup_catalog": "BACKUP_ARCHIVE",
    "security_audit_events": "SECURITY_AUDIT_LOG",
    "deleted_customer_references": "ACCOUNT_TOMBSTONE",
    "connector_configurations": "ACTIVE_DATA_FLOW",
    "retained_order_records": "LEGAL_HOLD_RECORD",
}

PREFIX_MAP = {
    "account_": "USER_PROFILE",
    "search_": "SEARCH_INDEX_ENTRY",
    "analytics_": "ANALYTICS_PROFILE",
    "export_": "USER_EXPORT",
    "backup_": "BACKUP_ARCHIVE",
    "audit_record_": "SECURITY_AUDIT_LOG",
    "tombstone_": "ACCOUNT_TOMBSTONE",
    "marketing_": "MARKETING_PROFILE",
    "delivery_": "EMAIL_DELIVERY_LOG",
    "cache_": "CACHE_ENTRY",
    "telemetry_": "PRODUCT_TELEMETRY",
    "data_flow_": "ACTIVE_DATA_FLOW",
}

SPECIAL_CATEGORIES = {
    "DATA_FLOW": "ACTIVE_DATA_FLOW",
    "RETAINED_ORDER_RECORDS": "LEGAL_HOLD_RECORD",
}

EVENT_CATEGORY_MAP = {
    "profile_lookup_started": "USER_PROFILE",
    "index_query_started": "SEARCH_INDEX_ENTRY",
    "audit_record_query_started": "SECURITY_AUDIT_LOG",
    "analytics_profile_scan_started": "ANALYTICS_PROFILE",
    "restore_policy_check_started": "BACKUP_ARCHIVE",
    "connector_config_read_started": "ACTIVE_DATA_FLOW",
    "message_scan_started": "SUPPORT_MESSAGE",
    "attachment_scan_started": "SUPPORT_ATTACHMENT",
}

def extract_json_details(record_text):
    """Extract details from JSON evidence, including timestamp-prefixed JSON."""

    if not isinstance(record_text, str):
        return {}

    # Find the beginning of the JSON object
    json_start = record_text.find("{")

    if json_start == -1:
        return {}

    try:
        data = json.loads(record_text[json_start:])
    except (json.JSONDecodeError, TypeError):
        return {}

    details = {}

    if isinstance(data, dict):
        details.update(data)

    return details


def normalize_category(category):
    category = (category or "").strip().upper()

    if category in SPECIAL_CATEGORIES:
        return SPECIAL_CATEGORIES[category]

    return category


def extract_log_field(text, field):
    if not isinstance(text, str):
        return ""

    # First, search for an ordinary log field.
    pattern = rf'\b{re.escape(field)}\s*=\s*"([^"]*)"'
    match = re.search(pattern, text)

    if match:
        return match.group(1)

    # Then search for an escaped field inside message="..."
    escaped_pattern = (
        rf'\b{re.escape(field)}\s*=\s*\\?"([^"\\]*)\\?"'
    )
    match = re.search(escaped_pattern, text)

    if match:
        return match.group(1)

    # Finally, search for an unquoted field.
    pattern = rf'\b{re.escape(field)}\s*=\s*([^\s|"]+)'
    match = re.search(pattern, text)

    return match.group(1) if match else ""




def infer_category(row, valid_categories):
    text = row.get("record_text", "")
    details = extract_json_details(text)

    # 1. Explicit category from CSV
    category = normalize_category(row.get("data_category"))

    if category in valid_categories:
        return category, "CSV_CATEGORY"

    # 2. Explicit category or record type from JSON/logs
    record_type = (
        details.get("data_category")
        or details.get("category")
        or details.get("record_type")
        or extract_log_field(text, "record_type")
    )

    category = normalize_category(record_type)

    if category in valid_categories:
        return category, "EXPLICIT_RECORD_TYPE"

    # 3. Pipe-separated evidence
    parts = [part.strip().lstrip("-").strip() for part in text.split("|")]

    if len(parts) >= 5:
        pipe_category = normalize_category(parts[3])

        if pipe_category in valid_categories:
            return pipe_category, "PIPE_RECORD"

    # 4. Extract resource ID
    resource_id = (
        row.get("resource_id")
        or details.get("resource_id")
        or extract_log_field(text, "resource_id")
        or ""
    )

    # 5. Collection name
    collection = details.get("collection_name", "")

    if collection in COLLECTION_MAP:
        return COLLECTION_MAP[collection], "COLLECTION_NAME"

    # 6. Identify support messages and attachments
    event = (
        details.get("event")
        or extract_log_field(text, "event")
        or ""
    ).lower()

    if resource_id.startswith("support_"):
        if "attachment" in event:
            return "SUPPORT_ATTACHMENT", "SUPPORT_ATTACHMENT_EVENT"

        if "message" in event:
            return "SUPPORT_MESSAGE", "SUPPORT_MESSAGE_EVENT"
    # 7. Map identifiable operational events
    if event in EVENT_CATEGORY_MAP:
        return EVENT_CATEGORY_MAP[event], "OPERATION_EVENT"


    # 8. Resource ID prefix
    for prefix, mapped_category in PREFIX_MAP.items():
        if resource_id.startswith(prefix):
            return mapped_category, "RESOURCE_PREFIX"

    # 9. Do not guess when evidence is insufficient
    return "", "UNRESOLVED"



def main():
    with open(RULES_FILE, newline="", encoding="utf-8-sig") as file:
        rules = list(csv.DictReader(file))

    rule_map = {
        rule["data_category"].strip(): rule["required_action"].strip()
        for rule in rules
    }

    valid_categories = set(rule_map) | set(SPECIAL_CATEGORIES.values())

    with open(EVIDENCE_FILE, newline="", encoding="utf-8-sig") as file:
        evidence_rows = list(csv.DictReader(file))

    results = []

    for row in evidence_rows:
        category, source = infer_category(row, valid_categories)

        action = rule_map.get(category, "")

        if category == "ACTIVE_DATA_FLOW":
            action = "SPECIAL_FLOW_CHECK"

        result = dict(row)
        result["mapped_category"] = category
        result["required_action"] = action
        result["mapping_source"] = source

        results.append(result)

    fieldnames = list(results[0].keys())

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print("\nSTAGE 3B COMPLETED")
    print("--------------------------")
    print(f"Evidence rows processed: {len(results)}")
    print(f"Mapped categories: {sum(bool(r['mapped_category']) for r in results)}")
    print(f"Unresolved records: {sum(r['mapping_source'] == 'UNRESOLVED' for r in results)}")

    print("\nCATEGORY SUMMARY")

    counts = {}

    for result in results:
        category = result["mapped_category"] or "UNRESOLVED"
        counts[category] = counts.get(category, 0) + 1

    for category, count in sorted(counts.items()):
        print(f"{category}: {count}")

    print(f"\nOutput saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()



