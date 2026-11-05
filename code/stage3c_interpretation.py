
import csv
import json
import re
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_FILE = BASE_DIR / "stage3b_evidence_mapping.csv"
OUTPUT_FILE = BASE_DIR / "stage3c_evidence_interpretation.csv"


def extract_details(text):
    """Extract fields from JSON, nested JSON, key-value logs and pipe records."""

    details = {}

    if not isinstance(text, str):
        return details

    # 1. Parse JSON and extract nested dictionary fields
    json_start = text.find("{")

    if json_start != -1:
        try:
            data = json.loads(text[json_start:])

            if isinstance(data, dict):
                details.update(data)

                def flatten_dict(obj):
                    if not isinstance(obj, dict):
                        return

                    for key, value in obj.items():
                        if isinstance(value, dict):
                            flatten_dict(value)
                        elif not isinstance(value, list):
                            details.setdefault(key, value)

                flatten_dict(data)

        except (json.JSONDecodeError, TypeError):
            pass

    # 2. Extract key-value log fields
    fields = [
        "event",
        "resource_id",
        "system_id",
        "matched_value",
        "detector",
        "enabled",
        "scheduler_registered",
        "restore_blocked",
        "restore_access",
        "legal_hold",
        "status",
        "state",
        "result",
        "record_type",
        "collection_name",
        "email",
        "phone",
        "requester_email",
        "requester_phone",
        "requester_name",
        "subject_reference",
    ]

    for field in fields:

        if field in details:
            continue

        pattern = (
            rf'\b{field}\s*=\s*'
            rf'(?:"([^"]*)"|([^\s|]+))'
        )

        match = re.search(pattern, text)

        if match:
            details[field] = match.group(1) or match.group(2)

    # 3. Extract pipe-delimited records
    parts = [
        part.strip().lstrip("-").strip()
        for part in text.split("|")
    ]

    timestamp_pattern = r"\d{4}-\d{2}-\d{2}T"

    if len(parts) >= 5 and re.match(timestamp_pattern, parts[0]):

        details.setdefault("record_timestamp", parts[0])

        # New log format
        if parts[1].upper() in {"DEBUG", "INFO", "WARN", "ERROR"}:

            details.setdefault("pipe_system_id", parts[2])
            details.setdefault("pipe_trace_id", parts[3])
            details.setdefault("pipe_event", parts[4])

            details.setdefault(
                "pipe_resource_id",
                details.get("resource_id", "")
            )

            details.setdefault("pipe_category", "")

        # Older audit format
        else:

            details.setdefault("pipe_system_id", parts[1])
            details.setdefault("pipe_resource_id", parts[2])
            details.setdefault("pipe_category", parts[3])
            details.setdefault("pipe_state", parts[4])

    return details


def interpret_evidence(row):

    text = row.get("record_text", "")
    details = extract_details(text)

    if not isinstance(details, dict):
        details = {}

    event = str(
        details.get("event")
        or details.get("event_name")
        or details.get("pipe_event")
        or ""
    ).lower()

    matched_value = details.get("matched_value", "")
    detector = str(details.get("detector", "")).lower()

    signals = []
    interpretation = []

    # 1. Personal information detection
    identifier_fields = [
        "email",
        "phone",
        "requester_email",
        "requester_phone",
        "requester_name",
        "matched_value",
    ]

    has_identifier = any(
        str(details.get(field, "")).strip()
        for field in identifier_fields
    )

    subject_reference = str(
        details.get("subject_reference", "")
    ).strip()

    subject_is_email = (
        "@" in subject_reference
        and "." in subject_reference
    )

    if has_identifier or subject_is_email:

        signals.append("PII_DETECTED")

        interpretation.append(
            "A personal identifier is present in the evidence."
        )

    # 2. Active data flow indicators
    enabled = str(
        details.get("enabled", "")
    ).lower()

    scheduler = str(
        details.get("scheduler_registered", "")
    ).lower()

    if enabled == "true" and scheduler == "true":

        signals.append("ACTIVE_FLOW_INDICATOR")

        interpretation.append(
            "Data flow is enabled and scheduler is registered."
        )

    # 3. Restore risk
    restore_blocked = str(
        details.get("restore_blocked", "")
    ).lower()

    restore_access = str(
        details.get("restore_access", "")
    ).lower()

    if (
        restore_blocked == "false"
        or restore_access == "enabled"
    ):

        signals.append("RESTORE_RISK_INDICATOR")

        interpretation.append(
            "Restore access may still be available."
        )

    # 4. Legal hold
    legal_hold = str(
        details.get("legal_hold", "")
    ).lower()

    if legal_hold in ("true", "active"):

        signals.append("LEGAL_HOLD_INDICATOR")

        interpretation.append(
            "Evidence indicates an active legal hold."
        )

    # 5. Direct record-state evidence
    raw_state = (
        details.get("pipe_state")
        or details.get("state")
        or details.get("status")
        or details.get("result")
        or ""
    )

    raw_state = str(raw_state).strip().upper()

    state_map = {
        "NOT_FOUND": "ABSENT",
        "ABSENT": "ABSENT",
        "PRESENT": "PRESENT",
        "FOUND": "PRESENT",
        "REDACTED": "REDACTED",
        "ANONYMIZED": "ANONYMIZED",
        "DISABLED": "DISABLED",
        "BLOCKED": "BLOCKED",
        "ACTIVE": "ACTIVE",
        "IDENTIFIABLE": "IDENTIFIABLE",
    }

    interpreted_state = state_map.get(raw_state, "")

    if interpreted_state == "ACTIVE":

        if "ACTIVE_FLOW_INDICATOR" not in signals:
            signals.append("ACTIVE_FLOW_INDICATOR")

        interpretation.append(
            "The evidence records an active data flow."
        )

    elif interpreted_state == "IDENTIFIABLE":

        if "PII_DETECTED" not in signals:
            signals.append("PII_DETECTED")

        interpretation.append(
            "The evidence records a support message containing identifiable information."
        )

    elif interpreted_state:

        signals.append("DIRECT_STATE_EVIDENCE")

        interpretation.append(
            f"Evidence records the state as {interpreted_state}."
        )

    # 6. Operational events
    if event:

        if "OPERATIONAL_EVENT" not in signals:
            signals.append("OPERATIONAL_EVENT")

        interpretation.append(
            "An operation was recorded; this alone does not prove record state."
        )

    # 7. Unclassified records
    if not signals:

        signals.append("UNCLASSIFIED")

        interpretation.append(
            "Insufficient information for a reliable interpretation."
        )

    return {
        "interpreted_event": event,
        "interpreted_state": interpreted_state,
        "pipe_system_id": (details.get("pipe_system_id", "")
            or details.get("system_id")
            or details.get("origin_system", "")),
        "pipe_resource_id": (details.get("pipe_resource_id") or details.get("pipe_resource_id", "")),
        "pipe_category": details.get("pipe_category", ""),
        "evidence_signals": "|".join(signals),
        "interpretation": " ".join(interpretation),
    }


def main():

    with open(
        INPUT_FILE,
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as f:

        rows = list(csv.DictReader(f))

    output_rows = []

    for row in rows:

        result = interpret_evidence(row)

        output_rows.append({
            **row,
            **result
        })

    fieldnames = (
        list(output_rows[0].keys())
        if output_rows else []
    )

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8",
        newline=""
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(output_rows)

    print("\nSTAGE 3C COMPLETED")
    print("--------------------------")

    print(
        f"Evidence rows interpreted: {len(output_rows)}"
    )

    print(
        "PII detections:",
        sum(
            "PII_DETECTED" in r["evidence_signals"]
            for r in output_rows
        )
    )

    print(
        "Active flow indicators:",
        sum(
            "ACTIVE_FLOW_INDICATOR" in r["evidence_signals"]
            for r in output_rows
        )
    )

    print(
        "Restore risk indicators:",
        sum(
            "RESTORE_RISK_INDICATOR" in r["evidence_signals"]
            for r in output_rows
        )
    )

    print(
        "Direct state evidence:",
        sum(
            "DIRECT_STATE_EVIDENCE" in r["evidence_signals"]
            for r in output_rows
        )
    )

    print(
        "Operational events:",
        sum(
            "OPERATIONAL_EVENT" in r["evidence_signals"]
            for r in output_rows
        )
    )

    print(
        "Unclassified records:",
        sum(
            "UNCLASSIFIED" in r["evidence_signals"]
            for r in output_rows
        )
    )

    print(f"\nOutput saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
