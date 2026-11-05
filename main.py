"""Ghost Data Still Exists — dataset inspection starter.

Stage 1: safely load and validate the participant-facing dataset.
This stage deliberately does NOT generate predictions yet.
"""

from __future__ import annotations

import csv
import json
import re
import sqlite3
import subprocess
import tempfile
from functools import lru_cache
from collections import Counter
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DATASET_DIR = REPO_ROOT / "dataset"

EXPECTED_COLUMNS = {
    "deletion_requests.csv": [
        "case_id", "email", "requested_at", "reported_status",
        "reported_at", "audit_at", "request_text",
    ],
    "sample_deletion_requests.csv": [
        "case_id", "email", "requested_at", "reported_status",
        "reported_at", "audit_at", "request_text",
    ],
    "sample_output.csv": ["case_id", "deletion_status", "steps_json"],
    "user_identities.csv": [
        "user_id", "name", "email", "phone", "email_hash", "updated_at",
    ],
    "user_audit_log.csv": [
        "audit_id", "user_id", "event_time", "field_name",
        "old_value", "new_value",
    ],
    "system_activity.csv": [
        "activity_id", "event_time", "event_type", "source_system",
        "target_system", "resource_id", "reported_result", "details",
    ],
    "deletion_rules.csv": [
        "rule_id", "data_category", "condition", "required_action",
    ],
    "evidence_files.csv": ["file_id", "file_path", "origin", "captured_at"],
}


def read_csv(filename: str) -> list[dict[str, str]]:
    """Read one CSV file and return its rows as dictionaries."""
    path = DATASET_DIR / filename
    if not path.exists():
        raise FileNotFoundError(f"Required dataset file is missing: {path}")

    with path.open("r", encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)
        actual_columns = reader.fieldnames or []
        expected_columns = EXPECTED_COLUMNS.get(filename)
        if expected_columns and actual_columns != expected_columns:
            raise ValueError(
                f"Unexpected columns in {filename}. "
                f"Expected {expected_columns}, got {actual_columns}"
            )
        return list(reader)


def check_evidence_files(manifest: list[dict[str, str]]) -> tuple[int, list[str]]:
    """Check that every path listed in the evidence manifest exists."""
    missing: list[str] = []
    for item in manifest:
        evidence_path = DATASET_DIR / item["file_path"]
        if not evidence_path.is_file():
            missing.append(item["file_path"])
    return len(manifest) - len(missing), missing


def check_sample_output(rows: list[dict[str, str]]) -> tuple[Counter, int]:
    """Check sample statuses and confirm every steps_json value is valid JSON."""
    status_counts: Counter = Counter()
    invalid_json = 0
    for row in rows:
        status_counts[row["deletion_status"]] += 1
        try:
            steps: Any = json.loads(row["steps_json"])
            if not isinstance(steps, list):
                invalid_json += 1
        except json.JSONDecodeError:
            invalid_json += 1
    return status_counts, invalid_json


def normalize_email(email: str) -> str:
    """Normalize email text so uppercase/lowercase differences do not matter."""
    return email.strip().casefold()


def build_email_lookup(
    identities: list[dict[str, str]],
    audit_log: list[dict[str, str]],
) -> dict[str, set[str]]:
    """Map every known current or historical email address to its user_id."""
    email_to_users: dict[str, set[str]] = {}

    def add_email(email: str, user_id: str) -> None:
        normalized = normalize_email(email)
        if normalized:
            email_to_users.setdefault(normalized, set()).add(user_id)

    # Current email addresses.
    for identity in identities:
        add_email(identity["email"], identity["user_id"])

    # Old and new email addresses recorded in the identity-change history.
    for event in audit_log:
        if event["field_name"] == "email":
            add_email(event["old_value"], event["user_id"])
            add_email(event["new_value"], event["user_id"])

    return email_to_users


def resolve_user_id(email: str, email_lookup: dict[str, set[str]]) -> str | None:
    """Return a user_id only when the email maps to exactly one person."""
    matches = email_lookup.get(normalize_email(email), set())
    if len(matches) == 1:
        return next(iter(matches))
    return None



def normalize_phone(value: str) -> str:
    """Keep digits only so phone formatting differences do not matter."""
    return "".join(ch for ch in value if ch.isdigit())


def build_user_tokens(
    identities: list[dict[str, str]],
    audit_log: list[dict[str, str]],
) -> dict[str, set[str]]:
    """Map strong identity values (ID, email, phone, hash) to user IDs."""
    token_to_users: dict[str, set[str]] = {}

    def add(token: str, user_id: str, kind: str) -> None:
        token = token.strip()
        if kind == "email":
            token = normalize_email(token)
        elif kind == "phone":
            token = normalize_phone(token)
        else:
            token = token.casefold()
        # Ignore short phone fragments; they are too likely to match by accident.
        if token and (kind != "phone" or len(token) >= 8):
            token_to_users.setdefault(token, set()).add(user_id)

    for row in identities:
        uid = row["user_id"]
        add(uid, uid, "id")
        add(row.get("email", ""), uid, "email")
        add(row.get("phone", ""), uid, "phone")
        add(row.get("email_hash", ""), uid, "hash")

    for event in audit_log:
        uid = event["user_id"]
        field = event["field_name"].strip().casefold()
        kind = {"email": "email", "phone": "phone", "email_hash": "hash"}.get(field)
        if kind:
            add(event["old_value"], uid, kind)
            add(event["new_value"], uid, kind)
    return token_to_users


def iter_evidence_chunks(path: Path):
    """Yield small evidence records so unrelated customers in one file stay separate."""
    suffix = path.suffix.casefold()
    if suffix == ".json":
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return

        def walk(value):
            if isinstance(value, dict):
                yield json.dumps(value, ensure_ascii=False, default=str)
                for child in value.values():
                    if isinstance(child, (dict, list)):
                        yield from walk(child)
            elif isinstance(value, list):
                for child in value:
                    if isinstance(child, (dict, list)):
                        yield from walk(child)
        yield from walk(data)
    elif suffix in {".log", ".sql", ".txt"}:
        try:
            with path.open("r", encoding="utf-8-sig", errors="replace") as file:
                for line in file:
                    if line.strip():
                        yield line.strip()
        except OSError:
            return
    # PDFs and images are intentionally not guessed or treated as empty evidence.
    # They are listed separately for later OCR / document extraction.


@lru_cache(maxsize=4)
def _compile_identity_patterns(tokens: tuple[str, ...]):
    """Compile lookup patterns once; this keeps evidence scanning fast."""
    text_tokens = [t for t in tokens if not t.isdigit()]
    phone_tokens = [t for t in tokens if t.isdigit() and len(t) >= 8]
    text_pattern = (
        re.compile(r"(?<![A-Za-z0-9_])(?:" + "|".join(re.escape(t) for t in sorted(text_tokens, key=len, reverse=True)) + r")(?![A-Za-z0-9_])", re.IGNORECASE)
        if text_tokens else None
    )
    phone_pattern = (
        re.compile(r"(?<![0-9])(?:" + "|".join(re.escape(t) for t in sorted(phone_tokens, key=len, reverse=True)) + r")(?![0-9])")
        if phone_tokens else None
    )
    return text_pattern, phone_pattern


def find_identity_tokens_in_chunk(
    chunk: str, token_to_users: dict[str, set[str]]
) -> set[str]:
    """Return users whose complete strong identifier appears in this chunk.

    A simple exact-token scan avoids a very large regular-expression alternation
    when OCR context windows contain several lines of text.
    """
    found: set[str] = set()
    lowered = chunk.casefold()
    digits = normalize_phone(chunk)
    for token, users in token_to_users.items():
        normalized = token.casefold()
        if normalized.isdigit() and len(normalized) >= 8:
            if normalized in digits:
                found.update(users)
            continue
        start = lowered.find(normalized)
        while start != -1:
            end = start + len(normalized)
            before_ok = start == 0 or not (lowered[start - 1].isalnum() or lowered[start - 1] == "_")
            after_ok = end == len(lowered) or not (lowered[end].isalnum() or lowered[end] == "_")
            if before_ok and after_ok:
                found.update(users)
                break
            start = lowered.find(normalized, start + 1)
    return found


def extract_resource_ids(chunk: str) -> set[str]:
    """Find dataset-style resource identifiers inside one evidence record."""
    found = set(re.findall(r"\b[a-z][a-z0-9]*_[0-9]+\b", chunk, flags=re.IGNORECASE))
    # These are identifiers for the dataset/workflow itself, not customer resources.
    non_resource_prefixes = ("user_", "activity_", "evidence_", "case_", "rule_")
    return {value for value in found if not value.casefold().startswith(non_resource_prefixes)}


def build_evidence_resource_index(
    manifest: list[dict[str, str]],
    token_to_users: dict[str, set[str]],
) -> tuple[dict[str, dict[str, set[str]]], int]:
    """Map each user and evidence file to resource IDs found in matching records."""
    user_index: dict[str, dict[str, set[str]]] = {}
    unreadable_or_visual = 0
    for item in manifest:
        path = DATASET_DIR / item["file_path"]
        if path.suffix.casefold() not in {".json", ".log", ".sql", ".txt"}:
            unreadable_or_visual += 1
            continue
        for chunk in iter_evidence_chunks(path):
            users = find_identity_tokens_in_chunk(chunk, token_to_users)
            resources = extract_resource_ids(chunk)
            if not users or not resources:
                continue
            for uid in users:
                user_index.setdefault(uid, {}).setdefault(item["file_id"], set()).update(resources)
    return user_index, unreadable_or_visual


def build_activity_resource_index(
    activity: list[dict[str, str]],
    token_to_users: dict[str, set[str]],
) -> tuple[dict[str, list[tuple[str, str, str]]], dict[str, set[str]]]:
    """Index explicit identity-link events separately from other resource activity."""
    user_links: dict[str, list[tuple[str, str, str]]] = {}
    resource_to_activity: dict[str, set[str]] = {}
    for event in activity:
        resource = event["resource_id"].strip()
        if not resource:
            continue
        resource_to_activity.setdefault(resource, set()).add(event["activity_id"])
        if event["event_type"] == "LINK_RESOURCE_IDENTITY":
            users = find_identity_tokens_in_chunk(event["details"], token_to_users)
            for uid in users:
                user_links.setdefault(uid, []).append(
                    (resource, event["event_time"], event["activity_id"])
                )
    return user_links, resource_to_activity


def run_stage_2b(
    requests: list[dict[str, str]],
    identities: list[dict[str, str]],
    audit_log: list[dict[str, str]],
    activity: list[dict[str, str]],
    manifest: list[dict[str, str]],
) -> None:
    """Build an evidence-backed candidate inventory; do not decide deletion status."""
    token_to_users = build_user_tokens(identities, audit_log)
    evidence_index, skipped_visual = build_evidence_resource_index(manifest, token_to_users)
    user_links, resource_to_activity = build_activity_resource_index(activity, token_to_users)

    evidence_time = {item["file_id"]: item["captured_at"] for item in manifest}
    activity_by_id = {item["activity_id"]: item for item in activity}
    identity_email_to_users = build_email_lookup(identities, audit_log)

    matched_cases = 0
    cases_with_resources = 0
    total_resources = 0
    total_evidence_links = 0
    total_activity_links = 0
    unresolved_cases: list[str] = []
    link_rows: list[dict[str, str]] = []

    for request in requests:
        case_id = request["case_id"]
        matches = identity_email_to_users.get(normalize_email(request["email"]), set())
        if len(matches) != 1:
            unresolved_cases.append(case_id)
            continue
        matched_cases += 1
        uid = next(iter(matches))
        cutoff = request["audit_at"]

        resources: set[str] = set()
        evidence_ids: set[str] = set()
        activity_ids: set[str] = set()
        evidence_by_resource: dict[str, set[str]] = {}
        activity_by_resource: dict[str, set[str]] = {}

        # Evidence must have been captured by this case's audit time.
        for evidence_id, found_resources in evidence_index.get(uid, {}).items():
            if evidence_time.get(evidence_id, "") <= cutoff:
                evidence_ids.add(evidence_id)
                resources.update(found_resources)
                for resource in found_resources:
                    evidence_by_resource.setdefault(resource, set()).add(evidence_id)

        # Only explicit identity links that existed by audit_at can add resources.
        for resource, event_time, link_activity_id in user_links.get(uid, []):
            if event_time <= cutoff:
                resources.add(resource)
                activity_ids.add(link_activity_id)
                activity_by_resource.setdefault(resource, set()).add(link_activity_id)

        # Attach earlier activity for the resources already linked to this user.
        for resource in resources:
            for activity_id in resource_to_activity.get(resource, set()):
                event = activity_by_id.get(activity_id, {})
                if event.get("event_time", "") <= cutoff:
                    activity_ids.add(activity_id)
                    activity_by_resource.setdefault(resource, set()).add(activity_id)

        for resource in sorted(resources):
            related_activity_ids = sorted(activity_by_resource.get(resource, set()))
            related_systems = set()
            for activity_id in related_activity_ids:
                event = activity_by_id.get(activity_id, {})
                if event.get("source_system"):
                    related_systems.add(event["source_system"])
                if event.get("target_system"):
                    related_systems.add(event["target_system"])
            link_rows.append({
                "case_id": case_id,
                "user_id": uid,
                "resource_id": resource,
                "system_ids": ";".join(sorted(related_systems)),
                "evidence_ids": ";".join(sorted(evidence_by_resource.get(resource, set()))),
                "activity_ids": ";".join(related_activity_ids),
            })

        if resources:
            cases_with_resources += 1
        total_resources += len(resources)
        total_evidence_links += len(evidence_ids)
        total_activity_links += len(activity_ids)

    index_path = REPO_ROOT / "resource_evidence_index.csv"
    with index_path.open("w", encoding="utf-8", newline="") as file:
        fieldnames = ["case_id", "user_id", "resource_id", "system_ids", "evidence_ids", "activity_ids"]
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(link_rows)

    print("\nSTAGE 2B — RESOURCE AND EVIDENCE LINKING")
    print(f"Requests resolved to one user:            {matched_cases}/{len(requests)}")
    print(f"Cases with candidate resources:            {cases_with_resources}")
    print(f"Distinct case-resource links:               {total_resources}")
    print(f"Case-evidence links (within audit time):    {total_evidence_links}")
    print(f"Related activity links (within audit time): {total_activity_links}")
    print(f"PDF/image evidence needing extraction:      {skipped_visual}")
    print(f"Intermediate index saved to:              {index_path.name} ({len(link_rows)} rows)")
    print("Note: these are candidate links, not proof of deletion or retention.")
    if unresolved_cases:
        print("Unresolved case IDs:", ", ".join(unresolved_cases[:10]))



# ---------------------------------------------------------------------------
# STAGE 2C — EXTRACT AND NORMALIZE THE ACTUAL EVIDENCE
# ---------------------------------------------------------------------------

RESOURCE_PATTERN = re.compile(r"\b[a-z][a-z0-9]*_[0-9]+\b", re.IGNORECASE)
NON_RESOURCE_PREFIXES = ("user_", "activity_", "evidence_", "case_", "rule_")


def _json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def _find_resource_ids(value: Any) -> set[str]:
    """Find resource-like IDs in a structured evidence record."""
    text = _json_dumps(value)
    return {
        item for item in RESOURCE_PATTERN.findall(text)
        if not item.casefold().startswith(NON_RESOURCE_PREFIXES)
    }


def _walk_json_records(value: Any, context: dict[str, str] | None = None):
    """Yield record-sized dictionaries, carrying snapshot system/time context."""
    context = dict(context or {})
    if isinstance(value, dict):
        local = dict(context)
        for key in ("captured_at", "data_store", "system", "collection", "origin", "source"):
            val = value.get(key)
            if isinstance(val, (str, int, float)):
                local[key] = str(val)
        # A record is a dictionary with an explicit resource_id, or a leaf-like
        # dictionary inside a records collection.
        if value.get("resource_id"):
            yield value, local
        for key, child in value.items():
            if isinstance(child, (dict, list)):
                child_context = dict(local)
                if key in {"records", "snapshots"}:
                    child_context["_container"] = key
                yield from _walk_json_records(child, child_context)
    elif isinstance(value, list):
        for child in value:
            if isinstance(child, (dict, list)):
                yield from _walk_json_records(child, context)


def _read_json_evidence(path: Path):
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return
    seen = set()
    for record, context in _walk_json_records(data):
        signature = _json_dumps(record)
        if signature in seen:
            continue
        seen.add(signature)
        yield record, context, signature


def _read_sql_evidence(path: Path):
    """Read SQLite-compatible snapshot tables without changing source files."""
    connection = sqlite3.connect(":memory:")
    try:
        script = path.read_text(encoding="utf-8-sig", errors="replace")
        connection.executescript(script)
        table_rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
        for (table_name,) in table_rows:
            # Ignore SQLite internal tables.
            if table_name.startswith("sqlite_"):
                continue
            safe_name = table_name.replace('"', '""')
            cursor = connection.execute(f'SELECT * FROM "{safe_name}"')
            columns = [item[0] for item in cursor.description or []]
            for values in cursor.fetchall():
                row = dict(zip(columns, values))
                normalized = {}
                for key, value in row.items():
                    if isinstance(value, str):
                        try:
                            parsed = json.loads(value)
                            normalized[key] = parsed
                        except (json.JSONDecodeError, TypeError):
                            normalized[key] = value
                    else:
                        normalized[key] = value
                # SQL snapshot rows commonly wrap the actual customer record
                # inside record_json. Keep the wrapper metadata as context.
                record = normalized.get("record_json")
                if isinstance(record, dict):
                    context = {
                        "system": str(normalized.get("origin_system", "")),
                        "collection": str(normalized.get("collection_name", table_name)),
                        "captured_at": str(normalized.get("updated_at", "")),
                        "sql_table": table_name,
                    }
                    yield record, context, _json_dumps({"table": table_name, "row": normalized}), "sql"
                else:
                    context = {"sql_table": table_name}
                    yield normalized, context, _json_dumps(normalized), "sql"
    finally:
        connection.close()


def _read_text_lines(path: Path):
    try:
        with path.open("r", encoding="utf-8-sig", errors="replace") as file:
            for line in file:
                line = line.strip()
                if line:
                    yield line, {}
    except OSError:
        return


def _extract_pdf_text(path: Path) -> tuple[str, str]:
    """Return (text, method); use pdftotext, then optional pypdf fallback."""
    try:
        result = subprocess.run(
            ["pdftotext", "-layout", str(path), "-"],
            capture_output=True, text=True, timeout=45, check=False,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout, "pdftotext"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    try:
        from pypdf import PdfReader  # optional dependency
        reader = PdfReader(str(path))
        return "\n".join(page.extract_text() or "" for page in reader.pages), "pypdf"
    except Exception:
        return "", "unavailable"


def _extract_image_text(path: Path) -> tuple[str, str]:
    """OCR an evidence image with the local Tesseract executable."""
    try:
        result = subprocess.run(
            ["tesseract", str(path), "stdout"],
            capture_output=True, text=True, timeout=45, check=False,
        )
        if result.returncode == 0:
            return result.stdout, "tesseract"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return "", "unavailable"


def _record_identity_matches(text: str, token_to_users: dict[str, set[str]]) -> set[str]:
    return find_identity_tokens_in_chunk(text, token_to_users)


def _extract_manifest_item(item: dict[str, str]):
    """Yield normalized evidence units for one manifest entry."""
    path = DATASET_DIR / item["file_path"]
    suffix = path.suffix.casefold()
    if suffix == ".json":
        for record, context, raw in _read_json_evidence(path) or []:
            yield record, context, raw, "json"
    elif suffix == ".sql":
        try:
            yield from _read_sql_evidence(path)
        except (sqlite3.Error, OSError, UnicodeError) as exc:
            yield {"extraction_error": str(exc)}, {"sql_file": path.name}, str(exc), "sql_error"
    elif suffix in {".log", ".txt"}:
        for line, context in _read_text_lines(path):
            yield {"line": line}, context, line, "text"
    elif suffix == ".pdf":
        text_value, method = _extract_pdf_text(path)
        if text_value.strip():
            # Keep page/document text together; splitting is performed by line
            # so identity-bearing sections remain individually searchable.
            lines = [line.strip() for line in text_value.splitlines() if line.strip()]
            for index, line in enumerate(lines):
                # A few neighbouring lines preserve labels/IDs that PDFs often
                # place on separate lines, without merging the whole document.
                start = max(0, index - 2)
                end = min(len(lines), index + 3)
                window = " | ".join(lines[start:end])
                yield {"text": window}, {"extraction_method": method, "identity_text": line}, window, "pdf"
        else:
            yield {"extraction_error": "PDF text extraction unavailable"}, {"extraction_method": method}, "", "pdf_error"
    elif suffix in {".png", ".jpg", ".jpeg", ".tif", ".tiff"}:
        text_value, method = _extract_image_text(path)
        if text_value.strip():
            lines = [line.strip() for line in text_value.splitlines() if line.strip()]
            for index, line in enumerate(lines):
                start = max(0, index - 2)
                end = min(len(lines), index + 3)
                window = " | ".join(lines[start:end])
                yield {"text": window}, {"extraction_method": method, "identity_text": line}, window, "image_ocr"
        else:
            yield {"extraction_error": "Image OCR unavailable"}, {"extraction_method": method}, "", "image_error"
    else:
        yield {"extraction_error": f"Unsupported evidence type: {suffix}"}, {}, "", "unsupported"


def _guess_system(context: dict[str, str], record: Any, text_value: str) -> str:
    for key in ("data_store", "system", "origin_system", "source"):
        value = context.get(key)
        if value:
            return value
    if isinstance(record, dict):
        for key in ("origin_system", "system", "service", "function", "data_store"):
            value = record.get(key)
            if isinstance(value, str) and value:
                return value
    match = re.search(r"\b(?:service|function)=([A-Za-z0-9_.-]+)", text_value)
    if match:
        return match.group(1)
    match = re.search(r"\[[A-Z]+\]\s+\[([A-Za-z0-9_.-]+)\]", text_value)
    return match.group(1) if match else ""


def _guess_category(context: dict[str, str], record: Any) -> str:
    """Map common evidence collection/resource names to policy categories."""
    if isinstance(record, dict):
        explicit = record.get("data_category", record.get("category"))
        if isinstance(explicit, str) and explicit.strip():
            return explicit.strip().upper()
    collection = context.get("collection", "")
    if not collection and isinstance(record, dict):
        collection = str(record.get("record_type", record.get("collection", "")))
    key = collection.casefold()
    collection_map = {
        "customer_profiles": "USER_PROFILE",
        "customer_search_documents": "SEARCH_INDEX_ENTRY",
        "customer_analytics_reports": "ANALYTICS_PROFILE",
        "customer_analytics_profiles": "ANALYTICS_PROFILE",
        "support_conversations": "SUPPORT_MESSAGE",
        "support_attachments": "SUPPORT_ATTACHMENT",
        "customer_exports": "USER_EXPORT",
        "connector_configurations": "ACTIVE_DATA_FLOW",
        "backup_restore_entries": "BACKUP_ARCHIVE",
        "security_audit_events": "SECURITY_AUDIT_LOG",
        "account_tombstones": "ACCOUNT_TOMBSTONE",
        "marketing_profiles": "MARKETING_PROFILE",
        "email_delivery_logs": "EMAIL_DELIVERY_LOG",
        "cache_entries": "CACHE_ENTRY",
        "product_telemetry": "PRODUCT_TELEMETRY",
    }
    if key in collection_map:
        return collection_map[key]
    resource = str(record.get("resource_id", "")).casefold() if isinstance(record, dict) else ""
    prefix_map = {
        "account_": "USER_PROFILE", "search_": "SEARCH_INDEX_ENTRY",
        "analytics_": "ANALYTICS_PROFILE", "support_": "SUPPORT_MESSAGE",
        "attachment_": "SUPPORT_ATTACHMENT", "export_": "USER_EXPORT",
        "data_flow_": "ACTIVE_DATA_FLOW", "backup_": "BACKUP_ARCHIVE",
        "audit_record_": "SECURITY_AUDIT_LOG", "tombstone_": "ACCOUNT_TOMBSTONE",
        "marketing_": "MARKETING_PROFILE", "delivery_": "EMAIL_DELIVERY_LOG",
        "cache_": "CACHE_ENTRY", "telemetry_": "PRODUCT_TELEMETRY",
    }
    for prefix, category in prefix_map.items():
        if resource.startswith(prefix):
            return category
    return key.upper()


def run_stage_2c(
    requests: list[dict[str, str]],
    identities: list[dict[str, str]],
    audit_log: list[dict[str, str]],
    manifest: list[dict[str, str]],
) -> None:
    """Extract evidence from every format and link identity-bearing units to cases."""
    token_to_users = build_user_tokens(identities, audit_log)
    email_lookup = build_email_lookup(identities, audit_log)
    evidence_rows: list[dict[str, str]] = []
    case_rows: list[dict[str, str]] = []
    errors: Counter = Counter()
    matched_units = 0
    total_units = 0
    requests_by_user: dict[str, list[dict[str, str]]] = {}
    for request in requests:
        resolved_users = email_lookup.get(normalize_email(request["email"]), set())
        if len(resolved_users) == 1:
            requests_by_user.setdefault(next(iter(resolved_users)), []).append(request)

    # Keep one record per extracted unit. For SQL/JSON, the whole structured
    # record is preserved; for logs/PDFs/images, each non-empty line is a unit.
    for item in manifest:
        evidence_id = item["file_id"]
        captured_at = item["captured_at"]
        for record, context, raw, evidence_type in _extract_manifest_item(item):
            total_units += 1
            if evidence_type.endswith("_error") or evidence_type == "unsupported":
                errors[evidence_type] += 1
            searchable = raw if raw else _json_dumps(record)
            users = _record_identity_matches(context.get("identity_text", searchable), token_to_users)
            resource_ids = _find_resource_ids(record)
            if not resource_ids:
                resource_ids = _find_resource_ids(searchable)
            resource_id = sorted(resource_ids)[0] if len(resource_ids) == 1 else ""
            system_id = _guess_system(context, record, searchable)
            category = _guess_category(context, record)
            matched_user_ids = ";".join(sorted(users))
            if users:
                matched_units += 1
            evidence_rows.append({
                "evidence_id": evidence_id,
                "captured_at": captured_at,
                "evidence_type": evidence_type,
                "system_id": system_id,
                "resource_id": resource_id,
                "resource_ids": ";".join(sorted(resource_ids)),
                "data_category": category,
                "matched_user_ids": matched_user_ids,
                "record_text": searchable[:12000],
            })

            # Attach each matched evidence unit to every request for that user,
            # but only when the evidence existed by that request's audit time.
            for matched_user_id in users:
                for request in requests_by_user.get(matched_user_id, []):
                    if captured_at and captured_at > request["audit_at"]:
                        continue
                    case_rows.append({
                    "case_id": request["case_id"],
                    "user_id": matched_user_id,
                    "evidence_id": evidence_id,
                    "captured_at": captured_at,
                    "evidence_type": evidence_type,
                    "system_id": system_id,
                    "resource_id": resource_id,
                    "resource_ids": ";".join(sorted(resource_ids)),
                    "data_category": category,
                    "record_text": searchable[:12000],
                    })

    evidence_path = REPO_ROOT / "evidence_extraction.csv"
    case_path = REPO_ROOT / "case_evidence_index.csv"
    evidence_fields = [
        "evidence_id", "captured_at", "evidence_type", "system_id",
        "resource_id", "resource_ids", "data_category", "matched_user_ids", "record_text",
    ]
    case_fields = [
        "case_id", "user_id", "evidence_id", "captured_at", "evidence_type",
        "system_id", "resource_id", "resource_ids", "data_category", "record_text",
    ]
    for output_path, fields, rows in (
        (evidence_path, evidence_fields, evidence_rows),
        (case_path, case_fields, case_rows),
    ):
        with output_path.open("w", encoding="utf-8", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)

    print("\nSTAGE 2C — EVIDENCE EXTRACTION")
    print(f"Evidence units extracted:                 {total_units}")
    print(f"Units matching known user identifiers:    {matched_units}")
    print(f"Case-to-evidence links (within audit_at):  {len(case_rows)}")
    print(f"Evidence extraction errors:               {sum(errors.values())}")
    for kind, count in sorted(errors.items()):
        print(f"  {kind}: {count}")
    print(f"Full extraction saved to:                 {evidence_path.name}")
    print(f"Case evidence index saved to:              {case_path.name}")
    print("Note: extracted matches are evidence candidates, not final deletion decisions.")

def main() -> None:
    print("\nGHOST DATA STILL EXISTS — DATASET CHECK")
    print("=" * 48)
    data: dict[str, list[dict[str, str]]] = {}
    for filename in EXPECTED_COLUMNS:
        data[filename] = read_csv(filename)
        print(f"{filename:32} {len(data[filename]):>5} rows")

    requests = data["deletion_requests.csv"]
    sample_requests = data["sample_deletion_requests.csv"]
    sample_output = data["sample_output.csv"]
    manifest = data["evidence_files.csv"]

    found, missing = check_evidence_files(manifest)
    print("\nEVIDENCE FILE CHECK")
    print(f"Files listed in manifest: {len(manifest)}")
    print(f"Files found:              {found}")
    print(f"Files missing:            {len(missing)}")
    for path in missing:
        print(f"  MISSING: {path}")

    status_counts, invalid_json = check_sample_output(sample_output)
    print("\nPUBLIC SAMPLE ANSWERS")
    for status, count in sorted(status_counts.items()):
        print(f"{status:18} {count:>3}")
    print(f"Invalid steps_json values: {invalid_json}")

    request_ids = [row["case_id"] for row in requests]
    sample_ids = [row["case_id"] for row in sample_requests]
    output_ids = [row["case_id"] for row in sample_output]
    print("\nBASIC CONSISTENCY CHECKS")
    print(f"Unique full request IDs:       {len(set(request_ids)) == len(request_ids)}")
    print(f"Unique sample IDs:             {len(set(sample_ids)) == len(sample_ids)}")
    print(f"Sample input/output IDs match: {set(sample_ids) == set(output_ids)}")
    print(f"Full request count is 518:     {len(requests) == 518}")

    # Stage 2A: resolve each request email to one user_id using current and
    # historical email addresses. Ambiguous matches are deliberately not guessed.
    identities = data["user_identities.csv"]
    audit_log = data["user_audit_log.csv"]
    email_lookup = build_email_lookup(identities, audit_log)
    resolved = 0
    unresolved: list[str] = []
    ambiguous: list[str] = []
    for request in requests:
        matches = email_lookup.get(normalize_email(request["email"]), set())
        if len(matches) == 1:
            resolved += 1
        elif len(matches) == 0:
            unresolved.append(request["case_id"])
        else:
            ambiguous.append(request["case_id"])

    print("\nSTAGE 2A — IDENTITY RESOLUTION")
    print(f"Requests resolved to exactly one user: {resolved}/{len(requests)}")
    print(f"Unresolved requests:                 {len(unresolved)}")
    print(f"Ambiguous requests:                  {len(ambiguous)}")
    if unresolved:
        print("Unresolved case IDs:", ", ".join(unresolved[:10]))
    if ambiguous:
        print("Ambiguous case IDs:", ", ".join(ambiguous[:10]))

    run_stage_2b(
        requests, identities, audit_log, data["system_activity.csv"], manifest
    )
    run_stage_2c(requests, identities, audit_log, manifest)
    print("\nNo deletion-status predictions have been generated in Stage 2C.\n")


if __name__ == "__main__":
    main()
