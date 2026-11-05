import csv
import json
from pathlib import Path
from collections import defaultdict

BASE = Path(__file__).resolve().parent.parent
DATA = BASE / "dataset"

REQUESTS = DATA / "deletion_requests.csv"
INVENTORY = BASE / "stage4a_resource_inventory.csv"
EVIDENCE = BASE / "stage3c_evidence_interpretation.csv"
ACTIVITY = DATA / "system_activity.csv"
RULES = DATA / "deletion_rules.csv"
OUTPUT = BASE / "output.csv"

PREFIX_CATEGORY = {
    "account_": "USER_PROFILE",
    "search_": "SEARCH_INDEX_ENTRY",
    "analytics_": "ANALYTICS_PROFILE",
    "support_": "SUPPORT_MESSAGE",
    "attachment_": "SUPPORT_ATTACHMENT",
    "export_": "USER_EXPORT",
    "data_flow_": "ACTIVE_DATA_FLOW",
    "backup_": "BACKUP_ARCHIVE",
    "audit_record_": "SECURITY_AUDIT_LOG",
    "tombstone_": "ACCOUNT_TOMBSTONE",
    "marketing_": "MARKETING_PROFILE",
    "delivery_": "EMAIL_DELIVERY_LOG",
    "cache_": "CACHE_ENTRY",
    "telemetry_": "PRODUCT_TELEMETRY",
}

POLICY = {
    "USER_PROFILE": ("ABSENT", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"),
    "SECONDARY_IDENTIFIER": ("ABSENT", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"),
    "SEARCH_INDEX_ENTRY": ("ABSENT", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"),
    "CACHE_ENTRY": ("ABSENT", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"),
    "SUPPORT_MESSAGE": ("REDACTED", "REDACT_RECORD", "VERIFY_RECORD_REDACTED"),
    "SUPPORT_ATTACHMENT": ("ABSENT", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"),
    "ANALYTICS_PROFILE": ("ANONYMIZED", "ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED"),
    "PRODUCT_TELEMETRY": ("ANONYMIZED", "ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED"),
    "USER_EXPORT": ("ABSENT", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"),
    "MARKETING_PROFILE": ("ABSENT", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"),
    "EMAIL_DELIVERY_LOG": ("REDACTED", "REDACT_RECORD", "VERIFY_RECORD_REDACTED"),
    "ACCOUNT_TOMBSTONE": ("REDACTED", "REDACT_RECORD", "VERIFY_RECORD_REDACTED"),
    "ACTIVE_DATA_FLOW": ("DISABLED", "DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED"),
    "BACKUP_ARCHIVE": ("BLOCKED", "BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED"),
    "SECURITY_AUDIT_LOG": ("PRESENT", "", "VERIFY_RECORD_PRESENT"),
    "LEGAL_HOLD_RECORD": ("PRESENT", "", "VERIFY_RECORD_PRESENT"),
}

FINDING_ORDER = {
    "REPORT_REMAINING_RECORD": 1,
    "REPORT_EXPOSED_PII": 2,
    "REPORT_ACTIVE_DATA_FLOW": 3,
    "REPORT_RESTORE_RISK": 4,
}

REMEDIATION_ORDER = {
    "DISABLE_DATA_FLOW": 1,
    "BLOCK_RESTORE": 2,
    "DELETE_RECORD": 3,
    "REDACT_RECORD": 4,
    "ANONYMIZE_RECORD": 5,
}


def read_csv(path):
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def split(value):
    return [x.strip() for x in (value or "").split(";") if x.strip()]


def category_for(resource, supplied=""):
    if supplied:
        return supplied.strip().upper()
    for prefix, category in PREFIX_CATEGORY.items():
        if resource.casefold().startswith(prefix):
            return category
    return ""


def system_for(resource, supplied, activities):
    if supplied and supplied not in {"deletion_worker", "LOGICAL_OR_UNSPECIFIED"}:
        return supplied

    candidates = []
    for event in activities:
        if event.get("resource_id") != resource:
            continue
        source = event.get("source_system", "").strip()
        target = event.get("target_system", "").strip()
        if target and target != "deletion_worker":
            candidates.append(target)
        elif source and source != "deletion_worker":
            candidates.append(source)

    return candidates[-1] if candidates else (supplied or "unknown_system")


def desired_step(category, state, system, resource, evidence_id, phase, operation, step_state):
    return {
        "step_no": 0,
        "phase": phase,
        "system_id": system,
        "resource_id": resource,
        "operation": operation,
        "state": step_state,
        "evidence_id": evidence_id,
    }


def main():
    requests = read_csv(REQUESTS)
    inventory = read_csv(INVENTORY)
    evidence = read_csv(EVIDENCE)
    activities = read_csv(ACTIVITY)
    rules = read_csv(RULES)

    allowed_categories = {r["data_category"].strip().upper() for r in rules}

    request_by_case = {r["case_id"]: r for r in requests}
    resources_by_case = defaultdict(dict)

    # Load inventory resources, preserving separate copies.
    for row in inventory:
        case = row["case_id"]
        resource = row["resource_id"].strip()
        if not case or not resource:
            continue

        category = category_for(
            resource,
            row.get("categories", "").split(";")[0]
        )

        if category not in allowed_categories:
            category = category_for(resource)

        resources_by_case[case][resource] = {
            "category": category,
            "system": row.get("system_id", ""),
            "states": [],
        }

    # Attach direct interpreted evidence to the matching resource.
    for row in evidence:
        case = row.get("case_id", "")
        resource = row.get("resource_id", "").strip()
        if not case or not resource or case not in request_by_case:
            continue

        captured = row.get("captured_at", "")
        audit_at = request_by_case[case].get("audit_at", "")
        if captured and audit_at and captured > audit_at:
            continue

        category = category_for(
            resource,
            row.get("mapped_category", "")
            or row.get("pipe_category", "")
            or row.get("data_category", "")
        )

        item = resources_by_case[case].setdefault(resource, {
            "category": category,
            "system": row.get("system_id") or row.get("pipe_system_id", ""),
            "states": [],
        })

        if not item["category"] and category:
            item["category"] = category

        state = row.get("interpreted_state", "").strip().upper()
        evidence_id = row.get("evidence_id", "").strip()
        record_text = row.get("record_text", "").casefold()
        effective_category = item["category"] or category

        # Recover obvious states when Stage 3C could not interpret the record.
        if not state and evidence_id:
            if effective_category == "SEARCH_INDEX_ENTRY":
                if '"email"' in record_text and "@" in record_text:
                    state = "PRESENT"

            elif effective_category == "SUPPORT_MESSAGE":
                if (
                    '"requester_email"' in record_text
                    or '"requester_phone"' in record_text
                    or '"requester_name"' in record_text
                    or ('"email"' in record_text and "@" in record_text)
                ):
                    state = "IDENTIFIABLE"

        # Dedented: runs for every category, not just support messages.
        if state and evidence_id:
            item["states"].append({
                "state": state,
                "evidence_id": evidence_id,
                "captured_at": captured,
                "system": row.get("system_id") or row.get("pipe_system_id", ""),
            })

    output_rows = []

    for case_id in sorted(request_by_case):
        request = request_by_case[case_id]
        resources = resources_by_case.get(case_id, {})
        findings = []
        remediations = []
        verifications = []
        uncertain = False

        # A request must actually have been made.
        request_text = request.get("request_text", "").casefold()
        if not request_text.strip():
            output_rows.append({
                "case_id": case_id,
                "deletion_status": "NOT_APPLICABLE",
                "steps_json": "[]",
            })
            continue

        for resource, item in resources.items():
            category = item["category"]
            if category not in POLICY:
                uncertain = True
                continue

            target_state, action, verify_operation = POLICY[category]

            # Use the latest direct state captured by the audit time.
            states = sorted(
                item["states"],
                key=lambda x: x["captured_at"]
            )
            latest = states[-1] if states else None

            system = system_for(
                resource, item["system"], activities
            )

            if latest:
                current_state = latest["state"]
                evidence_id = latest["evidence_id"]
                system = latest["system"] or system
            else:
                current_state = ""
                evidence_id = ""

            # Required retained records are verified, not deleted.
            
            if category in {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"}:
                verifications.append(desired_step(
                    category, current_state or "PRESENT", system, resource,
                    evidence_id, "VERIFICATION",
                    "VERIFY_RECORD_PRESENT", "PRESENT"
                ))
                continue

            # Direct evidence already proves the required final state.
            if current_state == target_state:
                verifications.append(desired_step(
                    category, current_state, system, resource,
                    evidence_id, "VERIFICATION",
                    verify_operation, target_state
                ))
                continue

            # Evidence shows a record or risk remains.
            if current_state in {"PRESENT", "IDENTIFIABLE", "ACTIVE"}:
                if category == "ACTIVE_DATA_FLOW":
                    finding_op = "REPORT_ACTIVE_DATA_FLOW"
                    finding_state = "ACTIVE"
                elif category == "BACKUP_ARCHIVE":
                    finding_op = "REPORT_RESTORE_RISK"
                    finding_state = "ACTIVE"
                elif current_state == "IDENTIFIABLE":
                    finding_op = "REPORT_EXPOSED_PII"
                    finding_state = "PRESENT"
                else:
                    finding_op = "REPORT_REMAINING_RECORD"
                    finding_state = "PRESENT"

                findings.append(desired_step(
                    category, current_state, system, resource,
                    evidence_id, "FINDING",
                    finding_op, finding_state
                ))

                if action:
                    remediations.append(desired_step(
                        category, current_state, system, resource,
                        "", "REMEDIATION", action, target_state
                    ))

                verifications.append(desired_step(
                    category, current_state, system, resource,
                    "", "VERIFICATION", verify_operation, target_state
                ))
                continue

                      # Unknown state: flag uncertainty, but do not invent
            # a finding, remediation, or successful verification.
            uncertain = True
            continue

        # No linked resources is also an unresolved audit, not automatic success.
        if not resources:
            uncertain = True

        steps = findings + remediations + verifications

        def sort_key(step):
            phase_order = {
                "FINDING": 1,
                "REMEDIATION": 2,
                "VERIFICATION": 3,
            }
            operation_order = (
                FINDING_ORDER if step["phase"] == "FINDING"
                else REMEDIATION_ORDER if step["phase"] == "REMEDIATION"
                else {}
            )
            return (
                phase_order[step["phase"]],
                operation_order.get(step["operation"], 99),
                step["system_id"],
                step["resource_id"],
            )

        steps.sort(key=sort_key)

        for number, step in enumerate(steps, start=1):
            step["step_no"] = number

        status = "INCOMPLETE" if uncertain or remediations else "COMPLETE"

        output_rows.append({
            "case_id": case_id,
            "deletion_status": status,
            "steps_json": json.dumps(steps, ensure_ascii=False),
        })

    with OUTPUT.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["case_id", "deletion_status", "steps_json"]
        )
        writer.writeheader()
        writer.writerows(output_rows)

    print("STAGE 4B COMPLETED")
    print("------------------")
    print("Requests:", len(requests))
    print("Output rows:", len(output_rows))
    print("Statuses:")
    for status in ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"):
        print(status, sum(r["deletion_status"] == status for r in output_rows))
    print("Saved:", OUTPUT)


if __name__ == "__main__":
    main()