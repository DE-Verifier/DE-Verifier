import argparse
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


def _parse_timestamp(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value)


@dataclass
class Event:
    timestamp: datetime
    principal_id: str
    principal_type: str
    action_service: str
    action_operation: str
    resource_id: Optional[str]
    raw: Dict


SENSITIVE_SERVICE_KEYWORDS: Dict[str, Tuple[str, ...]] = {
    # Data storage & package distribution
    "storage": ("storage.",),
    "artifactregistry": ("artifactregistry",),
    # AI document & inference outputs
    "documentai": ("documentai", "documentprocessor"),
    # Analytics / data warehouse
    "bigquery": ("bigquery", "tabledata", "dataset"),
    # Secrets and encryption material
    "secretmanager": ("secretmanager",),
    "cloudkms": ("cloudkms", ".kms."),
    # Messaging / streaming
    "pubsub": ("pubsub",),
    # Database platforms
    "sqladmin": ("sqladmin", "cloudsql"),
    "spanner": ("spanner",),
    "bigtableadmin": ("bigtable",),
    # AI Platform model artifacts
    "aiplatform": ("aiplatform", "modelservice", "endpointservice"),
}


def _load_events(path: Path) -> List[Event]:
    events: List[Event] = []
    with open(path, "rt", encoding="utf-8") as handle:
        for line_no, raw in enumerate(handle, start=1):
            stripped = raw.strip()
            if not stripped:
                continue
            try:
                data = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"Line {line_no}: invalid JSON -> {exc}") from exc

            timestamp_str = data.get("timestamp")
            if not timestamp_str:
                continue

            principal = data.get("principal") or {}
            action = data.get("action") or {}
            resources = data.get("resources") or []
            resource_id = None
            if isinstance(resources, list) and resources:
                first = resources[0]
                if isinstance(first, dict):
                    resource_id = first.get("id")

            events.append(
                Event(
                    timestamp=_parse_timestamp(timestamp_str),
                    principal_id=str(principal.get("id", "unknown")),
                    principal_type=str(principal.get("type", "unknown")),
                    action_service=str(action.get("service", "unknown")),
                    action_operation=str(action.get("operation", "unknown")),
                    resource_id=resource_id,
                    raw=data,
                )
            )
    events.sort(key=lambda evt: evt.timestamp)
    return events


def _is_sensitive_agent_action(event: Event) -> bool:
    """
    Returns True if the agent action should be evaluated for confused deputy evidence.
    Checks a curated set of resource services commonly used to handle user data.
    """
    service = (event.action_service or "").lower()
    operation = (event.action_operation or "").lower()

    if not service or not operation:
        return False

    if "create" in operation:
        return False

    keywords = SENSITIVE_SERVICE_KEYWORDS.get(service)
    if not keywords:
        return False

    return any(keyword in operation for keyword in keywords)
    return False


def detect_confused_deputy(events: Iterable[Event]) -> Optional[Tuple[Event, str]]:
    """
    Simple heuristic detector:
      - Track resources that have been directly accessed by a user (principal_type == 'user').
      - If a service account performs a storage.* action on a resource the user never accessed,
        flag as missing authorization proof.
    Returns tuple of offending event and caller id when vulnerability is found.
    """
    events = list(events)

    first_user_event = next(
        (evt for evt in events if evt.principal_type == "user"),
        None,
    )
    if not first_user_event or first_user_event.raw.get("status") != "success":
        return None

    seen_resources: Dict[str, str] = {}
    last_user_id = "unknown"

    for event in events:
        if event.principal_type == "user":
            if event.raw.get("status") == "success":
                last_user_id = event.principal_id
            if event.resource_id and event.raw.get("status") == "success":
                seen_resources[event.resource_id] = event.principal_id
            continue

        if (
            event.principal_type == "service_account"
            and event.resource_id
            and event.raw.get("status") == "success"
            and _is_sensitive_agent_action(event)
            and event.principal_id.endswith(".iam.gserviceaccount.com")
        ):
            if event.resource_id not in seen_resources:
                caller = last_user_id
                return event, caller
    return None


def format_report(event: Event, caller_id: str) -> str:
    lines = [
        "(1) VULNERABILITY FOUND: Confused Deputy",
        "",
        "EVIDENCE: Missing Authorization Chain",
        "",
        "🤖 Agent Action:",
        f"-- Principal: {event.principal_id}",
        f"-- Action   : {event.action_operation}",
        f"-- Resource : {event.resource_id or 'unknown'}",
        "",
        "🔍 Missing Proof:",
        f"No successful access check found for Caller ({caller_id}) on the target ",
        "resource before agent's action.",
    ]
    return "\n".join(lines)


def _collect_input_paths(input_path: Path, pattern: str) -> List[Path]:
    if input_path.is_file():
        return [input_path]
    if input_path.is_dir():
        files = sorted(input_path.rglob(pattern))
        return [path for path in files if path.is_file()]
    raise SystemExit(f"Input path '{input_path}' is neither a file nor directory.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Detect Confused Deputy evidence from normalized JSONL logs "
            "(e.g., output/gcp/downloaded-logs-20251031-213704.jsonl). "
            "You can supply either a single file or a directory containing JSONL files."
        )
    )
    parser.add_argument(
        "input",
        type=Path,
        help="Path to a normalized JSONL log file or directory containing JSONL files.",
    )
    parser.add_argument(
        "--pattern",
        default="*.jsonl",
        help="Glob pattern when --input is a directory. Defaults to '*.jsonl'.",
    )
    args = parser.parse_args()

    input_paths = _collect_input_paths(args.input, args.pattern)
    if not input_paths:
        print(f"No files found under '{args.input}' matching pattern '{args.pattern}'.")
        return

    any_finding = False

    processed_files = 0
    findings = 0

    for path in input_paths:
        processed_files += 1
        events = _load_events(path)
        finding = detect_confused_deputy(events)

        if not finding:
            continue

        any_finding = True
        findings += 1
        event, caller_id = finding
        print(f"\n=== Findings in {path} ===")
        print(format_report(event, caller_id))

    if not any_finding:
        print("No Confused Deputy vulnerability detected.")
    print(
        f"\nSummary: processed {processed_files} file(s), "
        f"detected {findings} potential vulnerability/vulnerabilities."
    )


if __name__ == "__main__":
    main()


