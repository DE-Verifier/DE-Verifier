import json
import re
import hashlib
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, List, Iterable, Tuple

import dateutil.parser

from .ir_schema import CloudEvent, Principal, Action, Resource

LOG_FAILURE_LEVELS = {'error', 'critical', 'fatal'}
AGENT_DIAG_LINE_RE = re.compile(
    r'^\[(?P<timestamp>[0-9T:\-\. ]+Z)\s+(?P<level>[A-Z]+)\s+(?P<component>[^\]]+)\]\s*(?P<message>.*)$'
)
PIPELINE_LINE_RE = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T[0-9:\.]+Z)\s+(?P<prefix>##\[[^\]]+\])\s*(?P<message>.*)$'
)
PIPELINE_SECTION_RE = re.compile(
    r'^(?P<phase>Starting|Finishing)\s*:\s*(?P<name>.+)$'
)
PIPELINE_PREFIX_LEVELS = {
    'section': 'info',
    'debug': 'debug',
    'error': 'error',
    'warning': 'warning',
    'warn': 'warning',
    'command': 'info',
    'group': 'info',
    'endgroup': 'info',
    'progress': 'info',
}


# === Embedded Azure Pipelines worker log parser (from azure_log_to_ir.py) ===

LOG_PATTERN = re.compile(
    r"^\[(?P<ts>[^]]+)\s+INFO\s+(?P<component>[^\]]+)\]\s(?P<message>.*)$"
)
JOB_LINE_PATTERN = re.compile(
    r"^\[Job:(?P<job_file>[^\]]+)\]\s+(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\s+(?P<message>.*)$"
)
JOB_ID_PATTERN = re.compile(r"JobId:(?P<job_id>[0-9a-fA-F-]+)")
DISPLAY_PATTERN = re.compile(
    r"Processing step(?:\s+\d+/\d+)?:\s+DisplayName='(?P<display>[^']+)'"
)
PROCESS_START_TRIGGER = "Starting process:"
PROCESS_STARTED_PATTERN = re.compile(
    r"Process started with process id (?P<pid>\d+)", re.IGNORECASE
)
PROCESS_EXIT_PATTERN = re.compile(
    r"Exited process (?P<pid>\d+) with exit code (?P<exit_code>-?\d+)", re.IGNORECASE
)
PROCESS_FINISHED_PATTERN = re.compile(
    r"Finished process (?P<pid>\d+) with exit code (?P<exit_code>-?\d+), and elapsed time (?P<elapsed>[0-9:.]+)",
    re.IGNORECASE,
)
JOB_SECTION_START_PATTERN = re.compile(r"##\[section\]Starting:\s*(?P<name>.+)")
JOB_SECTION_FINISH_PATTERN = re.compile(r"##\[section\]Finishing:\s*(?P<name>.+)")
JOB_COMMAND_PATTERN = re.compile(r"##\[command\]\s*(?P<command>.+)")
NETWORK_TOOL_PATTERN = re.compile(
    r"\b(curl|wget|invoke-webrequest|invoke-restmethod|az|kubectl)\b",
    re.IGNORECASE,
)
NETWORK_URL_PATTERN = re.compile(
    r"https?://(?P<host>[A-Za-z0-9\.\-]+)(?::(?P<port>\d+))?", re.IGNORECASE
)
NETWORK_IP_PORT_PATTERN = re.compile(
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+port\s+(?P<port>\d+)", re.IGNORECASE
)
CREDENTIAL_PATTERN = re.compile(
    r"\b(token|secret|password|credential|key)\b", re.IGNORECASE
)
TOKEN_NAME_PATTERN = re.compile(
    r"\b(?P<token>[A-Z0-9_]*(?:TOKEN|SECRET|KEY))\b"
)

_SENSITIVE_KEYWORDS = [
    "token",
    "secret",
    "password",
    "passphrase",
    "accesskey",
    "access_key",
    "api_key",
    "apikey",
    "clientsecret",
    "client_secret",
    "credential",
]
SENSITIVE_KV_PATTERN = re.compile(
    r"(?i)\b("
    + "|".join(_SENSITIVE_KEYWORDS)
    + r")\b(\s*[:=]\s*)([^\s\"']+)"
)
SENSITIVE_KV_QUOTED_PATTERN = re.compile(
    r"(?i)\b("
    + "|".join(_SENSITIVE_KEYWORDS)
    + r")\b(\s*[:=]\s*[\"'])(.+?)([\"'])"
)
BEARER_PATTERN = re.compile(r"(?i)(Bearer\s+)[A-Za-z0-9\-\._~=:+/]+")
GITHUB_URL_PATTERN = re.compile(
    r"(https?://github\.com/)([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)"
)
REPO_KEYWORD_PATTERN = re.compile(
    r"(?i)\b(Checkout|repository:|repo:)\s+([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)"
)
AGENT_PATH_PATTERN = re.compile(r"/home/vsts/[^\s\"']+")
USER_PATH_PATTERN = re.compile(r"/Users/[^\s\"']+")
WINDOWS_PATH_PATTERN = re.compile(r"[A-Za-z]:\\[^\s\"']+")
IPV4_PATTERN = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
IP_ONLY_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
GITHUB_TOKEN_PATTERN = re.compile(r"\bgh[pous]_[A-Za-z0-9]{20,}\b", re.IGNORECASE)
LONG_HEX_PATTERN = re.compile(r"\b[0-9a-f]{32,}\b", re.IGNORECASE)


def _normalize_timestamp_str(raw_ts: str) -> str:
    if not raw_ts:
        return raw_ts
    try:
        dt = dateutil.parser.isoparse(raw_ts)
    except (ValueError, TypeError):
        return raw_ts
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime('%Y-%m-%d %H:%M:%SZ')


def _stable_placeholder(prefix: str, value: str, length: int = 8) -> str:
    digest = hashlib.sha1(value.encode("utf-8")).hexdigest()[:length]
    return f"<{prefix.upper()}:{digest}>"


def _mask_sensitive_text(text: Optional[str]) -> Optional[str]:
    if not text:
        return text
    masked = text

    def _replace_kv(match: re.Match) -> str:
        return f"{match.group(1)}{match.group(2)}***"

    def _replace_kv_quoted(match: re.Match) -> str:
        return f"{match.group(1)}{match.group(2)}***{match.group(4)}"

    masked = SENSITIVE_KV_PATTERN.sub(_replace_kv, masked)
    masked = SENSITIVE_KV_QUOTED_PATTERN.sub(_replace_kv_quoted, masked)
    masked = BEARER_PATTERN.sub(r"\1***", masked)
    masked = GITHUB_TOKEN_PATTERN.sub(
        lambda m: _stable_placeholder("TOKEN", m.group(0)), masked
    )
    masked = LONG_HEX_PATTERN.sub(lambda m: _stable_placeholder("HEX", m.group(0)), masked)
    masked = IPV4_PATTERN.sub(lambda m: _stable_placeholder("IP", m.group(0)), masked)
    masked = AGENT_PATH_PATTERN.sub("<AGENT_PATH>", masked)
    masked = USER_PATH_PATTERN.sub("<USER_PATH>", masked)
    masked = WINDOWS_PATH_PATTERN.sub("<WIN_PATH>", masked)
    masked = GITHUB_URL_PATTERN.sub(
        lambda m: m.group(1) + _stable_placeholder("REPO", m.group(2)), masked
    )
    masked = REPO_KEYWORD_PATTERN.sub(
        lambda m: f"{m.group(1)} {_stable_placeholder('REPO', m.group(2))}", masked
    )
    return masked


def _sanitize_structure(value):
    if isinstance(value, str):
        return _mask_sensitive_text(value)
    if isinstance(value, list):
        return [_sanitize_structure(item) for item in value]
    if isinstance(value, dict):
        return {key: _sanitize_structure(val) for key, val in value.items()}
    return value


def _sanitize_principal(principal: Optional[dict]) -> dict:
    if not principal:
        return {}
    sanitized = dict(principal)
    sanitized.pop("display", None)
    return sanitized


@dataclass
class WorkerEvent:
    event_id: str
    timestamp: str
    operation: str
    service: str = "AzurePipelines"
    principal: dict = field(default_factory=dict)
    resources: List[dict] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    cloud_provider: str = "azure"
    status: str = "success"
    context: Optional[dict] = None
    response_annotations: Optional[dict] = None
    response_spec: Optional[dict] = None

    def __post_init__(self) -> None:
        self.principal = _sanitize_principal(self.principal)
        self.resources = _sanitize_structure(self.resources)
        self.metadata = _sanitize_structure(self.metadata)

    def to_json(self) -> str:
        payload = {
            "event_id": self.event_id,
            "cloud_provider": self.cloud_provider,
            "timestamp": self.timestamp,
            "principal": self.principal,
            "action": {"service": self.service, "operation": self.operation},
            "resources": self.resources,
            "status": self.status,
            "context": self.context,
            "response_annotations": self.response_annotations,
            "response_spec": self.response_spec,
            "metadata": self.metadata,
        }
        return json.dumps(payload, ensure_ascii=False)


def _slugify_step(display_name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9]+", " ", display_name).strip()
    if not cleaned:
        return "Step.Unknown"
    parts = cleaned.split()
    return "Step." + "".join(word.capitalize() for word in parts)


def _guess_resources(display_name: str) -> List[dict]:
    if not display_name:
        return []
    if display_name.lower().startswith("checkout"):
        remainder = display_name[len("Checkout") :].strip()
        repo_name = None
        branch = None
        if "@" in remainder:
            before_at, after_at = remainder.split("@", 1)
            repo_name = before_at.strip() or None
            branch = after_at.split()[0].strip() or None
        elif remainder:
            repo_name = remainder.split()[0]
        resource = {"type": "repo"}
        if repo_name:
            resource["name"] = repo_name
        if branch:
            resource["branch"] = branch
        return [resource]
    return []


def _dedupe_resources(resources: Iterable[dict]) -> List[dict]:
    seen = set()
    deduped: List[dict] = []
    for resource in resources:
        if not resource:
            continue
        key = json.dumps(resource, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(resource)
    return deduped


def _job_resources(job_id: Optional[str]) -> List[dict]:
    resource = {"type": "job"}
    if job_id:
        resource["id"] = job_id
    return [resource]


def _job_step_resource(job_file: str) -> dict:
    name = job_file.rsplit(".", 1)[0] if job_file else job_file
    return {"type": "job_step", "name": name or job_file}


def _infer_job_log_resources(job_message: str, job_file: str) -> List[dict]:
    resources: List[dict] = [_job_step_resource(job_file)]
    lowered = job_message.lower()
    categories: set[str] = set()

    network_resource: Optional[dict] = None
    if NETWORK_TOOL_PATTERN.search(job_message) or "connect to" in lowered:
        network_resource = {"type": "network"}
        url_match = NETWORK_URL_PATTERN.search(job_message)
        host_value: Optional[str] = None
        port_value: Optional[str] = None
        if url_match:
            host_value = url_match.group("host")
            port_value = url_match.group("port")
        else:
            ip_match = NETWORK_IP_PORT_PATTERN.search(job_message)
            if ip_match:
                host_value = ip_match.group("ip")
                port_value = ip_match.group("port")
        if host_value:
            network_resource["host"] = host_value
            if port_value:
                network_resource["port"] = port_value
            host_kind = "ip" if IP_ONLY_PATTERN.match(host_value) else "domain"
            resources.append({"type": "network_host_kind", "name": host_kind})
            resources.append(
                {
                    "type": "network_indicator",
                    "name": _stable_placeholder("HOST", host_value),
                }
            )
        resources.append(network_resource)
        categories.add("network")

    if CREDENTIAL_PATTERN.search(job_message):
        credential_resource: dict = {"type": "credential"}
        token_match = TOKEN_NAME_PATTERN.search(job_message)
        if token_match:
            credential_resource["name"] = token_match.group("token")
        resources.append(credential_resource)
        categories.add("credential")

    if any(token in lowered for token in ("error", "failed", "denied", "unauthorized")):
        categories.add("failure")

    trimmed = lowered.lstrip()
    command_prefixes = ("npm ", "node ", "curl ", "dotnet ", "powershell ", "python ")
    if (
        trimmed.startswith(">")
        or any(trimmed.startswith(prefix) for prefix in command_prefixes)
        or "[command]" in lowered
    ):
        categories.add("command")

    for category in categories:
        resources.append({"type": "log_category", "name": category})

    return _dedupe_resources(resources)


def _classify_job_log_operation(resources: List[dict]) -> str:
    category_priority = ["network", "credential", "failure", "command"]
    categories = {
        resource.get("name")
        for resource in resources
        if resource.get("type") == "log_category"
    }
    for category in category_priority:
        if category in categories:
            return f"Job.Log.{category.capitalize()}"
    return "Job.Log.General"


DEFAULT_PRINCIPAL = {
    "type": "ServicePrincipal",
    "id": "example@gmail.com_ci",
    "display": "Individual CI by azure-pipelines[bot]",
}


def _default_principal() -> dict:
    return dict(DEFAULT_PRINCIPAL)


def _normalize_process_detail(detail_line: str) -> Optional[Tuple[str, str]]:
    stripped = detail_line.strip()
    if not stripped or ":" not in stripped:
        return None
    key, value = stripped.split(":", 1)
    key = key.strip()
    value = value.strip()
    if value.startswith("'") and value.endswith("'"):
        value = value[1:-1]
    return key.lower().replace(" ", "_"), value


def _process_resources_from_path(file_path: Optional[str]) -> List[dict]:
    if not file_path:
        return []
    resource = {"type": "process", "path": file_path}
    resource["name"] = Path(file_path).name
    return [resource]


def _build_step_event(
    timestamp: str,
    display_name: str,
    step_index: int,
    raw_message: str,
) -> WorkerEvent:
    operation = _slugify_step(display_name)
    resources = [{"type": "step", "name": display_name}]
    resources.extend(_guess_resources(display_name))
    resources = _dedupe_resources(resources)
    return WorkerEvent(
        event_id=str(uuid.uuid4()),
        timestamp=timestamp,
        operation=operation,
        principal=_default_principal(),
        resources=resources,
        metadata={"display_name": display_name, "raw": raw_message},
    )


def _build_job_section_event(
    timestamp: str,
    section_name: str,
    phase: str,
    job_file: str,
    raw_message: str,
) -> WorkerEvent:
    slug = _slugify_step(section_name)
    operation = f"{slug}.{phase.capitalize()}"
    resources = _dedupe_resources(
        [
            {"type": "job_section", "name": section_name},
            _job_step_resource(job_file),
        ]
    )
    return WorkerEvent(
        event_id=str(uuid.uuid4()),
        timestamp=timestamp,
        operation=operation,
        principal=_default_principal(),
        resources=resources,
        metadata={
            "section": section_name,
            "phase": phase,
            "job_file": job_file,
            "raw": raw_message,
        },
    )


def _build_job_command_event(
    timestamp: str,
    command_text: str,
    job_file: str,
    raw_message: str,
) -> WorkerEvent:
    metadata = {
        "command": command_text,
        "job_file": job_file,
        "raw": raw_message,
    }
    resources: List[dict] = [_job_step_resource(job_file)]
    first_token = command_text.strip().split()[0] if command_text.strip() else None
    if first_token:
        resources.append({"type": "process", "name": first_token})
    resources = _dedupe_resources(resources)
    return WorkerEvent(
        event_id=str(uuid.uuid4()),
        timestamp=timestamp,
        operation="Job.Command",
        principal=_default_principal(),
        resources=resources,
        metadata=metadata,
    )


def _worker_parse_log(lines: Iterable[str]) -> List[WorkerEvent]:
    events: List[WorkerEvent] = []
    job_id: Optional[str] = None
    job_started = False
    step_counter = 0
    job_result: Optional[str] = None
    current_step_info: Optional[dict] = None
    pending_process: Optional[dict] = None
    running_processes: Dict[str, dict] = {}
    pending_exit_info: Dict[str, dict] = {}
    process_counter = 0
    job_section_counter = 0
    job_command_counter = 0

    for line in lines:
        stripped = line.rstrip("\n")
        job_line_match = JOB_LINE_PATTERN.match(stripped)
        if job_line_match:
            job_ts_raw = job_line_match.group("ts")
            job_ts = _normalize_timestamp_str(job_ts_raw)
            job_message = job_line_match.group("message")
            job_file = job_line_match.group("job_file")
            section_start = JOB_SECTION_START_PATTERN.match(job_message)
            section_finish = JOB_SECTION_FINISH_PATTERN.match(job_message)
            command_match = JOB_COMMAND_PATTERN.match(job_message)
            if section_start:
                job_section_counter += 1
                section_name = section_start.group("name").strip()
                events.append(
                    _build_job_section_event(
                        timestamp=job_ts,
                        section_name=section_name,
                        phase="start",
                        job_file=job_file,
                        raw_message=job_message,
                    )
                )
                continue
            if section_finish:
                job_section_counter += 1
                section_name = section_finish.group("name").strip()
                events.append(
                    _build_job_section_event(
                        timestamp=job_ts,
                        section_name=section_name,
                        phase="finish",
                        job_file=job_file,
                        raw_message=job_message,
                    )
                )
                continue
            if command_match:
                job_command_counter += 1
                command_text = command_match.group("command").strip()
                events.append(
                    _build_job_command_event(
                        timestamp=job_ts,
                        command_text=command_text,
                        job_file=job_file,
                        raw_message=job_message,
                    )
                )
                continue
            stripped_message = job_message.lstrip()
            lowered_message = stripped_message.lower()
            if (
                lowered_message.startswith("hint:")
                or lowered_message.startswith("knob:")
                or lowered_message.startswith("remote:")
            ):
                continue
            if stripped_message.startswith("##[debug]"):
                continue
            job_command_counter += 1
            resources = _infer_job_log_resources(job_message, job_file)
            operation = _classify_job_log_operation(resources)
            events.append(
                WorkerEvent(
                    event_id=str(uuid.uuid4()),
                    timestamp=job_ts,
                    operation=operation,
                    principal=_default_principal(),
                    resources=resources,
                    metadata={"job_file": job_file, "raw": job_message},
                )
            )
            continue

        match = LOG_PATTERN.match(stripped)
        if not match:
            continue
        timestamp_raw = match.group("ts")
        timestamp = _normalize_timestamp_str(timestamp_raw)
        component = match.group("component")
        message = match.group("message")

        job_id_match = JOB_ID_PATTERN.search(message)
        if not job_started:
            start_triggered = False
            candidate_id: Optional[str] = None
            if job_id_match:
                candidate_id = job_id_match.group("job_id")
                start_triggered = True
            elif "Job ID" in message:
                tail = message.split("Job ID", 1)[1].strip()
                candidate_id = tail.split()[0] if tail else None
                start_triggered = True

            if start_triggered:
                if candidate_id:
                    job_id = candidate_id
                events.append(
                    WorkerEvent(
                        event_id=str(uuid.uuid4()),
                        timestamp=timestamp,
                        operation="Job.Start",
                        principal=_default_principal(),
                        resources=_job_resources(job_id),
                        metadata={"component": component, "job_id": job_id},
                    )
                )
                job_started = True
        elif message.startswith("Processing step"):
            display_match = DISPLAY_PATTERN.search(message)
            display_name = display_match.group("display") if display_match else "Unnamed Step"
            step_counter += 1
            events.append(
                _build_step_event(
                    timestamp=timestamp,
                    display_name=display_name,
                    step_index=step_counter,
                    raw_message=message,
                )
            )
            current_step_info = {
                "display_name": display_name,
                "operation": _slugify_step(display_name),
                "index": step_counter,
            }
        elif message.startswith("Job result after all job steps finish:"):
            job_result = message.split(":", 1)[-1].strip()
        elif message.startswith("Job result:"):
            job_result = message.split(":", 1)[-1].strip()
        elif "Job completed." in message or message.startswith("Job completed"):
            events.append(
                WorkerEvent(
                    event_id=str(uuid.uuid4()),
                    timestamp=timestamp,
                    operation="Job.End",
                    principal=_default_principal(),
                    resources=_job_resources(job_id),
                    metadata={
                        "component": component,
                        "job_id": job_id,
                        "result": job_result or "Unknown",
                    },
                )
            )
            current_step_info = None

        if component == "ProcessInvokerWrapper":
            if message == PROCESS_START_TRIGGER:
                pending_process = {
                    "timestamp": timestamp,
                    "component": component,
                    "details": {},
                    "step": current_step_info.copy() if current_step_info else None,
                }
                continue

            if pending_process and message.startswith("  "):
                detail = _normalize_process_detail(message)
                if detail:
                    key, value = detail
                    pending_process["details"][key] = value
                continue

            start_match = PROCESS_STARTED_PATTERN.match(message)
            if start_match:
                pid = start_match.group("pid")
                process_counter += 1
                label = f"proc-{process_counter:03d}"
                details = dict(pending_process["details"]) if pending_process else {}
                step_snapshot = (
                    pending_process["step"].copy() if pending_process and pending_process["step"] else None
                )
                if not step_snapshot and current_step_info:
                    step_snapshot = current_step_info.copy()
                start_timestamp = pending_process["timestamp"] if pending_process else timestamp
                metadata = {"component": component, "pid": pid}
                metadata.update(details)
                if step_snapshot:
                    metadata["step_display"] = step_snapshot["display_name"]
                    metadata["step_operation"] = step_snapshot["operation"]
                    metadata["step_index"] = step_snapshot["index"]
                resources = _process_resources_from_path(details.get("file_name"))
                events.append(
                    WorkerEvent(
                        event_id=str(uuid.uuid4()),
                        timestamp=start_timestamp,
                        operation="Process.Start",
                        principal=_default_principal(),
                        resources=resources,
                        metadata=metadata,
                    )
                )
                running_processes[pid] = {
                    "label": label,
                    "details": details,
                    "step": step_snapshot,
                }
                pending_process = None
                continue

            exit_match = PROCESS_EXIT_PATTERN.match(message)
            if exit_match:
                pid = exit_match.group("pid")
                exit_code = exit_match.group("exit_code")
                pending_exit_info[pid] = {
                    "timestamp": timestamp,
                    "exit_code": exit_code,
                    "component": component,
                }
                continue

            finish_match = PROCESS_FINISHED_PATTERN.match(message)
            if finish_match:
                pid = finish_match.group("pid")
                exit_code = finish_match.group("exit_code")
                elapsed = finish_match.group("elapsed").rstrip(".")
                start_context = running_processes.pop(pid, None)
                exit_context = pending_exit_info.pop(pid, None)
                label = start_context["label"] if start_context else f"proc-{pid}"
                resources = _process_resources_from_path(
                    start_context["details"].get("file_name") if start_context else None
                )
                metadata = {"component": component, "pid": pid, "elapsed": elapsed}
                metadata["exit_code"] = (
                    exit_context["exit_code"] if exit_context else exit_code
                )
                if start_context and start_context["details"]:
                    metadata.update(start_context["details"])
                if start_context and start_context["step"]:
                    metadata["step_display"] = start_context["step"]["display_name"]
                    metadata["step_operation"] = start_context["step"]["operation"]
                    metadata["step_index"] = start_context["step"]["index"]
                if exit_context:
                    metadata.setdefault("exit_code", exit_context["exit_code"])
                event_timestamp = (
                    exit_context["timestamp"] if exit_context else timestamp
                )
                events.append(
                    WorkerEvent(
                        event_id=str(uuid.uuid4()),
                        timestamp=event_timestamp,
                        operation="Process.Exit",
                        principal=_default_principal(),
                        resources=resources,
                        metadata=metadata,
                    )
                )
                continue

    if not events:
        raise ValueError("No recognizable events found in log.")

    for pid, exit_context in pending_exit_info.items():
        start_context = running_processes.pop(pid, None)
        label = start_context["label"] if start_context else f"proc-{pid}"
        resources = _process_resources_from_path(
            start_context["details"].get("file_name") if start_context else None
        )
        metadata = {
            "component": exit_context["component"],
            "pid": pid,
            "exit_code": exit_context["exit_code"],
        }
        if start_context and start_context["details"]:
            metadata.update(start_context["details"])
        if start_context and start_context["step"]:
            metadata["step_display"] = start_context["step"]["display_name"]
            metadata["step_operation"] = start_context["step"]["operation"]
            metadata["step_index"] = start_context["step"]["index"]
        events.append(
            WorkerEvent(
                event_id=str(uuid.uuid4()),
                timestamp=exit_context["timestamp"],
                operation="Process.Exit",
                principal=_default_principal(),
                resources=resources,
                metadata=metadata,
            )
        )

    return events


# Alias used by the Azure parser integration.
worker_parse_log = _worker_parse_log


def _build_log_event(
    *,
    timestamp_str: str,
    file_path: Path,
    line_number: int,
    component: str,
    level: str,
    message: str,
    raw_line: str,
) -> CloudEvent:
    status = 'failure' if level.lower() in LOG_FAILURE_LEVELS else 'success'
    principal = Principal(id='azure_devops_agent', type='service_principal')
    action = Action(service='azure_devops', operation=component or 'log')
    resources = [
        Resource(id=str(file_path), type='azure_pipeline_log')
    ]
    context = {
        'level': level.lower(),
        'component': component,
        'message': message.strip(),
        'raw_line': raw_line,
    }
    return CloudEvent(
        timestamp=dateutil.parser.isoparse(timestamp_str),
        event_id=f"{file_path.name}:{line_number}",
        cloud_provider='azure',
        principal=principal,
        action=action,
        resources=resources,
        correlation_id=None,
        status=status,
        context=context,
        raw_log={
            'line_number': line_number,
            'line': raw_line,
            'level': level,
            'component': component,
        }
    )


def _build_pipeline_event(
    *,
    timestamp_str: str,
    file_path: Path,
    line_number: int,
    step_name: str,
    phase: str,
    duration_ms: Optional[int],
) -> CloudEvent:
    action = Action(service='azure_pipeline', operation=f"{phase}_section", category='control_plane')
    principal = Principal(id='azure_pipeline', type='system')
    context = {
        'phase': phase,
        'step_name': step_name,
    }
    if duration_ms is not None:
        context['duration_ms'] = duration_ms

    return CloudEvent(
        timestamp=dateutil.parser.isoparse(timestamp_str),
        event_id=f"{file_path.name}:{line_number}:{phase}",
        cloud_provider='azure',
        principal=principal,
        action=action,
        resources=[Resource(id=str(file_path), type='azure_pipeline_step')],
        correlation_id=None,
        status='success',
        context=context,
        raw_log={
            'line_number': line_number,
            'phase': phase,
            'step_name': step_name,
        }
    )


def _parse_text_log(file_path: Path):
    section_state: Dict[str, datetime] = {}
    with open(file_path, 'rt', encoding='utf-8', errors='ignore') as handle:
        for idx, line in enumerate(handle, start=1):
            stripped = line.rstrip('\n')
            if not stripped:
                continue

            diag_match = AGENT_DIAG_LINE_RE.match(stripped)
            if diag_match:
                try:
                    yield _build_log_event(
                        timestamp_str=diag_match.group('timestamp').strip(),
                        file_path=file_path,
                        line_number=idx,
                        component=diag_match.group('component').strip(),
                        level=diag_match.group('level').strip(),
                        message=diag_match.group('message'),
                        raw_line=stripped,
                    )
                except (ValueError, TypeError):
                    continue
                continue

            pipeline_match = PIPELINE_LINE_RE.match(stripped)
            if pipeline_match:
                prefix = pipeline_match.group('prefix')
                prefix_value = prefix.strip('#[]').lower()
                timestamp_str = pipeline_match.group('timestamp').strip()
                message = pipeline_match.group('message').strip()

                if prefix_value == 'section':
                    section_match = PIPELINE_SECTION_RE.match(message)
                    if not section_match:
                        continue
                    phase_raw = section_match.group('phase').lower()
                    step_name = section_match.group('name').strip()
                    try:
                        current_ts = dateutil.parser.isoparse(timestamp_str)
                    except (ValueError, TypeError):
                        continue

                    if phase_raw == 'starting':
                        section_state[step_name] = current_ts
                        yield _build_pipeline_event(
                            timestamp_str=timestamp_str,
                            file_path=file_path,
                            line_number=idx,
                            step_name=step_name,
                            phase='start',
                            duration_ms=None,
                        )
                    elif phase_raw == 'finishing':
                        start_ts = section_state.pop(step_name, None)
                        duration_ms = None
                        if start_ts:
                            duration_ms = int((current_ts - start_ts).total_seconds() * 1000)
                        yield _build_pipeline_event(
                            timestamp_str=timestamp_str,
                            file_path=file_path,
                            line_number=idx,
                            step_name=step_name,
                            phase='finish',
                            duration_ms=duration_ms,
                        )
                    continue

                level = PIPELINE_PREFIX_LEVELS.get(prefix_value, 'info')
                component = 'pipeline'
                try:
                    yield _build_log_event(
                        timestamp_str=timestamp_str,
                        file_path=file_path,
                        line_number=idx,
                        component=component,
                        level=level.upper(),
                        message=message,
                        raw_line=stripped,
                    )
                except (ValueError, TypeError):
                    continue
                continue

def _looks_like_worker_log(file_path: Path) -> bool:
    if worker_parse_log is None:
        return False
    try:
        with open(file_path, 'rt', encoding='utf-8', errors='ignore') as handle:
            for _ in range(50):
                line = handle.readline()
                if not line:
                    break
                lowered = line.lower()
                if 'worker process entry point' in lowered or 'jobrunner service created' in lowered:
                    return True
                if lowered.startswith('{'):
                    return False
    except OSError:
        return False
    return False


def _worker_resources_to_ir(resources: Optional[List[dict]]) -> List[Resource]:
    ir_resources: List[Resource] = []
    if not resources:
        return ir_resources
    for resource in resources:
        res_type = resource.get('type', 'unknown')
        res_id = (
            resource.get('id')
            or resource.get('path')
            or resource.get('name')
            or resource.get('host')
            or resource.get('url')
        )
        if not res_id:
            try:
                res_id = json.dumps(resource, sort_keys=True)
            except TypeError:
                res_id = str(resource)
        ir_resources.append(Resource(id=str(res_id), type=str(res_type)))
    return ir_resources


def _worker_event_to_cloudevent(worker_event: WorkerEvent, file_path: Path) -> CloudEvent:
    principal_info = worker_event.principal or {}
    principal = Principal(
        id=principal_info.get('id', 'unknown'),
        type=principal_info.get('type', 'unknown'),
    )

    action_info = getattr(worker_event, 'action', None)
    if isinstance(action_info, dict):
        service = action_info.get('service', 'AzurePipelines')
        operation = action_info.get('operation', 'log')
        category = action_info.get('category')
    else:
        service = getattr(worker_event, 'service', 'AzurePipelines')
        operation = getattr(worker_event, 'operation', 'log')
        category = None
    action = Action(service=service, operation=operation, category=category)

    context = worker_event.context or {}
    metadata = worker_event.metadata or {}
    if metadata:
        context = dict(context) if context else {}
        context.setdefault('metadata', metadata)

    return CloudEvent(
        event_id=worker_event.event_id,
        cloud_provider=worker_event.cloud_provider,
        timestamp=dateutil.parser.isoparse(worker_event.timestamp),
        principal=principal,
        action=action,
        resources=_worker_resources_to_ir(worker_event.resources),
        status=worker_event.status,
        correlation_id=None,
        context=context or None,
        response_annotations=worker_event.response_annotations,
        response_spec=worker_event.response_spec,
        raw_log={
            'source': str(file_path),
            'worker_event': asdict(worker_event),
        },
    )


def _parse_worker_log(file_path: Path):
    if worker_parse_log is None:
        return
    with open(file_path, 'rt', encoding='utf-8', errors='ignore') as handle:
        worker_events = worker_parse_log(handle)
    for worker_event in worker_events:
        yield _worker_event_to_cloudevent(worker_event, file_path)

def _normalize_diagnostic_record(record: dict) -> CloudEvent:
    """Converts a single Azure Diagnostic log record to the common CloudEvent format."""
    timestamp_str = record.get('time')
    if not timestamp_str:
        return None

    # Build Principal from the 'identity' claim
    identity = record.get('identity', {})
    claims = identity.get('claims') or identity.get('claim') or {}
    principal_id_str = claims.get('upn') or claims.get('appid') or record.get('callerIpAddress', 'unknown')
    
    principal_type = 'unknown'
    if claims.get('upn'):
        principal_type = 'user'
    elif claims.get('appid'):
        principal_type = 'service_principal'
    
    principal = Principal(id=principal_id_str, type=principal_type)

    # Build Action
    operation_name = record.get('operationName', 'unknown/unknown')
    category = record.get('category', 'unknown')
    parts = operation_name.split('/')
    service = parts[0] if parts and parts[0] else category
    operation = parts[-1] if len(parts) > 1 else operation_name
    action = Action(service=service, operation=operation, category=category)

    # Build Resource
    resources = []
    # In diagnostic logs, the primary resource is in 'resourceId'
    resource_id = record.get('resourceId')
    if resource_id:
        res_parts = resource_id.lower().split('/')
        res_type = "unknown"
        if 'providers' in res_parts:
            provider_index = res_parts.index('providers')
            if len(res_parts) > provider_index + 2:
                res_type = res_parts[provider_index+2]
        resources.append(Resource(id=resource_id, type=f"azure_{service.lower()}_{res_type}"))

    return CloudEvent(
        timestamp=dateutil.parser.isoparse(timestamp_str),
        event_id=record.get('correlationId'), # Use correlationId as a unique ID
        cloud_provider='azure',
        principal=principal,
        action=action,
        resources=resources,
        correlation_id=record.get('correlationId'),
        status='success' if record.get('resultType', '').lower() == 'success' else 'failure',
        raw_log=record
    )


def _normalize_record(record: dict) -> CloudEvent:
    """Converts a single Azure Monitor log record to the common CloudEvent format."""
    # Azure Activity Logs have a different timestamp field name
    timestamp_str = record.get('eventTimestamp') or record.get('time')
    if not timestamp_str:
        return None

    # Build Principal
    caller = record.get('caller', 'unknown')
    principal_id_str = caller
    principal_type = 'unknown'
    if isinstance(caller, dict):
        principal_id_str = caller.get('upn') or caller.get('appid') or str(caller)
        if caller.get('upn'):
            principal_type = 'user'
        elif caller.get('appid'):
            principal_type = 'service_principal'
    
    principal = Principal(id=principal_id_str, type=principal_type)
    
    # Build Action
    operation_field = record.get('operationName')
    if isinstance(operation_field, dict):
        operation_name = operation_field.get('value') or operation_field.get('localizedValue') or 'unknown/unknown'
    elif isinstance(operation_field, str):
        operation_name = operation_field
    else:
        operation_name = 'unknown/unknown'

    parts = operation_name.split('/')
    service = parts[0] if parts and parts[0] else 'unknown'
    operation = parts[-1] if len(parts) > 1 else operation_name
    action = Action(service=service, operation=operation)

    # Build Resource
    resources = []
    resource_id = record.get('resourceId')
    if resource_id:
        # Format: /subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/{type}/{name}
        res_parts = resource_id.lower().split('/')
        res_type = "unknown"
        if 'providers' in res_parts:
            provider_index = res_parts.index('providers')
            if len(res_parts) > provider_index + 2:
                res_type = res_parts[provider_index+2]

        resources.append(Resource(id=resource_id, type=f"azure_{service.lower()}_{res_type}"))

    status_field = record.get('status')
    if isinstance(status_field, dict):
        status_value = status_field.get('value') or status_field.get('localizedValue') or 'unknown'
    elif isinstance(status_field, str):
        status_value = status_field
    else:
        status_value = 'unknown'

    return CloudEvent(
        timestamp=dateutil.parser.isoparse(timestamp_str),
        event_id=record.get('eventDataId'),
        cloud_provider='azure',
        principal=principal,
        action=action,
        resources=resources,
        correlation_id=record.get('correlationId'),
        status=status_value.lower(),
        raw_log=record
    )


def parse(file_path):
    """
    Parses an Azure Monitor log file.
    This can be either Activity Logs or Diagnostic Logs.
    The function will attempt to distinguish between them.
    Yields normalized log records.
    """
    path = Path(file_path)
    if path.suffix.lower() in {'.txt', '.log'}:
        if _looks_like_worker_log(path):
            yield from _parse_worker_log(path)
        else:
            yield from _parse_text_log(path)
        return

    try:
        with open(path, 'rt', encoding='utf-8-sig') as f:
            # Some log files are just one JSON object per line
            try:
                data = json.load(f)
                # Handle both a flat list of records and the common {'records': [...]} or {'value': [...]} structure
                records = data.get('records', []) or data.get('value', []) if isinstance(data, dict) else data
            except json.JSONDecodeError:
                f.seek(0) # Rewind file to read line-by-line
                try:
                    records = [json.loads(line) for line in f if line.strip()]
                except json.JSONDecodeError:
                    yield from _parse_text_log(path)
                    return

            if not isinstance(records, list):
                print(f"Warning: Expected a list of records in {path}, but found {type(records)}.")
                return

            for record in records:
                # Heuristic to detect log type. Diagnostic logs often have 'category'.
                if 'category' in record and 'resultType' in record:
                    normalized = _normalize_diagnostic_record(record)
                else:
                    normalized = _normalize_record(record) # Assume Activity Log
                
                if normalized:
                    yield normalized
    except (json.JSONDecodeError, IOError) as e:
        print(f"Warning: Could not process file {file_path}. Reason: {e}")
        return
