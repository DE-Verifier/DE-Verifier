import json
import re
from typing import List
from urllib.parse import urlparse

import dateutil.parser

from .ir_schema import CloudEvent, Principal, Action, Resource

FAILURE_SEVERITIES = {'ALERT', 'CRITICAL', 'ERROR', 'EMERGENCY', 'FATAL'}


def _build_resources(record: dict, payload: dict, service: str) -> List[Resource]:
    resources: List[Resource] = []

    resource_name = payload.get('resourceName')
    if isinstance(resource_name, str):
        parts = resource_name.split('/')
        res_type = parts[-2] if len(parts) > 1 else service
        resources.append(Resource(id=resource_name, type=f"gcp_{service}_{res_type}"))
        return resources

    record_resource = record.get('resource')
    if isinstance(record_resource, dict):
        res_type = record_resource.get('type') or service or 'resource'
        labels = record_resource.get('labels') or {}

        identifier = None
        project_id = labels.get('project_id')
        if res_type == 'build' and labels.get('build_id'):
            identifier = f"projects/{project_id or 'unknown'}/builds/{labels['build_id']}"
        elif res_type == 'cloudsql_database' and labels.get('database_id'):
            identifier = labels['database_id']
        elif labels.get('service_name'):
            identifier = f"{project_id or 'unknown'}:services/{labels['service_name']}"
        elif labels.get('resource_name'):
            identifier = labels['resource_name']
        elif labels.get('database_id'):
            identifier = labels['database_id']
        elif labels.get('instanceId'):
            identifier = labels['instanceId']

        if not identifier:
            identifier = res_type or service or 'resource'

        resources.append(
            Resource(
                id=identifier,
                type=f"gcp_{service}_{res_type.replace('.', '_') if isinstance(res_type, str) else 'resource'}"
            )
        )

    return resources


def _derive_operation(record: dict, payload: dict) -> str:
    operation = payload.get('methodName') or record.get('methodName')

    if not operation:
        labels = record.get('labels')
        if isinstance(labels, dict):
            operation = labels.get('build_step') or labels.get('function_name')

    if not operation:
        resource = record.get('resource')
        if isinstance(resource, dict):
            operation = resource.get('type')

    if not operation:
        http_request = record.get('httpRequest')
        if isinstance(http_request, dict):
            method = http_request.get('requestMethod')
            url = http_request.get('requestUrl')
            if method and url:
                parsed = urlparse(url)
                path = parsed.path or '/'
                operation = f"{method} {path}"

    if not operation:
        log_name = record.get('logName')
        if isinstance(log_name, str):
            log_tail = log_name.split('/')[-1]
            if '%2F' in log_tail:
                log_tail = log_tail.split('%2F')[-1]
            operation = log_tail

    if not operation:
        text_payload = record.get('textPayload')
        if isinstance(text_payload, str):
            match = re.match(r'^Step\s+#\d+\s+-\s+"([^"]+)"', text_payload)
            if match:
                operation = f"build_step:{match.group(1)}"
            else:
                snippet = text_payload.split(':')[0].strip() or text_payload[:80]
                operation = snippet

    return operation or 'unknown'


def _determine_status(record: dict, payload: dict) -> str:
    if payload.get('status'):
        return 'failure'

    http_request = record.get('httpRequest')
    if isinstance(http_request, dict):
        status_code = http_request.get('status')
        try:
            status_int = int(status_code)
        except (TypeError, ValueError):
            status_int = None
        if isinstance(status_int, int) and status_int >= 400:
            return 'failure'

    severity = record.get('severity')
    if isinstance(severity, str) and severity.upper() in FAILURE_SEVERITIES:
        return 'failure'

    return 'success'


def _normalize_record(record: dict) -> CloudEvent:
    """Converts a single GCP Audit Log record to the common CloudEvent format."""
    timestamp_str = record.get('timestamp')
    if not timestamp_str:
        return None

    payload = record.get('protoPayload') or record.get('jsonPayload') or {}
    if not isinstance(payload, dict):
        payload = {}
    auth_info = payload.get('authenticationInfo', {})

    # Build Principal, looking for delegation info
    invoking_principal = None
    delegation_info = auth_info.get('serviceAccountDelegationInfo', [])
    if delegation_info:
        # GCP logs the full chain, here we take the first delegator
        first_delegator = delegation_info[0].get('firstPartyPrincipal') or delegation_info[0].get('thirdPartyPrincipal')
        if first_delegator:
            invoking_principal = Principal(
                id=first_delegator.get('principalEmail'),
                type='service_account' # Inferred
            )

    # Build Action
    service_name = payload.get('serviceName') or record.get('serviceName')
    if not service_name:
        log_name = record.get('logName')
        if isinstance(log_name, str):
            service_candidate = log_name.split('/')[-1]
            service_name = service_candidate.split('%2F')[0] if service_candidate else None
    service = (service_name or 'unknown').split('.')[0]

    action = Action(
        service=service,
        operation=_derive_operation(record, payload)
    )

    # Build Resource
    resources = _build_resources(record, payload, service)
    http_request = record.get('httpRequest')
    if not resources and isinstance(http_request, dict):
        url = http_request.get('requestUrl')
        if isinstance(url, str):
            parsed = urlparse(url)
            path = parsed.path or '/'
            netloc = parsed.netloc or ''
            resources.append(
                Resource(
                    id=f"{netloc}{path}",
                    type=f"gcp_{service}_http_resource"
                )
            )

    response_annotations = None
    response_spec = None
    response = payload.get('response')
    if isinstance(response, dict):
        metadata = response.get('metadata')
        if isinstance(metadata, dict):
            annotations = metadata.get('annotations')
            if isinstance(annotations, dict):
                response_annotations = annotations
        spec = response.get('spec')
        if isinstance(spec, dict):
            response_spec = spec

    principal_email = auth_info.get('principalEmail') or 'unknown'
    principal_type = 'service_account' if 'gserviceaccount' in principal_email else 'user'
    if principal_email == 'unknown' and isinstance(http_request, dict):
        remote_ip = http_request.get('remoteIp')
        if remote_ip:
            principal_email = remote_ip
            principal_type = 'ip_address'

    context_data = None
    text_payload = record.get('textPayload')
    labels = record.get('labels')
    if isinstance(text_payload, str) or isinstance(labels, dict):
        context_data = {}
        if isinstance(text_payload, str):
            context_data['textPayload'] = text_payload
        if isinstance(labels, dict):
            context_data['labels'] = labels

    return CloudEvent(
        timestamp=dateutil.parser.isoparse(timestamp_str),
        event_id=record.get('insertId'),
        cloud_provider='gcp',
        principal=Principal(
            id=principal_email,
            type=principal_type,
            invoking_principal=invoking_principal
        ),
        action=action,
        resources=resources,
        correlation_id=record.get('operation', {}).get('id'),
        context=context_data,
        response_annotations=response_annotations,
        response_spec=response_spec,
        status=_determine_status(record, payload),
        raw_log=record
    )

def parse(file_path):
    """
    Parses a GCP Cloud Audit Log file.
    The file can be a single JSON object containing a list of records,
    or a JSONL file with one record per line.
    Yields normalized log records.
    """
    try:
        with open(file_path, 'rt', encoding='utf-8-sig') as f:
            # First, try to load the entire file as a single JSON object/array
            try:
                data = json.load(f)
                records = data if isinstance(data, list) else [data]
            except json.JSONDecodeError:
                # If that fails, reset and try to parse as JSONL (one object per line)
                f.seek(0)
                records = (json.loads(line) for line in f if line.strip())

            for record in records:
                # Ensure record is a dict before processing
                if not isinstance(record, dict):
                    print(f"Warning: Skipping record of type {type(record)} in {file_path}")
                    continue
                normalized = _normalize_record(record)
                if normalized:
                    yield normalized

    except (IOError, json.JSONDecodeError) as e:
        print(f"Warning: Could not process file {file_path}. Reason: {e}")
        return
