import json
import dateutil.parser
from .ir_schema import CloudEvent, Principal, Action, Resource

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
    try:
        with open(file_path, 'rt', encoding='utf-8-sig') as f:
            # Some log files are just one JSON object per line
            try:
                data = json.load(f)
                # Handle both a flat list of records and the common {'records': [...]} or {'value': [...]} structure
                records = data.get('records', []) or data.get('value', []) if isinstance(data, dict) else data
            except json.JSONDecodeError:
                f.seek(0) # Rewind file to read line-by-line
                records = [json.loads(line) for line in f if line.strip()]

            if not isinstance(records, list):
                print(f"Warning: Expected a list of records in {file_path}, but found {type(records)}.")
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
