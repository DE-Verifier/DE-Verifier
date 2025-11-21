import gzip
import json
import dateutil.parser

from .ir_schema import CloudEvent, Principal, Action, Resource

def _parse_aws_principal(identity: dict) -> Principal:
    """Parses the complex userIdentity field to build a Principal object, including delegation."""
    identity_type = identity.get('type')
    
    if identity_type == 'AssumedRole':
        # This is a delegation scenario.
        session_context = identity.get('sessionContext', {})
        session_issuer = session_context.get('sessionIssuer', {})
        
        # The invoking principal is who assumed the role.
        invoking_principal = Principal(
            id=session_issuer.get('arn') or session_issuer.get('principalId') or 'unknown',
            type=session_issuer.get('type') or 'unknown'
        )
        
        # The current principal is the role that was assumed.
        return Principal(
            id=identity.get('arn') or identity.get('principalId') or 'unknown',
            type=identity_type or 'unknown',
            invoking_principal=invoking_principal
        )
    
    # Simple case (IAMUser, Root, AWSService)
    return Principal(
        id=identity.get('arn') or identity.get('principalId') or 'unknown',
        type=identity_type or 'unknown'
    )

def _normalize_record(record: dict) -> CloudEvent:
    """Converts a single AWS CloudTrail record to the common CloudEvent format."""
    timestamp_str = record.get('eventTime')
    if not timestamp_str:
        return None
    
    # Build Action
    event_source = record.get('eventSource', 'unknown.amazonaws.com')
    service = event_source.split('.')[0]
    action = Action(
        service=service,
        operation=record.get('eventName')
    )

    # Build Resources
    resources = []
    for res in record.get('resources', []):
        # A simple heuristic to get resource type from ARN
        # Format: arn:partition:service:region:account-id:resource-type/resource-id
        arn = res.get('ARN')
        if arn:
            parts = arn.split(':')
            res_type = parts[5].split('/')[0] if len(parts) > 5 else service
            resources.append(Resource(id=arn, type=f"aws_{service}_{res_type}"))

    return CloudEvent(
        timestamp=dateutil.parser.isoparse(timestamp_str),
        event_id=record.get('eventID'),
        cloud_provider='aws',
        principal=_parse_aws_principal(record.get('userIdentity', {})),
        action=action,
        resources=resources,
        correlation_id=record.get('requestID'),
        status='success' if 'errorCode' not in record else 'failure',
        raw_log=record
    )

def parse(file_path):
    """
    Parses an AWS CloudTrail log file, which may be gzipped.
    Yields normalized log records.
    """
    open_func = gzip.open if file_path.name.endswith('.gz') else open
    
    try:
        with open_func(file_path, 'rt', encoding='utf-8-sig') as f:
            data = json.load(f)
            if isinstance(data, list):
                records = data
            elif isinstance(data, dict):
                records = data.get('Records', [])
            else:
                print(f"Warning: Unsupported JSON structure in {file_path}: {type(data)}")
                return
            for record in records:
                normalized = _normalize_record(record)
                if normalized:
                    yield normalized
    except (json.JSONDecodeError, gzip.BadGzipFile, UnicodeDecodeError) as e:
        print(f"Warning: Could not process file {file_path}. Reason: {e}")
        return
