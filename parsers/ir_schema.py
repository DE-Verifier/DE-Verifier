from __future__ import annotations
from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class Principal(BaseModel):
    """
    Represents an identity (user, role, service) performing an action.
    Crucially, it supports a nested structure to represent delegation chains.
    """
    id: str  # e.g., ARN, email, service principal name
    type: str  # e.g., 'user', 'role', 'service_account', 'assumed_role'
    # The principal that invoked the current principal (e.g., the user who assumed a role)
    invoking_principal: Optional[Principal] = None

class Action(BaseModel):
    """
    Represents the operation being performed.
    """
    service: str  # e.g., 's3', 'iam', 'compute'
    operation: str  # e.g., 'GetObject', 'CreateInstance'
    # Optional categorization for easier analysis
    category: Optional[str] = None # e.g., 'read', 'write', 'permission_change'

class Resource(BaseModel):
    """
    Represents a resource being acted upon.
    """
    id: str  # e.g., ARN, full resource name
    type: str # e.g., 'aws_s3_bucket', 'gcp_compute_instance'

class CloudEvent(BaseModel):
    """
    The unified Intermediate Representation (IR) for a single cloud log event.
    """
    event_id: str = Field(..., description="Unique ID for the event log entry.")
    cloud_provider: str
    timestamp: datetime
    
    principal: Principal
    action: Action
    resources: List[Resource] = Field(default_factory=list)
    
    status: str  # 'success' or 'failure'
    correlation_id: Optional[str] = Field(None, description="ID to correlate events in a workflow.")
    context: Optional[Dict[str, Any]] = Field(
        None, description="Provider-specific context (e.g., text payloads, labels)."
    )
    response_annotations: Optional[Dict[str, Any]] = Field(
        None, description="Annotations extracted from provider response metadata."
    )
    response_spec: Optional[Dict[str, Any]] = Field(
        None, description="Spec portion captured from provider response."
    )
    
    raw_log: Dict[str, Any]

# This is necessary for Pydantic to handle the recursive Principal -> Principal model
Principal.update_forward_refs()
