# DE-Verifier

DE-Verifier is a cloud log defense pipeline that ingests heterogeneous AWS, GCP, and Azure telemetry, normalizes every record into a unified CloudEvent schema, and runs specialized analytics to surface Confused Deputy and Agent Takeover risks. The toolkit automates the path from raw evidence to actionable findings so responders can triage incidents faster.

It ships with:
- `aggregate_logs.py` – auto-detects the source cloud provider, routes logs through the right parser, and emits sorted JSONL files under `output/<provider>/`.
- `detect_confused_deputy.py` – correlates authorization chains inside normalized GCP logs to flag missing preconditions before high-risk agent actions.
- `detect_agent_takeover.py` – compares AWS activity sequences against historical baselines to highlight anomalous service usage indicative of agent takeover.

## File Structure Overview

```
.
├── aggregate_logs.py            # Provider auto-detection + normalization CLI
├── baseline_samples/            # The samples of similarity baselines
├── detect_confused_deputy.py    # Confused Deputy detector
├── detect_agent_takeover.py     # Agent takeover scoring engine 
├── output/                      # Destination for normalized JSONL grouped per cloud
├── parsers/
│   ├── ir_schema.py             # CloudEvent + helper models shared by all parsers
│   ├── aws_parser.py            # CloudTrail → CloudEvent converter
│   ├── gcp_parser.py            # Cloud Audit / Logging → CloudEvent converter
│   └── azure_parser.py          # Azure Activity + pipeline worker log parser
└── README.md                    # Project documentation
```

## Quick Start

### 1. Environment Setup
The toolkit targets Python 3.10+. Create a virtual environment and install the small dependency set (Pydantic + python-dateutil):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install pydantic python-dateutil
```

Install any additional libraries that your environment may require (e.g., for log ingestion helpers).

### 2. Normalize multi-cloud logs

Point `aggregate_logs.py` at a folder of raw JSON/JSONL/text logs. The command below recursively scans the directory, guesses the provider per file, and writes normalized events to `output/<provider>/name.jsonl`.

```bash
python3 aggregate_logs.py \
  --input input/mixed_logs \
  --output output \
  --pattern "*.json,*.jsonl,*.log" \
  --recursive
```

### 3. Run the Confused Deputy Check 

Run the Confused Deputy detector on the normalized CloudEvents (example below targets the `output/gcp` subset):

```bash
python3 detect_confused_deputy.py output/gcp
```

### 4. Run the Agent Takeover Check

Run the Agent Takeover detector on the normalized CloudEvents, comparing each file to the baseline corpus (example below uses AWS baselines):

```bash
python3 detect_agent_takeover.py baseline_samples output/aws --threshold 0.6
```

## Log Normalization Pipeline

`aggregate_logs.py` is the front door for every workflow. It hides provider-specific quirks behind a single CLI and makes sure downstream detectors only ever see structured, timestamp-sorted CloudEvents.

### Provider detection

The script loads a representative record from each file (falling back to JSONL scanning and filename heuristics) and looks for hallmark fields:

- AWS: `eventSource`, `userIdentity`, or CloudTrail naming patterns.
- GCP: presence of `protoPayload`, `insertId`, GCP logName prefixes, or resource labels such as `project_id`.
- Azure: fields like `resourceId`, `operationName`, or Azure Pipelines worker log markers in plain-text files.

If the record is unstructured, extra heuristics such as `_looks_like_azure_worker_log` inspect the first hundred lines for pipeline keywords.

### Parser architecture

Each parser produces the shared `CloudEvent` schema defined in `parsers/ir_schema.py`, which captures principals (including delegation chains), actions, resources, status, correlation IDs, and optional context/response annotations. Provider modules then fill in the details:

- `aws_parser.py` traces IAM identities (including `AssumedRole` delegation), derives services from `eventSource`, and heuristically extracts resource types from ARNs.
- `gcp_parser.py` inspects `protoPayload` to capture serviceAccount delegation, HTTP context, and response metadata while remaining resilient to JSONL + textPayload variations.
- `azure_parser.py` handles both structured diagnostics and Azure Pipelines worker logs, masking secrets, IPs, and repository names before emitting sanitized events.

### Output layout & sorting

All normalized events are timestamp-sorted, serialized as JSONL, and written under `<output>/<provider>/<original>.jsonl`. The `raw_log` field is stripped to keep files lightweight while still retaining the rest of the context needed by the detectors. Re-run the command at any time to regenerate fresh normalized data.

## Detection Workflows

### Confused Deputy Check

`detect_confused_deputy.py` scans normalized CloudEvents for agent actions that lack a preceding authorization proof. Use it after normalization; the sample below happens to reference the GCP dataset:

```bash
python3 detect_confused_deputy.py output/gcp
```

Sample output:

```
=== Findings in output/gcp/gcp_attack_1.jsonl ===
(1) VULNERABILITY FOUND: Confused Deputy

EVIDENCE: Missing Authorization Chain

🤖 Agent Action:
-- Principal: insufficient-permission@micro-harmony-475105-g2.iam.gserviceaccount.com
-- Action   : google.cloud.aiplatform.v1.DatasetService.ImportData
-- Resource : projects/example-111111

🔍 Missing Proof:
No successful access check found for Caller (unknown) on the target 
resource before agent's action.

=== Findings in output/gcp/gcp_attack_2.jsonl ===
(1) VULNERABILITY FOUND: Confused Deputy

EVIDENCE: Missing Authorization Chain

🤖 Agent Action:
-- Principal: service-111111111111@gcp-sa-discoveryengine.iam.gserviceaccount.com
-- Action   : storage.buckets.get
-- Resource : projects/_/buckets/sensitive-43223

🔍 Missing Proof:
No successful access check found for Caller (example@gmail.com) on the target 
resource before agent's action.

=== Findings in output/gcp/gcp_attack_3.jsonl ===
(1) VULNERABILITY FOUND: Confused Deputy

EVIDENCE: Missing Authorization Chain

🤖 Agent Action:
-- Principal: service-111111111111@gcp-sa-discoveryengine.iam.gserviceaccount.com
-- Action   : storage.buckets.get
-- Resource : projects/_/buckets/sensitive-43223

🔍 Missing Proof:
No successful access check found for Caller (example@gmail.com) on the target 
resource before agent's action.

Summary: processed 52 file(s), detected 3 potential vulnerability/vulnerabilities.
```

### Agent Takeover Check

`detect_agent_takeover.py` aligns each normalized CloudEvent stream with the closest baseline run, computes similarity scores, and highlights unexpected versus anomalous API calls. Tune the `--threshold` flag to control the alert sensitivity; the example below uses AWS data:

```bash
python3 detect_agent_takeover.py baseline_samples output/aws --threshold 0.6
```

Sample output:

```
=== Risk Logs ===
aws_96.jsonl
  baseline : aws_baseline_ecs_runtask_28.jsonl
  score    : 0.6865
  Unexpected: notifications:ListManagedNotificationEvents (+85), ec2:RunInstances (+73), monitoring:DescribeAlarms (+25)
  Anomalous : None

aws_attack_1.jsonl
  baseline : aws_baseline_batch_submitjob_96.jsonl
  score    : 0.6206
  Unexpected: cloudtrail:DescribeTrails (+4), s3:ListBuckets (+2), ec2:DescribeInstances (+2)
  Anomalous : batch:DescribeJobQueues (-4), batch:ListSchedulingPolicies (-3), iam:ListInstanceProfiles (-2)

aws_attack_2.jsonl
  baseline : aws_baseline_batch_submitjob_96.jsonl
  score    : 0.6069
  Unexpected: batch:DescribeSchedulingPolicies (+12), batch:DescribeJobs (+6), cloudtrail:DeleteTrail (+5)
  Anomalous : sts:AssumeRole (-2), iam:ListInstanceProfiles (-1), ec2:DescribeKeyPairs (-1)

aws_attack_3.jsonl
  baseline : aws_baseline_codebuild_startbuild_10.jsonl
  score    : 0.6338
  Unexpected: logs:CreateLogStream (+2), sts:GetCallerIdentity (+2), s3:PutObject (+2)
  Anomalous : codebuild:BatchGetBuilds (-1), autoscaling:DescribeAutoScalingGroups (-1)

aws_attack_4.jsonl
  baseline : aws_baseline_codebuild_startbuild_10.jsonl
  score    : 0.6511
  Unexpected: cloudtrail:GetTrailStatus (+5), cloudtrail:GetEventSelectors (+4), cloudtrail:GetResourcePolicy (+4)
  Anomalous : sts:AssumeRole (-4), codebuild:BatchGetBuilds (-2), codeconnections:GetConnectionToken (-2)

aws_attack_5.jsonl
  baseline : aws_baseline_ecs_registertaskdefinition_3.jsonl
  score    : 0.6297
  Unexpected: ecs:DescribeClusters (+5), ecs:DescribeTasks (+5), ecs:DescribeTaskDefinition (+4)
  Anomalous : ecs:ListAccountSettings (-2), batch:ListSchedulingPolicies (-1), batch:DescribeComputeEnvironments (-1)

aws_attack_6.jsonl
  baseline : aws_baseline_ecs_registertaskdefinition_3.jsonl
  score    : 0.6852
  Unexpected: ecs:RunTask (+1), cloudtrail:DescribeTrails (+1), logs:DescribeLogGroups (+1)
  Anomalous : ecs:ListAccountSettings (-2), batch:ListSchedulingPolicies (-1), batch:DescribeComputeEnvironments (-1)


Total risk logs: 7

Evaluated combinations: 194 | Elapsed time: 9.56s
```