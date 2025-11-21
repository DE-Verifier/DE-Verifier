import argparse
import json
from pathlib import Path
import sys
from datetime import datetime
from typing import Any, Dict, Optional, List
from pydantic import BaseModel

# Dynamically import parsers
from parsers import aws_parser, gcp_parser, azure_parser

# Map provider names to parser modules
PROVIDER_PARSERS = {
    'aws': aws_parser,
    'gcp': gcp_parser,
    'azure': azure_parser,
}

class EnhancedJSONEncoder(json.JSONEncoder):
    """
    Custom JSON encoder to serialize Pydantic models and datetime objects.
    """
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, BaseModel):
            return obj.dict()
        return super().default(obj)


def _extract_first_event(data: Any, file_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """
    Attempts to extract the first event dict from assorted JSON structures.
    Supports:
      - list of events
      - dicts containing arrays under common keys (Records, records, value, items, events, logEvents)
      - a single event dict
    """
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                return item
        return None

    if isinstance(data, dict):
        candidate_keys = ['Records', 'records', 'value', 'items', 'events', 'logEvents']
        for key in candidate_keys:
            container = data.get(key)
            if isinstance(container, list):
                for item in container:
                    if isinstance(item, dict):
                        return item
        # Fallback: assume dict itself is the event
        return data

    return None


def _load_sample_event(file_path: Path) -> Optional[Dict[str, Any]]:
    """
    Loads a representative event from the given file for provider inference.
    Supports JSON arrays/objects and JSONL files.
    """
    try:
        with open(file_path, 'rt', encoding='utf-8-sig') as f:
            try:
                data = json.load(f)
                return _extract_first_event(data, file_path)
            except json.JSONDecodeError:
                f.seek(0)
                for line in f:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    try:
                        maybe = json.loads(stripped)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(maybe, dict):
                        return maybe
                    if isinstance(maybe, list):
                        event = _extract_first_event(maybe, file_path)
                        if event:
                            return event
                return None
    except IOError as e:
        print(f"Error reading file '{file_path}': {e}", file=sys.stderr)
        return None


def _infer_provider_from_path(file_path: Path) -> Optional[str]:
    """
    Guess provider names purely from the path in cases where structured hints are absent.
    """
    lowered_path = file_path.as_posix().lower()
    if any(token in lowered_path for token in ('cloudtrail', 'aws', 'iam.amazonaws.com')):
        return 'aws'
    if any(token in lowered_path for token in ('gcp', 'google', 'cloudaudit', 'bigquery')):
        return 'gcp'
    if any(token in lowered_path for token in ('azure', 'logs_', 'agent diagnostic logs', 'pipelines', 'worker_')):
        return 'azure'
    return None


def _looks_like_azure_worker_log(file_path: Path) -> bool:
    """
    Heuristic detection for Azure Pipelines worker logs (plain-text, not JSON).
    """
    keywords = (
        'worker process entry point',
        'jobrunner service created',
        '##[section]starting',
        '##[command]',
    )
    try:
        with open(file_path, 'rt', encoding='utf-8', errors='ignore') as handle:
            for _ in range(100):
                line = handle.readline()
                if not line:
                    break
                lowered = line.lower()
                if any(keyword in lowered for keyword in keywords):
                    return True
                if lowered.strip().startswith('{'):
                    # looks like structured JSON instead
                    return False
    except OSError:
        return False
    return False


def _detect_provider(file_path: Path) -> Optional[str]:
    """
    Inspects the first event in the file to guess the cloud provider.
    """
    sample_event = _load_sample_event(file_path)
    if not sample_event:
        if _looks_like_azure_worker_log(file_path):
            return 'azure'
        return _infer_provider_from_path(file_path)

    # AWS CloudTrail indicators
    if sample_event.get('eventSource') or sample_event.get('userIdentity'):
        return 'aws'

    # GCP Audit / Cloud Logging indicators
    if 'protoPayload' in sample_event or sample_event.get('insertId'):
        return 'gcp'

    log_name = sample_event.get('logName')
    if isinstance(log_name, str) and (
        'run.googleapis.com' in log_name
        or 'cloudaudit.googleapis.com' in log_name
        or 'logging.googleapis.com' in log_name
    ):
        return 'gcp'

    resource = sample_event.get('resource')
    if isinstance(resource, dict):
        resource_type = resource.get('type') or ''
        if isinstance(resource_type, str):
            if resource_type.startswith(('cloud_', 'gce_', 'gae_', 'bigquery')):
                return 'gcp'
        labels = resource.get('labels') or {}
        if isinstance(labels, dict):
            project_id = labels.get('project_id')
            if project_id and isinstance(project_id, str) and project_id.count('-') >= 1:
                # Heuristic: many GCP project IDs follow <name>-<numbers>.
                return 'gcp'

    # Azure Activity/Diagnostic indicators
    azure_fields = ['resourceId', 'category', 'identity', 'caller', 'operationName']
    if any(field in sample_event for field in azure_fields):
        return 'azure'

    return _infer_provider_from_path(file_path)


def _build_output_path(input_file: Path, provider: str, output_arg: Optional[Path], force_directory: bool) -> Path:
    """
    Determine where to write normalized events.
    If force_directory is True, treat output_arg as a directory base.
    """
    if output_arg:
        if force_directory:
            base_dir = output_arg
        else:
            if output_arg.exists() and output_arg.is_dir():
                base_dir = output_arg
            elif output_arg.suffix:
                return output_arg
            else:
                base_dir = output_arg
        output_name = input_file.with_suffix('.jsonl').name
        return base_dir / provider / output_name

    output_name = input_file.with_suffix('.jsonl').name
    return Path('output') / provider / output_name


def _process_file(input_file: Path, output_arg: Optional[Path], force_output_dir: bool, exit_on_error: bool) -> bool:
    if not input_file.is_file():
        message = f"Error: Input path '{input_file}' is not a file."
        if exit_on_error:
            print(message, file=sys.stderr)
            sys.exit(1)
        print(message, file=sys.stderr)
        return False

    provider = _detect_provider(input_file)
    if not provider:
        message = f"Error: Could not determine cloud provider for '{input_file}'."
        if exit_on_error:
            print(message, file=sys.stderr)
            sys.exit(1)
        print(message, file=sys.stderr)
        return False

    output_path = _build_output_path(input_file, provider, output_arg, force_output_dir)
    parser_module = PROVIDER_PARSERS[provider]
    print(f"Detected provider: {provider}")
    print(f"Parsing '{input_file}'...")

    all_events = []
    try:
        for event in parser_module.parse(input_file):
            all_events.append(event)
    except Exception as exc:
        message = f"Error parsing file '{input_file}': {exc}"
        if exit_on_error:
            print(message, file=sys.stderr)
            sys.exit(1)
        print(message, file=sys.stderr)
        return False

    print(f"Found {len(all_events)} events. Sorting by timestamp...")
    all_events.sort(key=lambda x: x.timestamp)

    print(f"Writing normalized events to '{output_path}'...")
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        message = f"Error creating output directory '{output_path.parent}': {e}"
        if exit_on_error:
            print(message, file=sys.stderr)
            sys.exit(1)
        print(message, file=sys.stderr)
        return False

    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            for event in all_events:
                event_dict = event.model_dump()
                event_dict.pop('raw_log', None)
                json.dump(event_dict, f, cls=EnhancedJSONEncoder)
                f.write('\n')
        print("Processing complete.")
        return True
    except IOError as e:
        message = f"Error writing to output file '{output_path}': {e}"
        if exit_on_error:
            print(message, file=sys.stderr)
            sys.exit(1)
        print(message, file=sys.stderr)
        return False


def _collect_input_files(root: Path, pattern: str, recursive: bool) -> List[Path]:
    """
    Supports comma-separated glob patterns so users can mix JSON and text logs.
    """
    patterns = [p.strip() for p in pattern.split(',') if p.strip()]
    if not patterns:
        patterns = ['*.json', '*.jsonl', '*.txt', '*.log']

    files = set()
    for single_pattern in patterns:
        iterator = root.rglob(single_pattern) if recursive else root.glob(single_pattern)
        for path in iterator:
            if path.is_file():
                files.add(path)
    return sorted(files)


def main():
    """
    Detect provider from one or many log files, normalize, and emit sorted events.
    """
    parser = argparse.ArgumentParser(
        description="Normalize cloud log files by auto-detecting their providers."
    )
    parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="Path to the input log file (.json/.jsonl) or a directory containing such files."
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Path to the output file for single-file mode, or a directory for batch mode."
    )
    parser.add_argument(
        "--pattern",
        default="*.json,*.jsonl,*.txt,*.log",
        help="Comma-separated glob patterns to match files when --input is a directory."
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Recursively search for files under --input when it is a directory."
    )
    args = parser.parse_args()

    if args.input.is_file():
        _process_file(args.input, args.output, force_output_dir=False, exit_on_error=True)
        return

    if not args.input.is_dir():
        print(f"Error: Input path '{args.input}' is neither a file nor a directory.", file=sys.stderr)
        sys.exit(1)

    if args.output and args.output.suffix and not args.output.is_dir():
        print("Error: When processing a directory, --output must point to a directory.", file=sys.stderr)
        sys.exit(1)

    files = _collect_input_files(args.input, args.pattern, args.recursive)
    if not files:
        print(f"No files found under '{args.input}' matching pattern '{args.pattern}'.", file=sys.stderr)
        sys.exit(1)

    successes = 0
    for file_path in files:
        print("\n==============================")
        print(f"Processing {file_path}...")
        if _process_file(file_path, args.output, force_output_dir=True, exit_on_error=False):
            successes += 1

    print("\nSummary:")
    print(f"  Total files: {len(files)}")
    print(f"  Successful : {successes}")
    print(f"  Failed     : {len(files) - successes}")
    if successes != len(files):
        sys.exit(1)


if __name__ == "__main__":
    main()
