import argparse
import json
from collections import Counter
from datetime import datetime
from time import perf_counter
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


def _load_events(path: Path) -> Dict[str, dict]:
    events: Dict[str, dict] = {}
    fallback = 0
    with open(path, "rt", encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, start=1):
            stripped = raw.strip()
            if not stripped:
                continue
            try:
                data = json.loads(stripped)
            except json.JSONDecodeError as exc:
                print(f"[WARN] Skip line {line_number} in '{path}': {exc}")
                continue
            if not isinstance(data, dict):
                continue
            event_id = data.get("event_id")
            if not event_id:
                fallback += 1
                event_id = f"__synthetic_{line_number}_{fallback}"
            elif event_id in events:
                # ensure uniqueness to keep both records
                fallback += 1
                event_id = f"{event_id}__dup{fallback}"
            events[event_id] = data
    return events


def _read_first_operation(path: Path) -> Optional[str]:
    with open(path, "rt", encoding="utf-8") as handle:
        for raw in handle:
            stripped = raw.strip()
            if not stripped:
                continue
            try:
                data = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            action = data.get("action") or {}
            op = action.get("operation")
            if isinstance(op, str) and op:
                return op.lower()
            return None
    return None


def _count_events(path: Path, limit: Optional[int] = None) -> int:
    count = 0
    with open(path, "rt", encoding="utf-8") as handle:
        for raw in handle:
            if raw.strip():
                count += 1
                if limit and count >= limit:
                    return count
    return count


def _action_key(event: dict) -> str:
    action = event.get("action") or {}
    service = action.get("service", "unknown")
    operation = action.get("operation", "unknown")
    return f"{service}:{operation}"


def _summarize_actions(events: Dict[str, dict]) -> Counter:
    counter: Counter = Counter()
    for event in events.values():
        counter[_action_key(event)] += 1
    return counter


def _format_counter_diff(
    c1: Counter, c2: Counter, top_n: int
) -> Iterable[Tuple[str, int]]:
    keys = set(c1) | set(c2)
    deltas = []
    for key in keys:
        delta = c1.get(key, 0) - c2.get(key, 0)
        if delta != 0:
            deltas.append((key, delta))
    deltas.sort(key=lambda item: abs(item[1]), reverse=True)
    if top_n > 0:
        deltas = deltas[:top_n]
    return deltas


def jaccard_distance(a: Iterable, b: Iterable) -> float:
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 0.0
    return 1.0 - len(sa & sb) / len(sa | sb)


def normalized_levenshtein(s1: Sequence, s2: Sequence) -> float:
    if not s1 and not s2:
        return 0.0
    m, n = len(s1), len(s2)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            dp[i][j] = min(
                dp[i - 1][j] + 1,
                dp[i][j - 1] + 1,
                dp[i - 1][j - 1] + cost,
            )
    raw = dp[m][n]
    return raw / max(m, n)


def normalized_hamming(v1: Sequence, v2: Sequence) -> float:
    if len(v1) != len(v2):
        raise ValueError("Hamming distance requires vectors of equal length.")
    if not v1:
        return 0.0
    diff = sum(el1 != el2 for el1, el2 in zip(v1, v2))
    return diff / len(v1)


def composite_score(
    Vacc_obs: Iterable,
    Vacc_base: Iterable,
    Vtype_obs: Iterable,
    Vtype_base: Iterable,
    Vng_obs: Sequence,
    Vng_base: Sequence,
    Vflag_obs: Sequence,
    Vflag_base: Sequence,
    weights: Dict[str, float],
) -> float:
    return (
        weights["actions"] * jaccard_distance(Vacc_obs, Vacc_base)
        + weights["vtypes"] * jaccard_distance(Vtype_obs, Vtype_base)
        + weights["ngrams"] * normalized_levenshtein(Vng_obs, Vng_base)
        + weights["flags"] * normalized_hamming(Vflag_obs, Vflag_base)
    )


def _parse_timestamp(value: str) -> datetime:
    if not value:
        return datetime.min
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return datetime.min


SENSITIVE_KEYWORDS = (
    # Aws Specific
    "Delete",
    "Detach",
    "Stop",
    "Disable",
    "PutBucketPolicy",
    "AttachRolePolicy",
    "PassRole",
    "RunInstances",
    "StartSession",
    "ExecuteCommand",
    "TerminateInstances",
    "DeleteCluster",
    "DeleteRole",
    "DeleteObject",
    "GetObject",
    "ListBuckets",
    "Decrypt",
    "GetSecretValue",
    # Azure Specific
    "AzurePipelines:Job.Log",
    "secrets/get/action",
    "workflows/write",
    "listKeys/action",
    "roleAssignments/write",
    "runCommand/action",
    "networkSecurityGroups/write",
    "regenerateKey/action",
)


def _is_sensitive(action_key: str) -> bool:
    return any(keyword.lower() in action_key.lower() for keyword in SENSITIVE_KEYWORDS)


def _build_action_sequence(events: List[dict]) -> List[str]:
    return [_action_key(evt) for evt in events]


def _build_resource_types(events: List[dict]) -> List[str]:
    types = []
    for evt in events:
        for resource in evt.get("resources") or []:
            rtype = resource.get("type")
            if rtype:
                types.append(rtype)
    return types


def _build_ngrams(actions: List[str], n: int) -> List[str]:
    if n <= 1 or len(actions) < n:
        return actions[:]
    return ["->".join(actions[i : i + n]) for i in range(len(actions) - n + 1)]


def _build_flags(actions: List[str]) -> List[int]:
    return [1 if _is_sensitive(action) else 0 for action in actions]


def _extract_features(events: Dict[str, dict], ngram_n: int) -> Dict[str, List]:
    sorted_events = sorted(
        events.values(), key=lambda evt: _parse_timestamp(evt.get("timestamp"))
    )
    action_seq = _build_action_sequence(sorted_events)
    return {
        "actions_set": set(action_seq),
        "resource_types": set(_build_resource_types(sorted_events)),
        "ngrams": _build_ngrams(action_seq, ngram_n),
        "flags": _build_flags(action_seq),
    }


def _align_vectors(v1: Sequence[int], v2: Sequence[int]) -> Tuple[List[int], List[int]]:
    max_len = max(len(v1), len(v2))
    v1_aligned = list(v1) + [0] * (max_len - len(v1))
    v2_aligned = list(v2) + [0] * (max_len - len(v2))
    return v1_aligned, v2_aligned


DEFAULT_WEIGHTS = {
    "actions": 0.2,
    "vtypes": 0.2,
    "ngrams": 0.2,
    "flags": 0.4,
}


def _format_divergent(items: List[Tuple[str, int]], prefix: str) -> str:
    if not items:
        return "None"
    return ", ".join(f"{action} ({prefix}{delta})" for action, delta in items)


def _describe_divergent_actions(
    baseline_path: Path, observed_path: Path, top_n: int = 3
) -> Dict[str, List[Tuple[str, int]]]:
    base_events = _load_events(baseline_path)
    obs_events = _load_events(observed_path)
    if not base_events or not obs_events:
        return {"unexpected": [], "anomalous": []}

    base_counter = _summarize_actions(base_events)
    obs_counter = _summarize_actions(obs_events)

    unexpected = [
        (key, obs_counter[key] - base_counter.get(key, 0))
        for key in obs_counter
        if obs_counter[key] > base_counter.get(key, 0)
    ]
    unexpected.sort(key=lambda item: item[1], reverse=True)

    anomalous = [
        (key, base_counter[key] - obs_counter.get(key, 0))
        for key in base_counter
        if base_counter[key] > obs_counter.get(key, 0)
    ]
    anomalous.sort(key=lambda item: item[1], reverse=True)

    return {
        "unexpected": unexpected[:top_n],
        "anomalous": anomalous[:top_n],
    }


def _compute_score(
    baseline_path: Path,
    observed_path: Path,
    ngram_size: int,
    weights: Dict[str, float],
) -> float:
    events_base = _load_events(baseline_path)
    events_obs = _load_events(observed_path)
    if not events_base or not events_obs:
        raise ValueError("Empty event set for comparison.")

    features_base = _extract_features(events_base, ngram_size)
    features_obs = _extract_features(events_obs, ngram_size)
    flags_base_aligned, flags_obs_aligned = _align_vectors(
        features_base["flags"], features_obs["flags"]
    )

    return composite_score(
        features_obs["actions_set"],
        features_base["actions_set"],
        features_obs["resource_types"],
        features_base["resource_types"],
        features_obs["ngrams"],
        features_base["ngrams"],
        flags_obs_aligned,
        flags_base_aligned,
        weights,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Scan observed JSONL logs, match samples in the baseline directory"
            " whose filenames contain the same operation, and compute anomaly scores."
        )
    )
    parser.add_argument("baseline_dir", type=Path, help="Path to the baseline JSONL directory.")
    parser.add_argument("observed_dir", type=Path, help="Path to the observed JSONL directory.")
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.6,
        help="Threshold for flagging risk (default 0.6).",
    )
    parser.add_argument(
        "--ngram-size",
        type=int,
        default=3,
        help="n-gram length used in feature extraction (default 3).",
    )
    args = parser.parse_args()

    baseline_dir = args.baseline_dir
    observed_dir = args.observed_dir
    start_time = perf_counter()

    if not baseline_dir.is_dir() or not observed_dir.is_dir():
        raise SystemExit("Both arguments must be valid directories.")

    risk_logs: List[Tuple[str, str, float, Dict[str, List[Tuple[str, int]]]]] = []
    baseline_files = list(baseline_dir.glob("*.jsonl"))
    if not baseline_files:
        raise SystemExit("No JSONL files found under the baseline directory.")

    job_start_baseline = next(
        (path for path in baseline_files if "job.start" in path.name.lower()), None
    )
    logicapp_baseline = next(
        (path for path in baseline_files if "logicapp" in path.name.lower()), None
    )

    combo_total = 0

    for observed_path in sorted(observed_dir.glob("*.jsonl")):
        event_count = _count_events(observed_path, limit=5)
        if event_count < 5:
            continue
        operation_fragment = _read_first_operation(observed_path)
        if not operation_fragment:
            continue

        candidates: List[Path] = []
        if "job.start" in operation_fragment and job_start_baseline:
            candidates = [job_start_baseline]
        elif logicapp_baseline:
            candidates = [logicapp_baseline]
        if not candidates:
            candidates = [
                base_path
                for base_path in baseline_files
                if operation_fragment in base_path.name.lower()
            ]
        if not candidates:
            # print(
            #     f"[SKIP] {observed_path.name}: no baseline filename contains '{operation_fragment}'"
            # )
            continue

        best_score: Optional[float] = None
        best_baseline: Optional[Path] = None

        for base_path in candidates:
            combo_total += 1
            try:
                score = _compute_score(
                    base_path, observed_path, args.ngram_size, DEFAULT_WEIGHTS
                )
            except Exception as exc:  # noqa: BLE001
                # print(
                #     f"[WARN] Comparison failed {base_path.name} vs {observed_path.name}: {exc}"
                # )
                continue
            if best_score is None or score > best_score:
                best_score = score
                best_baseline = base_path

        if best_score is None or best_baseline is None:
            # print(f"[SKIP] {observed_path.name}: unable to compute score")
            continue

        if best_score > args.threshold:
            divergent = _describe_divergent_actions(best_baseline, observed_path)
            unexpected_desc = _format_divergent(divergent["unexpected"], "+")
            anomalous_desc = _format_divergent(divergent["anomalous"], "-")
            risk_logs.append(
                (observed_path.name, best_baseline.name, best_score, divergent)
            )
            # print(
            #     f"[RISK] {observed_path.name} ↔ {best_baseline.name}\n"
            #     f"       score={best_score:.4f}\n"
            #     f"       Divergent Actions:\n"
            #     f"         - Unexpected : {unexpected_desc}\n"
            #     f"         - Anomalous  : {anomalous_desc}"
            # )
        else:
            # print(
            #     f"[OK]   {observed_path.name} ↔ {best_baseline.name} | "
            #     f"score={best_score:.4f}"
            # )
            pass

    elapsed = perf_counter() - start_time

    if risk_logs:
        print("\n=== Risk Logs ===")
        for obs_name, base_name, score, divergent in risk_logs:
            unexpected_desc = _format_divergent(divergent["unexpected"], "+")
            anomalous_desc = _format_divergent(divergent["anomalous"], "-")
            print(
                f"{obs_name}\n"
                f"  baseline : {base_name}\n"
                f"  score    : {score:.4f}\n"
                f"  Unexpected: {unexpected_desc}\n"
                f"  Anomalous : {anomalous_desc}\n"
            )
        print(f"\nTotal risk logs: {len(risk_logs)}")
    else:
        print("\nNo risk logs detected.")

    print(
        f"\nEvaluated combinations: {combo_total} | "
        f"Elapsed time: {elapsed:.2f}s"
    )


if __name__ == "__main__":
    main()


