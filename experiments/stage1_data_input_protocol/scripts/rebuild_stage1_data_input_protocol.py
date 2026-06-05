#!/usr/bin/env python3
"""Rebuild Stage-1 data/input protocol artifacts from local legacy outputs."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path, PurePosixPath


DATASETS = ("mapp", "nudt")
SPLITS = ("train", "val", "test")
BLOCKS = [(i, i + 4) for i in range(0, 64, 4)]
SEP = "[SEP]"


def stage_root_default() -> Path:
    return Path(__file__).resolve().parents[1]


def repo_root_from_stage(stage_root: Path) -> Path:
    return stage_root.parents[1]


def write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})


def read_tsv(path: Path):
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        yield from csv.DictReader(handle, delimiter="\t")


def read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8-sig"))


def safe_int(value, default: int = -1) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def sha1_text(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8", errors="replace")).hexdigest()


def packet_segments(text: str) -> list[list[str]]:
    segments: list[list[str]] = []
    cur: list[str] = []
    for tok in text.split():
        if tok == SEP:
            if cur:
                segments.append(cur)
                cur = []
            continue
        cur.append(tok)
    if cur:
        segments.append(cur)
    return segments


def hex_tokens_to_bytes(tokens: list[str]) -> bytes:
    valid = [tok.lower() for tok in tokens if tok and all(c in "0123456789abcdefABCDEF" for c in tok)]
    if not valid:
        return b""
    token_len = len(valid[0])
    valid = [tok for tok in valid if len(tok) == token_len]
    if token_len not in (2, 4):
        return b""

    candidates: list[tuple[float, int]] = []
    for overlap in range(token_len - 1, 0, -1):
        checks = 0
        hits = 0
        for prev, cur in zip(valid, valid[1:]):
            checks += 1
            if prev[-overlap:] == cur[:overlap]:
                hits += 1
        candidates.append((hits / checks if checks else 1.0, overlap))
    score, overlap = max(candidates, key=lambda x: (x[0], x[1]))
    if score < 0.60:
        return b""
    hex_string = valid[0] + "".join(tok[overlap:] for tok in valid[1:])
    if len(hex_string) % 2 == 1:
        hex_string = hex_string[:-1]
    try:
        return bytes.fromhex(hex_string)
    except ValueError:
        return b""


def first_packet_bytes(text: str) -> bytes:
    for segment in packet_segments(text):
        data = hex_tokens_to_bytes(segment)
        if data:
            return data
    return b""


def ip4(data: bytes) -> str:
    return ".".join(str(x) for x in data)


def infer_session_id(source_file: str) -> str:
    if not source_file:
        return ""
    return str(PurePosixPath(source_file.replace("\\", "/")).parent)


def parse_shortcut_fields(text: str) -> dict:
    data = first_packet_bytes(text)
    rec = {
        "first_packet_observed_len": len(data),
        "ip_version": "",
        "ip_header_len": "",
        "ip_total_len": "",
        "protocol": "",
        "protocol_name": "",
        "src_ip": "",
        "dst_ip": "",
        "src_port": "",
        "dst_port": "",
        "transport_header_len": "",
        "payload_offset": "",
        "first_packet_sha1": hashlib.sha1(data).hexdigest() if data else "",
        "payload_prefix_sha1": "",
        "flow_key_directional": "",
        "flow_key_bidir": "",
    }
    if len(data) < 20 or data[0] >> 4 != 4:
        return rec
    ihl = (data[0] & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return rec
    proto = data[9]
    proto_name = {6: "tcp", 17: "udp"}.get(proto, str(proto))
    src_ip = ip4(data[12:16])
    dst_ip = ip4(data[16:20])
    rec.update(
        {
            "ip_version": 4,
            "ip_header_len": ihl,
            "ip_total_len": int.from_bytes(data[2:4], "big"),
            "protocol": proto,
            "protocol_name": proto_name,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
        }
    )

    src_port = dst_port = transport_header_len = payload_offset = ""
    if proto == 6 and len(data) >= ihl + 20:
        src_port = int.from_bytes(data[ihl : ihl + 2], "big")
        dst_port = int.from_bytes(data[ihl + 2 : ihl + 4], "big")
        tcp_hlen = ((data[ihl + 12] >> 4) & 0x0F) * 4
        if tcp_hlen >= 20:
            transport_header_len = tcp_hlen
            payload_offset = ihl + tcp_hlen
    elif proto == 17 and len(data) >= ihl + 8:
        src_port = int.from_bytes(data[ihl : ihl + 2], "big")
        dst_port = int.from_bytes(data[ihl + 2 : ihl + 4], "big")
        transport_header_len = 8
        payload_offset = ihl + 8

    rec.update(
        {
            "src_port": src_port,
            "dst_port": dst_port,
            "transport_header_len": transport_header_len,
            "payload_offset": payload_offset,
        }
    )
    if payload_offset != "" and int(payload_offset) < len(data):
        start = int(payload_offset)
        rec["payload_prefix_sha1"] = hashlib.sha1(data[start : min(len(data), start + 32)]).hexdigest()
    if src_port != "" and dst_port != "":
        left = f"{src_ip}:{src_port}"
        right = f"{dst_ip}:{dst_port}"
        rec["flow_key_directional"] = f"{proto_name}|{left}->{right}"
        a, b = sorted([left, right])
        rec["flow_key_bidir"] = f"{proto_name}|{a}<->{b}"
    return rec


def classify_block(protocol_name: str, ihl: int, payload_offset: int, start: int, end: int) -> str:
    if ihl <= 0:
        return "unparsed"
    if end <= ihl:
        return "ipv4_header"
    if start < ihl:
        return "mixed_ipv4_transport"
    if payload_offset <= 0:
        return "transport_or_payload_unknown"
    if end <= payload_offset:
        if protocol_name == "tcp":
            return "tcp_header_or_options"
        if protocol_name == "udp":
            return "udp_header"
        return "transport_header"
    if start >= payload_offset:
        return "payload"
    return "mixed_transport_payload"


def static_offset_map() -> list[dict]:
    static = {
        (0, 4): ("IPv4 version/IHL, DSCP/ECN, total length", "same"),
        (4, 8): ("IPv4 identification, flags, fragment offset", "same"),
        (8, 12): ("IPv4 TTL, protocol, header checksum", "same"),
        (12, 16): ("IPv4 source address", "same"),
        (16, 20): ("IPv4 destination address", "same"),
        (20, 24): ("TCP source/destination ports", "UDP source/destination ports"),
        (24, 28): ("TCP sequence number", "UDP length/checksum"),
        (28, 32): ("TCP acknowledgement number", "UDP payload start"),
        (32, 36): ("TCP data offset/flags/window", "UDP payload"),
        (36, 40): ("TCP checksum/urgent pointer", "UDP payload"),
        (40, 44): ("TCP options or payload depending on TCP data offset", "UDP payload"),
        (44, 48): ("TCP options or payload depending on TCP data offset", "UDP payload"),
        (48, 52): ("TCP payload for common 20-byte TCP header flows; may include TLS/HTTP/QUIC bytes", "UDP payload"),
        (52, 56): ("payload for most flows", "UDP payload"),
        (56, 60): ("payload for most flows", "UDP payload"),
        (60, 64): ("payload for most flows", "UDP payload"),
    }
    return [
        {
            "byte_start": start,
            "byte_end_exclusive": end,
            "block_label": f"{start}-{end - 1}",
            "tcp_static_semantics": static[(start, end)][0],
            "udp_static_semantics": static[(start, end)][1],
            "note": "Offsets are IP-layer offsets after Ethernet/VLAN removal.",
        }
        for start, end in BLOCKS
    ]


def build_split_and_shortcut_manifests(downstream_root: Path, stage_root: Path):
    output_dir = stage_root / "outputs"
    shortcut_path = output_dir / "flow_shortcut_manifest_baseline_v0_2.csv"
    shortcut_fields = [
        "dataset",
        "split",
        "sample_id",
        "app_label",
        "label",
        "source_file",
        "pcap_session",
        "seq_len",
        "ip_version",
        "ip_header_len",
        "ip_total_len",
        "protocol_name",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "payload_offset",
        "first_packet_observed_len",
        "text_sha1",
        "first_packet_sha1",
        "payload_prefix_sha1",
        "flow_key_bidir",
    ]
    split_rows: list[dict] = []
    leakage_values: dict[tuple[str, str], dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    offset_counts: Counter[tuple[str, str, str, str, str]] = Counter()
    class_counts: Counter[tuple[str, str]] = Counter()
    class_sets: dict[tuple[str, str], dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))

    with shortcut_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=shortcut_fields)
        writer.writeheader()
        for dataset in DATASETS:
            for split in SPLITS:
                path = downstream_root / dataset / "baseline" / f"{split}.tsv"
                app_counter: Counter[str] = Counter()
                label_counter: Counter[str] = Counter()
                seq_values: list[int] = []
                rows = 0
                for row in read_tsv(path):
                    text = row.get("text_a", "")
                    shortcut = parse_shortcut_fields(text)
                    rec = {
                        "dataset": dataset,
                        "split": split,
                        "sample_id": row.get("sample_id", ""),
                        "app_label": row.get("app_label", ""),
                        "label": row.get("label", ""),
                        "source_file": row.get("source_file", ""),
                        "pcap_session": infer_session_id(row.get("source_file", "")),
                        "seq_len": safe_int(row.get("seq_len")),
                        "text_sha1": sha1_text(text),
                    }
                    rec.update(shortcut)
                    writer.writerow({field: rec.get(field, "") for field in shortcut_fields})

                    rows += 1
                    app_counter[rec["app_label"]] += 1
                    label_counter[rec["label"]] += 1
                    if rec["seq_len"] != -1:
                        seq_values.append(rec["seq_len"])

                    for key_type in ("sample_id", "source_file", "pcap_session", "text_sha1", "first_packet_sha1", "payload_prefix_sha1", "flow_key_bidir"):
                        value = str(rec.get(key_type, ""))
                        if value:
                            leakage_values[(dataset, key_type)][value].append(split)
                            class_sets[(dataset, str(rec["app_label"]))][key_type].add(value)
                    class_counts[(dataset, str(rec["app_label"]))] += 1

                    proto = str(rec.get("protocol_name", ""))
                    ihl = safe_int(rec.get("ip_header_len"), 0)
                    payload_offset = safe_int(rec.get("payload_offset"), 0)
                    for start, end in BLOCKS:
                        region = classify_block(proto, ihl, payload_offset, start, end)
                        offset_counts[(dataset, split, f"{start}-{end - 1}", proto, region)] += 1

                split_rows.append(
                    {
                        "dataset": dataset,
                        "role": "discovery" if dataset == "mapp" else "external_validation",
                        "variant": "baseline",
                        "split": split,
                        "relative_path": f"LEGACY/h100_downstream_50class_ablation_package_20260604/data/downstream_50class_ablation/{dataset}/baseline/{split}.tsv",
                        "rows": rows,
                        "class_count": len(app_counter),
                        "label_count": len(label_counter),
                        "min_per_class": min(app_counter.values()) if app_counter else 0,
                        "max_per_class": max(app_counter.values()) if app_counter else 0,
                        "seq_min": min(seq_values) if seq_values else "",
                        "seq_max": max(seq_values) if seq_values else "",
                    }
                )

    return split_rows, summarize_leakage(leakage_values), summarize_offsets(offset_counts), summarize_strict_split_feasibility(class_counts, class_sets)


def summarize_leakage(values: dict[tuple[str, str], dict[str, list[str]]]) -> list[dict]:
    rows: list[dict] = []
    for (dataset, key_type), value_map in sorted(values.items()):
        leaking = []
        sample_count = 0
        for value, splits in value_map.items():
            unique = sorted(set(splits))
            if len(unique) > 1:
                leaking.append((value, unique, len(splits)))
                sample_count += len(splits)
        rows.append(
            {
                "dataset": dataset,
                "key_type": key_type,
                "leaking_key_count": len(leaking),
                "leaking_sample_count": sample_count,
                "example_keys": " | ".join(f"{v}=>{','.join(s)}" for v, s, _ in leaking[:3]),
            }
        )
    return rows


def summarize_offsets(counts: Counter[tuple[str, str, str, str, str]]) -> list[dict]:
    totals: Counter[tuple[str, str, str, str]] = Counter()
    for dataset, split, block, proto, region in counts:
        totals[(dataset, split, block, proto)] += counts[(dataset, split, block, proto, region)]
    rows: list[dict] = []
    for (dataset, split, block, proto, region), count in sorted(counts.items()):
        total = totals[(dataset, split, block, proto)]
        rows.append(
            {
                "dataset": dataset,
                "split": split,
                "block": block,
                "protocol_name": proto,
                "semantic_region": region,
                "count": count,
                "proportion_within_protocol_block": round(count / total, 6) if total else "",
            }
        )
    return rows


def summarize_strict_split_feasibility(class_counts: Counter[tuple[str, str]], class_sets: dict[tuple[str, str], dict[str, set[str]]]) -> list[dict]:
    rows: list[dict] = []
    for (dataset, app_label), rows_total in sorted(class_counts.items()):
        sets = class_sets[(dataset, app_label)]
        session_count = len(sets.get("pcap_session", set()))
        flow_key_count = len(sets.get("flow_key_bidir", set()))
        text_count = len(sets.get("text_sha1", set()))
        first_packet_count = len(sets.get("first_packet_sha1", set()))
        payload_prefix_count = len(sets.get("payload_prefix_sha1", set()))
        rows.append(
            {
                "dataset": dataset,
                "app_label": app_label,
                "rows": rows_total,
                "unique_pcap_sessions": session_count,
                "unique_flow_keys": flow_key_count,
                "unique_text_hashes": text_count,
                "unique_first_packet_hashes": first_packet_count,
                "unique_payload_prefix_hashes": payload_prefix_count,
                "session_level_split_feasible_in_current_tsv": "yes" if session_count >= 3 else "no",
                "exact_text_dedup_loss": rows_total - text_count,
                "note": "Need at least 3 independent sessions per class for train/val/test session-disjoint split.",
            }
        )
    return rows


def strict_split_policy_rows() -> list[dict]:
    return [
        {
            "constraint_id": "SP-001",
            "level": "hard",
            "field_or_group": "sample_id",
            "rule": "No identical sample_id may appear in more than one split.",
            "reason": "Prevents direct flow duplication leakage.",
        },
        {
            "constraint_id": "SP-002",
            "level": "hard",
            "field_or_group": "source_file",
            "rule": "No identical source_file may appear in more than one split.",
            "reason": "Prevents exact file reuse across train/val/test.",
        },
        {
            "constraint_id": "SP-003",
            "level": "hard",
            "field_or_group": "text_sha1,first_packet_sha1",
            "rule": "Exact duplicated TrafficFormer text or first packet must be assigned to one split only or removed.",
            "reason": "Prevents exact and near-exact input leakage.",
        },
        {
            "constraint_id": "SP-004",
            "level": "hard",
            "field_or_group": "flow_key_bidir",
            "rule": "Bidirectional five-tuple groups should not cross train/val/test.",
            "reason": "Reduces IP/port shortcut leakage.",
        },
        {
            "constraint_id": "SP-005",
            "level": "preferred_hard_for_final",
            "field_or_group": "pcap_session",
            "rule": "When raw data provide enough sessions, pcap/session groups should be split-disjoint.",
            "reason": "Network traffic often leaks session/capture-specific shortcuts.",
        },
        {
            "constraint_id": "SP-006",
            "level": "hard",
            "field_or_group": "class_balance",
            "rule": "Keep fixed class list and deterministic target counts per class whenever feasible.",
            "reason": "Keeps static classification and later class-incremental tasks comparable.",
        },
        {
            "constraint_id": "SP-007",
            "level": "protocol",
            "field_or_group": "dataset_role",
            "rule": "Use MAPP for discovery and NUDT for external validation only.",
            "reason": "Avoids tuning representation explanations to both datasets at once.",
        },
    ]


def build_cil_manifest(downstream_root: Path) -> list[dict]:
    rows: list[dict] = []
    for dataset in DATASETS:
        mapping = read_json(downstream_root / dataset / "label_mapping.json")
        id_to_label = mapping.get("id_to_label", {})
        for raw_id in sorted(id_to_label, key=lambda x: int(x)):
            idx = int(raw_id)
            rows.append(
                {
                    "dataset": dataset,
                    "role": "discovery" if dataset == "mapp" else "external_validation",
                    "task_id": idx // 10,
                    "class_order_index": idx,
                    "label_id": idx,
                    "app_label": id_to_label[raw_id],
                    "task_design": "50 classes split into 5 tasks of 10 labels in fixed label-id order",
                }
            )
    return rows


def mutation_protocol_rows() -> list[dict]:
    rows: list[dict] = []
    for start, end in BLOCKS:
        for mode in ("mask_in_place", "physical_delete"):
            rows.append(
                {
                    "mutation_mode": mode,
                    "byte_start": start,
                    "byte_end_exclusive": end,
                    "block_label": f"{start}-{end - 1}",
                    "current_role": "primary_clean_ablation" if mode == "mask_in_place" else "perturbation_control",
                    "definition": (
                        "Replace target-overlapping tokens with [MASK] without changing segment length or downstream positions."
                        if mode == "mask_in_place"
                        else "Remove target bytes and regenerate overlapping tokens; changes length and downstream positions."
                    ),
                }
            )
    return rows


def source_manifest(legacy_root: Path) -> list[dict]:
    sources = [
        ("stage1_builder", "build_foundation_stage1_tsv.py", "Prior raw pcap to TrafficFormer TSV builder"),
        ("effective_packet_audit", "effective_packet_audit/mapp_nudt_effective_packet_gt16_summary.json", "Effective packet count audit"),
        ("foundation_stage1_summary", "foundation_stage1_tsv/foundation_stage1_tsv/foundation_stage1_tsv_summary.json", "Prior Stage-1 foundation TSV summary"),
        ("downstream_validation", "h100_downstream_50class_ablation_package_20260604/data/downstream_50class_ablation/validation_summary.json", "Formal 50-class split validation"),
        ("byte_block_generator", "foundation_space_experiment/run_packet_byte_block_tsv_multiprocess.py", "Legacy byte-block mutation generator"),
        ("position_aware_report", "foundation_token_ablation_tsvs/foundation_token_ablation_tsvs/reports/position_aware_ablation_report.md", "Legacy semantic token ablation report"),
    ]
    rows = []
    for source_id, rel, purpose in sources:
        rows.append(
            {
                "source_id": source_id,
                "relative_path": f"LEGACY/{rel}",
                "exists": (legacy_root / rel).exists(),
                "purpose": purpose,
            }
        )
    return rows


def write_protocol_config(path: Path, outputs: dict) -> None:
    config = {
        "stage": "stage1_data_input_protocol",
        "version": "v0.2",
        "created_at": str(date.today()),
        "dataset_roles": {
            "MAPP": "discovery and method tuning",
            "NUDT": "external validation only",
        },
        "effective_flow_rule": {
            "packet_types": "IPv4 TCP or UDP",
            "excluded_packets": ["TCP SYN handshake", "empty payload", "non-IP"],
            "minimum_effective_packet_count": 17,
        },
        "trafficformer_input_rule": {
            "packet_scope": "first 8 effective packets",
            "byte_scope": "first 64 IP-layer bytes after Ethernet/VLAN removal",
            "separator": "[SEP]",
            "max_tokens": 512,
            "tokenization_note": "Legacy artifacts contain both byte-level and overlapping hex-window tokenizations; the audit script detects both for metadata extraction.",
        },
        "current_mutation_protocol": {
            "primary": "mask_in_place sweep over all 4-byte blocks 0-3 through 60-63",
            "control": "physical_delete sweep over all 4-byte blocks, interpreted only as perturbation/layout sensitivity",
            "not_primary": "legacy fixed-block physical delete results are historical context, not the current main hypothesis",
        },
        "class_incremental_protocol": {
            "num_classes": 50,
            "num_tasks": 5,
            "classes_per_task": 10,
            "task_order": "fixed label-id order",
        },
        "outputs": outputs,
    }
    path.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")


def write_protocol_report(path: Path, split_rows: list[dict], leakage_rows: list[dict], outputs: dict) -> None:
    exact_blockers = [
        row for row in leakage_rows
        if row["key_type"] in {"sample_id", "source_file", "text_sha1", "first_packet_sha1", "payload_prefix_sha1", "flow_key_bidir"}
        and int(row["leaking_key_count"]) > 0
    ]
    session_risks = [
        row for row in leakage_rows
        if row["key_type"] == "pcap_session" and int(row["leaking_key_count"]) > 0
    ]
    gate = "pass"
    if exact_blockers:
        gate = "needs_strict_resplit_before_final_metrics"
    elif session_risks:
        gate = "pass_with_session_shortcut_caution"

    lines = [
        "# Stage 1 Data Input Protocol Report",
        "",
        "## Current Scope",
        "",
        "This stage fixes data reading, split metadata, TrafficFormer input interpretation, shortcut fields, leakage checks, and absolute byte-offset semantics.",
        "",
        "Legacy fixed-block delete results are not the current main experiment. The current byte protocol is a full 4-byte block sweep from `0-3` through `60-63`, with `mask_in_place` as the primary clean ablation.",
        "",
        "## Split Summary",
        "",
        "| dataset | role | split | rows | classes | min/class | max/class | seq_min | seq_max |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in split_rows:
        lines.append(
            f"| {row['dataset']} | {row['role']} | {row['split']} | {row['rows']} | {row['class_count']} | {row['min_per_class']} | {row['max_per_class']} | {row['seq_min']} | {row['seq_max']} |"
        )
    lines += [
        "",
        "## Leakage And Shortcut Audit",
        "",
        "| dataset | key_type | leaking_keys | leaking_samples | examples |",
        "|---|---|---:|---:|---|",
    ]
    for row in leakage_rows:
        lines.append(
            f"| {row['dataset']} | {row['key_type']} | {row['leaking_key_count']} | {row['leaking_sample_count']} | {row.get('example_keys', '')} |"
        )
    lines += [
        "",
        "## Gate",
        "",
        f"Stage 1 gate: `{gate}`.",
        "",
        "Exact duplicate or shortcut leakage must be resolved by stricter split generation before final metrics are claimed. Existing legacy splits can still be used as audit inputs and smoke baselines.",
        "",
        "## Strict Split Policy",
        "",
        "Final metrics should use a deterministic strict split built from the fixed class list while preventing duplicate sample ids, duplicate source files, exact text duplicates, first-packet duplicates, bidirectional five-tuple reuse, and session/capture leakage whenever the raw data provide enough independent sessions.",
        "",
        "The policy is tracked in `manifests/stage1_strict_split_policy.csv`; current TSV feasibility diagnostics are generated in `outputs/stage1_strict_split_feasibility.csv`.",
        "",
        "## Generated Local Outputs",
        "",
    ]
    for key, value in outputs.items():
        lines.append(f"- `{key}`: `{value}`")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def append_file_manifest(repo_root: Path, stage_rel: str, entries: list[tuple[str, str, str, str]]) -> None:
    path = repo_root / "docs" / "file_manifest.csv"
    existing: list[dict] = []
    if path.exists():
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            existing = list(csv.DictReader(handle))
    fields = list(existing[0].keys())
    existing = [row for row in existing if not row.get("record_id", "").startswith("STAGE1-")]
    today = str(date.today())
    rows = []
    for idx, (artifact_type, rel_path, file_name, purpose) in enumerate(entries, start=1):
        rows.append(
            {
                "record_id": f"STAGE1-{idx:04d}",
                "stage": "stage1",
                "artifact_type": artifact_type,
                "dataset": "mapp,nudt",
                "experiment": "data_input_protocol",
                "method": "protocol_rebuild",
                "split": "train,val,test",
                "task_id": "",
                "block_range": "0-63",
                "relative_path": f"{stage_rel}/{rel_path}",
                "absolute_path": f"REPO_ROOT/{stage_rel}/{rel_path}",
                "file_name": file_name,
                "file_format": file_name.rsplit(".", 1)[-1],
                "purpose": purpose,
                "description": purpose,
                "source_or_parent": "legacy_local_outputs",
                "generated_by": f"{stage_rel}/scripts/rebuild_stage1_data_input_protocol.py",
                "config_path": f"{stage_rel}/configs/stage1_data_input_protocol.json",
                "depends_on": "LEGACY/project outputs",
                "status": "active",
                "version": "v0.2",
                "created_at": today,
                "last_updated": today,
                "checksum_sha256": "",
                "git_commit": "",
                "notes": "",
            }
        )
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(existing + rows)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage_root", default=str(stage_root_default()))
    parser.add_argument("--legacy_root", default="")
    args = parser.parse_args()

    stage_root = Path(args.stage_root).resolve()
    repo_root = repo_root_from_stage(stage_root)
    legacy_root = Path(args.legacy_root).resolve() if args.legacy_root else repo_root.parent / "project"
    downstream_root = legacy_root / "h100_downstream_50class_ablation_package_20260604" / "data" / "downstream_50class_ablation"

    split_rows, leakage_rows, offset_rows, feasibility_rows = build_split_and_shortcut_manifests(downstream_root, stage_root)
    cil_rows = build_cil_manifest(downstream_root)
    mutation_rows = mutation_protocol_rows()
    strict_policy_rows = strict_split_policy_rows()
    sources = source_manifest(legacy_root)
    offsets = static_offset_map()

    write_csv(stage_root / "manifests" / "stage1_split_manifest.csv", split_rows, ["dataset", "role", "variant", "split", "relative_path", "rows", "class_count", "label_count", "min_per_class", "max_per_class", "seq_min", "seq_max"])
    write_csv(stage_root / "manifests" / "stage1_cil_task_manifest.csv", cil_rows, ["dataset", "role", "task_id", "class_order_index", "label_id", "app_label", "task_design"])
    write_csv(stage_root / "manifests" / "stage1_mutation_protocol.csv", mutation_rows, ["mutation_mode", "byte_start", "byte_end_exclusive", "block_label", "current_role", "definition"])
    write_csv(stage_root / "manifests" / "stage1_strict_split_policy.csv", strict_policy_rows, ["constraint_id", "level", "field_or_group", "rule", "reason"])
    write_csv(stage_root / "manifests" / "stage1_offset_semantic_map.csv", offsets, ["byte_start", "byte_end_exclusive", "block_label", "tcp_static_semantics", "udp_static_semantics", "note"])
    write_csv(stage_root / "manifests" / "stage1_protocol_sources.csv", sources, ["source_id", "relative_path", "exists", "purpose"])
    write_csv(stage_root / "outputs" / "stage1_leakage_summary.csv", leakage_rows, ["dataset", "key_type", "leaking_key_count", "leaking_sample_count", "example_keys"])
    write_csv(stage_root / "outputs" / "stage1_offset_semantic_observed.csv", offset_rows, ["dataset", "split", "block", "protocol_name", "semantic_region", "count", "proportion_within_protocol_block"])
    write_csv(stage_root / "outputs" / "stage1_strict_split_feasibility.csv", feasibility_rows, ["dataset", "app_label", "rows", "unique_pcap_sessions", "unique_flow_keys", "unique_text_hashes", "unique_first_packet_hashes", "unique_payload_prefix_hashes", "session_level_split_feasible_in_current_tsv", "exact_text_dedup_loss", "note"])

    stage_rel = "experiments/stage1_data_input_protocol"
    outputs = {
        "flow_shortcut_manifest": f"{stage_rel}/outputs/flow_shortcut_manifest_baseline_v0_2.csv",
        "leakage_summary": f"{stage_rel}/outputs/stage1_leakage_summary.csv",
        "observed_offset_semantics": f"{stage_rel}/outputs/stage1_offset_semantic_observed.csv",
        "strict_split_feasibility": f"{stage_rel}/outputs/stage1_strict_split_feasibility.csv",
    }
    write_protocol_config(stage_root / "configs" / "stage1_data_input_protocol.json", outputs)
    write_protocol_report(stage_root / "reports" / "stage1_data_input_protocol_report.md", split_rows, leakage_rows, outputs)
    summary = {
        "status": "success",
        "split_rows": len(split_rows),
        "cil_rows": len(cil_rows),
        "mutation_rows": len(mutation_rows),
        "strict_policy_rows": len(strict_policy_rows),
        "strict_feasibility_rows": len(feasibility_rows),
        "offset_rows": len(offset_rows),
        "leakage_rows": len(leakage_rows),
        "outputs": outputs,
    }
    (stage_root / "outputs" / "stage1_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    append_file_manifest(
        repo_root,
        stage_rel,
        [
            ("script", "scripts/rebuild_stage1_data_input_protocol.py", "rebuild_stage1_data_input_protocol.py", "Rebuild Stage 1 protocol artifacts"),
            ("config", "configs/stage1_data_input_protocol.json", "stage1_data_input_protocol.json", "Fixed Stage 1 data/input protocol"),
            ("manifest", "manifests/stage1_split_manifest.csv", "stage1_split_manifest.csv", "Baseline train/val/test split manifest"),
            ("manifest", "manifests/stage1_cil_task_manifest.csv", "stage1_cil_task_manifest.csv", "Class-incremental task manifest"),
            ("manifest", "manifests/stage1_mutation_protocol.csv", "stage1_mutation_protocol.csv", "Full byte-block mutation protocol"),
            ("manifest", "manifests/stage1_strict_split_policy.csv", "stage1_strict_split_policy.csv", "Strict split policy for final metrics"),
            ("manifest", "manifests/stage1_offset_semantic_map.csv", "stage1_offset_semantic_map.csv", "Static absolute offset semantic map"),
            ("manifest", "manifests/stage1_protocol_sources.csv", "stage1_protocol_sources.csv", "Legacy source manifest"),
            ("report", "reports/stage1_data_input_protocol_report.md", "stage1_data_input_protocol_report.md", "Stage 1 protocol and leakage report"),
            ("local_output", "outputs/flow_shortcut_manifest_baseline_v0_2.csv", "flow_shortcut_manifest_baseline_v0_2.csv", "Full per-flow shortcut manifest"),
            ("local_output", "outputs/stage1_leakage_summary.csv", "stage1_leakage_summary.csv", "Leakage summary output"),
            ("local_output", "outputs/stage1_offset_semantic_observed.csv", "stage1_offset_semantic_observed.csv", "Observed offset semantic output"),
            ("local_output", "outputs/stage1_strict_split_feasibility.csv", "stage1_strict_split_feasibility.csv", "Strict split feasibility output"),
        ],
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
