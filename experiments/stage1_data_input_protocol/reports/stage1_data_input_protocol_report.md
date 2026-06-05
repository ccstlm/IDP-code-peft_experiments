# Stage 1 Data Input Protocol Report

## Current Scope

This stage fixes data reading, split metadata, TrafficFormer input interpretation, shortcut fields, leakage checks, and absolute byte-offset semantics.

Legacy fixed-block delete results are not the current main experiment. The current byte protocol is a full 4-byte block sweep from `0-3` through `60-63`, with `mask_in_place` as the primary clean ablation.

## Split Summary

| dataset | role | split | rows | classes | min/class | max/class | seq_min | seq_max |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| mapp | discovery | train | 35000 | 50 | 700 | 700 | 66 | 512 |
| mapp | discovery | val | 5000 | 50 | 100 | 100 | 66 | 512 |
| mapp | discovery | test | 10000 | 50 | 200 | 200 | 66 | 512 |
| nudt | external_validation | train | 35000 | 50 | 700 | 700 | 510 | 510 |
| nudt | external_validation | val | 5000 | 50 | 100 | 100 | 510 | 510 |
| nudt | external_validation | test | 10000 | 50 | 200 | 200 | 510 | 510 |

## Leakage And Shortcut Audit

| dataset | key_type | leaking_keys | leaking_samples | examples |
|---|---|---:|---:|---|
| mapp | first_packet_sha1 | 74 | 148 | 818b79ef4a6179839bc523f7dfee4f3f06392834=>test,train | 56c57e4aad8927ca02a6a583d6964c910d3c6246=>test,train | e89cf8f423f164c0da876985c5d806925f629ea2=>train,val |
| mapp | flow_key_bidir | 98 | 208 | udp|192.168.137.1:137<->192.168.137.255:137=>train,val | udp|192.168.137.125:40435<->192.168.137.1:53=>test,train | tcp|148.78.37.7:443<->192.168.137.28:48813=>test,train |
| mapp | payload_prefix_sha1 | 1597 | 14969 | 1e76cf674b19eb64502ae502b0334359f66c86b8=>test,train,val | d6a0b73513b07a467dd1927f99a84995eeefc83e=>test,train,val | fb9f0ffe612ed6c9b69ddb3ba772e90eee75578b=>test,train,val |
| mapp | pcap_session | 83 | 50000 | /lvs/lm/LiMeng/01_dataset/mapp/raw_split/nhaccuatui/nhac_4_230m_3.6pm_07022021.pcap=>test,train,val | /lvs/lm/LiMeng/01_dataset/mapp/raw_split/iQIYI/iQIYI_3_200m_2pm_25022021.pcap=>test,train,val | /lvs/lm/LiMeng/01_dataset/mapp/raw_split/chess/chess_8_2.25h_11am_13042021.pcap=>test,train,val |
| mapp | sample_id | 14 | 28 | mapp_instagram_bf000238_udp=>test,train | mapp_instagram_bf000570_udp=>test,train | mapp_instagram_bf000761_udp=>train,val |
| mapp | source_file | 0 | 0 |  |
| mapp | text_sha1 | 74 | 148 | 297022f56e2592b9613885c73ce0f56ed123ecb6=>test,train | 1ab2d16dbd441145bc51f5cb3eeba0054341dc30=>test,train | d15994602bd267d4ddc77513e43afe1bbb5f7fed=>train,val |
| nudt | first_packet_sha1 | 0 | 0 |  |
| nudt | flow_key_bidir | 207 | 417 | tcp|10.1.10.1:48903<->183.0.169.105:443=>test,train | tcp|10.1.10.1:37896<->52.82.73.241:443=>test,train | tcp|10.1.10.1:47888<->42.226.92.237:443=>train,val |
| nudt | payload_prefix_sha1 | 197 | 4249 | e5bd55cabf888e1add6842b399b47f61d3fd7d99=>test,train | a2e10f295b46688585bea39262356250220f63a9=>train,val | 350889a0e735b5a4b38d2b07d98b11bbe46947d0=>test,train,val |
| nudt | pcap_session | 0 | 0 |  |
| nudt | sample_id | 0 | 0 |  |
| nudt | source_file | 0 | 0 |  |
| nudt | text_sha1 | 0 | 0 |  |

## Gate

Stage 1 gate: `needs_strict_resplit_before_final_metrics`.

Exact duplicate or shortcut leakage must be resolved by stricter split generation before final metrics are claimed. Existing legacy splits can still be used as audit inputs and smoke baselines.

## Strict Split Policy

Final metrics should use a deterministic strict split built from the fixed class list while preventing duplicate sample ids, duplicate source files, exact text duplicates, first-packet duplicates, bidirectional five-tuple reuse, and session/capture leakage whenever the raw data provide enough independent sessions.

The policy is tracked in `manifests/stage1_strict_split_policy.csv`; current TSV feasibility diagnostics are generated in `outputs/stage1_strict_split_feasibility.csv`.

## Generated Local Outputs

- `flow_shortcut_manifest`: `experiments/stage1_data_input_protocol/outputs/flow_shortcut_manifest_baseline_v0_2.csv`
- `leakage_summary`: `experiments/stage1_data_input_protocol/outputs/stage1_leakage_summary.csv`
- `observed_offset_semantics`: `experiments/stage1_data_input_protocol/outputs/stage1_offset_semantic_observed.csv`
- `strict_split_feasibility`: `experiments/stage1_data_input_protocol/outputs/stage1_strict_split_feasibility.csv`
