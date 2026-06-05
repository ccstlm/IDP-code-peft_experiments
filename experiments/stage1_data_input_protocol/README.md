# Stage 1 Data Input Protocol

This stage fixes the data, split, TrafficFormer input, leakage-check, shortcut-field, and byte-offset protocols used by later experiments.

MAPP is used for discovery and method tuning. NUDT is reserved for external validation.

All Stage 1 artifacts live under this directory:

- `scripts/`: reproducible generation and audit scripts
- `configs/`: fixed protocol definitions
- `manifests/`: tracked split, task, offset, and source manifests
- `reports/`: tracked human-readable reports
- `outputs/`: local generated outputs ignored by Git
