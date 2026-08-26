# ML Pipeline — Notebooks

Four notebooks that build the anomaly detector, in order. Each one runs top to
bottom and writes its artifacts into `saved_model/`.

| # | Notebook | Runtime | Produces |
|---|---|---|---|
| 01 | `01_explore_dataset.ipynb` | ~30 s | `syscall_map.json` |
| 02 | `02_isolation_forest.ipynb` | ~1 min | `isolation_forest.pkl`, `scaler.pkl`, `top_bigrams.pkl`, `config.json` |
| 03 | `03_lstm_train.ipynb` | 2–4 min (GPU) | `lstm_model.pt`, `lstm_config.json` |
| 04 | `04_live_inference.ipynb` | ~1 min | nothing — validates and tunes |

Notebook 01 must run before 04. Everything else is independent.

## Opening them

**VS Code** — open the `.ipynb`, then pick kernel **Python (BPF Detector)**.
If it is not listed, choose *Select Another Kernel → Python Environments →*
`venv/bin/python3`.

**Browser**

```bash
cd ~/Downloads/Project
venv/bin/python3 -m jupyter lab ml/
```

## What each one covers

**01 — Dataset & the syscall ABI problem.** Explores ADFA-LD, then works out
that the dataset uses **i686** syscall numbers while our eBPF sensor emits
**x86-64**. Same operations, different numbers: `read` is 3 there and 0 here.
Untranslated, the model reads every `openat` as `remap_file_pages`. Builds the
376-entry translation table that fixes it.

**02 — Isolation Forest.** Unsupervised baseline trained on normal data only.
Uses unigram + bigram frequency features. Fast, CPU-only, needs no attack
labels — but it mostly ignores *order*, which is the argument for notebook 03.

**03 — LSTM with attention.** Embedding → LSTM → attention → classifier, on the
GPU. Handles the 7:1 class imbalance with a weighted sampler and `pos_weight`.
Reaches ~0.985 validation AUC.

**04 — Live inference.** Replays ADFA-LD traces *as x86-64* to test the real
path, then derives the two constants `src/dashboard.py` runs on:

- **threshold 0.9** — 0.5 fires too often on live traffic
- **100-syscall window to alert, 50 to display** — a 15-syscall buffer is mostly
  padding and produces ~78 % false positives

## Relationship to the `.py` files

The notebooks and scripts are equivalent — same algorithms, same
hyperparameters, verified to produce byte-identical artifacts.

| Script | Notebook |
|---|---|
| `train_model.py` | 02 |
| `lstm_train.py` | 03 |
| `live_predictor.py` | 04 (imports it rather than duplicating) |

`live_predictor.py` is **not** a notebook copy — it is the live class that
`src/dashboard.py` imports. Notebook 04 exercises that exact class, so what you
tune there is what runs in production. Edit the `.py` for behaviour changes;
use the notebooks to explore and to justify constants.

## Requirements

- ADFA-LD at `~/Downloads/ADFA-LD` (edit `ADFA_ROOT` in cell 1 otherwise)
- CUDA GPU for notebook 03 — falls back to CPU, just slower
- Never needs root; only the live dashboard does
