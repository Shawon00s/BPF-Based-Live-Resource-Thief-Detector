#!/usr/bin/env python3
"""
ADFA-LD Anomaly Detection Model Training
=========================================

What ADFA-LD provides:
  Training_Data_Master/  -> 833 normal syscall sequences  (label=0)
  Attack_Data_Master/    -> 6 types of attack sequences   (label=1)

What this script does:
  1. Extract features from each syscall sequence (n-gram frequency)
  2. Train Isolation Forest on NORMAL data only (unsupervised)
  3. Evaluate on attack data to measure accuracy
  4. Save the trained model for use in live detection
"""

import os
import glob
import numpy as np
import joblib
from collections import Counter
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix

# ─── Paths ────────────────────────────────────────────────────────────────────
ADFA_ROOT    = "/home/sudipto-roy-s-hawon/Downloads/ADFA-LD"
NORMAL_DIR   = os.path.join(ADFA_ROOT, "Training_Data_Master")
ATTACK_DIR   = os.path.join(ADFA_ROOT, "Attack_Data_Master")
MODEL_DIR    = "/home/sudipto-roy-s-hawon/Downloads/Project/ml/saved_model"
os.makedirs(MODEL_DIR, exist_ok=True)

# ─── Config ───────────────────────────────────────────────────────────────────
MAX_SYSCALL   = 350      # maximum syscall number in ADFA-LD (~350)
BIGRAM        = True     # whether to use bigram features
CONTAMINATION = 0.05     # expected fraction of anomalies in training data (~5%)

# ─── Step 1: Read a trace file ────────────────────────────────────────────────
def read_trace(filepath):
    """Read one ADFA-LD trace file and return a list of syscall numbers."""
    with open(filepath, "r") as f:
        content = f.read().strip()
    if not content:
        return []
    return [int(x) for x in content.split() if x.isdigit()]


# ─── Step 2: Feature Extraction ───────────────────────────────────────────────
def extract_features(syscalls):
    """
    Convert a syscall sequence into a fixed-size feature vector.

    Feature 1: Unigram frequency vector — how often each syscall appeared
               size = MAX_SYSCALL (indices 0 to MAX_SYSCALL-1)

    Feature 2: Bigram frequency — how often each consecutive syscall pair appeared
               Top 50 most common bigrams across the full dataset

    Total feature size = MAX_SYSCALL + (50 if BIGRAM else 0)
    """
    if not syscalls:
        return None

    # Feature 1: Unigram frequency (normalized to relative frequency)
    freq = np.zeros(MAX_SYSCALL, dtype=np.float32)
    for sc in syscalls:
        if 0 <= sc < MAX_SYSCALL:
            freq[sc] += 1
    if freq.sum() > 0:
        freq /= freq.sum()   # normalize to relative frequency

    if not BIGRAM:
        return freq

    # Feature 2: Bigram — consecutive syscall pairs
    bigrams = [(syscalls[i], syscalls[i+1])
               for i in range(len(syscalls)-1)
               if syscalls[i] < MAX_SYSCALL and syscalls[i+1] < MAX_SYSCALL]
    bigram_counts = Counter(bigrams)

    # Fixed index for top-50 bigrams will be built after scanning all data
    return freq, bigram_counts


# ─── Step 3: Load all files ───────────────────────────────────────────────────
print("=" * 60)
print("  ADFA-LD Anomaly Detection — Model Training")
print("=" * 60)

print("\n[1/5] Loading ADFA-LD dataset...")

# Load normal traces
normal_files  = glob.glob(os.path.join(NORMAL_DIR, "*.txt"))
normal_traces = [read_trace(f) for f in normal_files]
normal_traces = [t for t in normal_traces if len(t) > 10]  # filter out traces that are too short
print(f"      Normal traces loaded: {len(normal_traces)} files")

# Load attack traces
attack_traces = []
attack_labels = []
attack_dirs   = sorted(glob.glob(os.path.join(ATTACK_DIR, "*")))
for adir in attack_dirs:
    if not os.path.isdir(adir):
        continue
    aname = os.path.basename(adir)
    files = glob.glob(os.path.join(adir, "*.txt"))
    for f in files:
        t = read_trace(f)
        if len(t) > 10:
            attack_traces.append(t)
            attack_labels.append(aname)

print(f"      Attack traces loaded:  {len(attack_traces)} files")
attack_types = sorted(set(attack_labels))
for at in attack_types:
    count = attack_labels.count(at)
    print(f"      └─ {at:<25} {count} traces")

# ─── Step 4: Feature extraction with bigrams ──────────────────────────────────
print("\n[2/5] Extracting features...")

# Build bigram statistics from all traces combined
all_bigram_counter = Counter()
for trace in normal_traces + attack_traces:
    for i in range(len(trace)-1):
        if trace[i] < MAX_SYSCALL and trace[i+1] < MAX_SYSCALL:
            all_bigram_counter[(trace[i], trace[i+1])] += 1

# Select top 100 most frequent bigrams as features
TOP_BIGRAMS  = 100
top_bigrams  = [bg for bg, _ in all_bigram_counter.most_common(TOP_BIGRAMS)]
bigram_index = {bg: i for i, bg in enumerate(top_bigrams)}

def make_feature_vector(syscalls):
    """Convert a syscall list to a flat numpy array (unigram + bigram features)."""
    if not syscalls:
        return None

    # Unigram frequency
    freq = np.zeros(MAX_SYSCALL, dtype=np.float32)
    for sc in syscalls:
        if 0 <= sc < MAX_SYSCALL:
            freq[sc] += 1
    if freq.sum() > 0:
        freq /= freq.sum()

    # Bigram frequency
    bg_vec = np.zeros(TOP_BIGRAMS, dtype=np.float32)
    for i in range(len(syscalls)-1):
        bg = (syscalls[i], syscalls[i+1])
        if bg in bigram_index:
            bg_vec[bigram_index[bg]] += 1
    if bg_vec.sum() > 0:
        bg_vec /= bg_vec.sum()

    return np.concatenate([freq, bg_vec])

# Build normal feature matrix
X_normal = []
for trace in normal_traces:
    fv = make_feature_vector(trace)
    if fv is not None:
        X_normal.append(fv)
X_normal = np.array(X_normal)

# Build attack feature matrix
X_attack = []
for trace in attack_traces:
    fv = make_feature_vector(trace)
    if fv is not None:
        X_attack.append(fv)
X_attack = np.array(X_attack)

print(f"      Feature vector size: {X_normal.shape[1]} dimensions")
print(f"      Normal  matrix: {X_normal.shape}")
print(f"      Attack  matrix: {X_attack.shape}")

# ─── Step 5: Normalize ────────────────────────────────────────────────────────
print("\n[3/5] Normalizing features...")
scaler = StandardScaler()
X_normal_scaled = scaler.fit_transform(X_normal)  # fit only on normal data
X_attack_scaled = scaler.transform(X_attack)       # transform attack data using the same scaler
print("      StandardScaler fit on normal data only ✓")

# ─── Step 6: Train Isolation Forest ───────────────────────────────────────────
print("\n[4/5] Training Isolation Forest...")
print("      (trained on normal data only — fully unsupervised)")

model = IsolationForest(
    n_estimators=200,       # more trees = better accuracy
    contamination=CONTAMINATION,
    max_samples="auto",
    random_state=42,
    n_jobs=-1,              # use all available CPU cores
    verbose=0,
)
model.fit(X_normal_scaled)
print("      Training complete ✓")

# ─── Step 7: Evaluate ─────────────────────────────────────────────────────────
print("\n[5/5] Evaluating model...")

# Isolation Forest output: 1 = normal, -1 = anomaly
pred_normal = model.predict(X_normal_scaled)   # test on normal data
pred_attack = model.predict(X_attack_scaled)   # test on attack data

# Score: lower score = more anomalous
score_normal = model.score_samples(X_normal_scaled)
score_attack = model.score_samples(X_attack_scaled)

# Metrics
normal_detected_ok = np.sum(pred_normal == 1)    # correctly classified as normal
attack_detected     = np.sum(pred_attack == -1)  # correctly detected as anomaly

print(f"\n  ┌─ Results ──────────────────────────────┐")
print(f"  │ Normal traces correctly classified:    {normal_detected_ok}/{len(pred_normal)} ({100*normal_detected_ok/len(pred_normal):.1f}%)")
print(f"  │ Attack traces detected as anomaly:     {attack_detected}/{len(pred_attack)} ({100*attack_detected/len(pred_attack):.1f}%)")
print(f"  │                                        │")
print(f"  │ Normal score (avg):  {score_normal.mean():.4f}             │")
print(f"  │ Attack score (avg):  {score_attack.mean():.4f}             │")
print(f"  │ Score gap:           {score_normal.mean() - score_attack.mean():.4f}             │")
print(f"  └─────────────────────────────────────────┘")

# Per-attack-type breakdown
print("\n  Per-attack-type detection rate:")
for at in attack_types:
    indices = [i for i, lb in enumerate(attack_labels) if lb == at]
    if not indices:
        continue
    valid_indices = [i for i in indices if i < len(pred_attack)]
    if not valid_indices:
        continue
    detected = sum(1 for i in valid_indices if pred_attack[i] == -1)
    rate = 100 * detected / len(valid_indices)
    bar = "█" * int(rate / 5) + "░" * (20 - int(rate / 5))
    print(f"  {at:<25} [{bar}] {rate:.0f}%")

# ─── Step 8: Save model ───────────────────────────────────────────────────────
print("\n[✓] Saving model...")
joblib.dump(model,       os.path.join(MODEL_DIR, "isolation_forest.pkl"))
joblib.dump(scaler,      os.path.join(MODEL_DIR, "scaler.pkl"))
joblib.dump(top_bigrams, os.path.join(MODEL_DIR, "top_bigrams.pkl"))

# Save model config — required by live_predictor.py
import json
config = {
    "max_syscall":   MAX_SYSCALL,
    "top_bigrams":   TOP_BIGRAMS,
    "feature_size":  X_normal.shape[1],
    "contamination": CONTAMINATION,
    "threshold":     float(np.percentile(score_normal, 5)),  # 5th percentile as alert threshold
}
with open(os.path.join(MODEL_DIR, "config.json"), "w") as f:
    json.dump(config, f, indent=2)

print(f"\n  Saved to: {MODEL_DIR}/")
print(f"    isolation_forest.pkl  <- main model")
print(f"    scaler.pkl            <- feature normalizer")
print(f"    top_bigrams.pkl       <- bigram vocabulary")
print(f"    config.json           <- thresholds & config")
print(f"\n  Alert threshold: score < {config['threshold']:.4f} -> ANOMALY")
print("\n" + "=" * 60)
print("  Training complete! Run live_predictor.py to use the model.")
print("=" * 60)
