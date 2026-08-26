#!/usr/bin/env python3
"""
Live ML Predictor
=================
Runs the trained LSTM model on real-time syscall data coming from the eBPF
sensor and produces an anomaly probability score for each monitored process.

Imported and used by detector.py or dashboard.py.
"""

import os
import json
import numpy as np
import joblib
import torch
import torch.nn as nn
from collections import defaultdict, deque

MODEL_DIR = "/home/sudipto-roy-s-hawon/Downloads/Project/ml/saved_model"
DEVICE    = torch.device("cuda" if torch.cuda.is_available() else "cpu")


# ── LSTM model class (must match the architecture defined in lstm_train.py) ───
class SyscallLSTM(nn.Module):
    def __init__(self, max_syscall, embed_dim, hidden_dim, num_layers, pad_token):
        super().__init__()
        self.embed = nn.Embedding(max_syscall + 1, embed_dim, padding_idx=pad_token)
        self.lstm  = nn.LSTM(embed_dim, hidden_dim, num_layers,
                             batch_first=True, dropout=0.3)
        self.attn  = nn.Linear(hidden_dim, 1)
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, 64), nn.ReLU(),
            nn.Dropout(0.4), nn.Linear(64, 1),
        )
    def forward(self, x):
        emb     = self.embed(x)
        out, _  = self.lstm(emb)
        attn_w  = torch.softmax(self.attn(out), dim=1)
        context = (attn_w * out).sum(dim=1)
        return self.classifier(context).squeeze(-1)


class LivePredictor:
    """
    Real-time anomaly scorer for live eBPF events.

    Maintains a sliding window syscall buffer per PID.
    Once the window is full, runs the LSTM model and returns an anomaly score.
    """

    WINDOW_SIZE = 100          # syscalls needed for a full, alert-grade window
    MIN_DISPLAY_SYSCALLS = 50  # minimum before showing a (low-confidence) score
    INFERENCE_STRIDE = 50      # re-score only after this many new syscalls
    ALERT_SCORE = None         # loaded from lstm_config.json at startup

    def __init__(self):
        self._load_model()
        self._load_syscall_map()
        # pid -> deque of recent syscall numbers (sliding window, i686-normalised)
        self.buffers = defaultdict(lambda: deque(maxlen=self.WINDOW_SIZE))
        self.scores  = {}   # pid -> latest anomaly probability
        self.inference_count = 0   # how many LSTM forward passes we have run
        self.seen = {}             # pid -> total syscalls ever seen (for striding)
        print("[ML] LivePredictor initialized ✓")

    def _load_syscall_map(self):
        """
        Load the x86_64 -> i686 syscall number translation table.

        WHY THIS IS REQUIRED:
        ADFA-LD was captured on Ubuntu 11.04 i686 (32-bit x86), so every
        syscall number in the training data uses the i686 ABI:
            read=3  write=4  open=5  close=6  mmap2=192  poll=168

        Our eBPF sensor runs on x86_64, which numbers them completely
        differently:
            read=0  write=1  open=2  close=3  mmap=9    poll=7

        Without translation the model receives numbers it was never trained
        on — e.g. an 'openat'(257) is read by the model as i686 syscall 257
        ('remap_file_pages'), which almost never appears in ADFA-LD.  The
        result is a meaningless, near-constant score.

        This table maps by syscall NAME so the model sees the same semantic
        sequence it learned from.
        """
        map_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "syscall_map.json")
        try:
            with open(map_path) as f:
                raw = json.load(f)
            self.syscall_map = {int(k): int(v) for k, v in raw.items()}
            print(f"[ML] Syscall ABI map loaded: {len(self.syscall_map)} "
                  f"x86_64 → i686 translations")
        except FileNotFoundError:
            self.syscall_map = {}
            print("[ML] WARNING: syscall_map.json missing — model accuracy "
                  "will be poor (ABI mismatch with ADFA-LD training data)")

    def translate(self, syscall_nr: int) -> int:
        """Convert an x86_64 syscall number to its i686 equivalent."""
        return self.syscall_map.get(syscall_nr, syscall_nr)

    def _load_model(self):
        """Load the trained LSTM model onto the GPU (or CPU as fallback)."""
        try:
            with open(os.path.join(MODEL_DIR, "lstm_config.json")) as f:
                cfg = json.load(f)

            self.SEQ_LEN     = cfg["seq_len"]
            self.MAX_SYSCALL = cfg["max_syscall"]
            self.PAD_TOKEN   = cfg["pad_token"]
            self.ALERT_SCORE = cfg["threshold"]   # 0.9 — tuned for low false positives
            self.MIN_DISPLAY_SYSCALLS = cfg.get("min_display_syscalls", 50)

            self.lstm_model = SyscallLSTM(
                max_syscall=self.MAX_SYSCALL,
                embed_dim=cfg["embed_dim"],
                hidden_dim=cfg["hidden_dim"],
                num_layers=cfg["num_layers"],
                pad_token=self.PAD_TOKEN,
            ).to(DEVICE)

            state = torch.load(
                os.path.join(MODEL_DIR, "lstm_model.pt"),
                map_location=DEVICE, weights_only=True,
            )
            self.lstm_model.load_state_dict(state)
            self.lstm_model.eval()
            self.ready = True
            print(f"[ML] LSTM loaded on {DEVICE} | AUC={cfg.get('best_auc', '?')}")

        except FileNotFoundError:
            print("[ML] Model not found. Run: python3 ml/lstm_train.py")
            self.ready = False

    def add_syscall(self, pid: int, syscall_nr: int):
        """
        Add one syscall event for the given PID.

        Once the sliding window reaches WINDOW_SIZE, runs inference and
        returns a result dict. Returns None while the window is still filling.

        Returns:
            None                  — window not yet full
            {
              "score":      float,  — anomaly probability (0.0=normal, 1.0=attack)
              "is_anomaly": bool,   — True if score >= threshold
              "label":      str,    — "NORMAL" or "ANOMALY"
              "pid":        int
            }
        """
        if not self.ready:
            return None

        # Translate x86_64 syscall number -> i686 (what the model was trained on)
        self.buffers[pid].append(self.translate(syscall_nr))
        self.seen[pid] = self.seen.get(pid, 0) + 1

        n = len(self.buffers[pid])
        if n < self.WINDOW_SIZE:
            return None

        # The buffer is a deque(maxlen=WINDOW_SIZE), so once it fills it STAYS
        # full.  Predicting on every call from then on would run one GPU
        # inference per syscall — thousands per second on a live system, and it
        # re-raises the same alert for a process that simply stays busy.
        # Instead advance in strides: score once per INFERENCE_STRIDE new
        # syscalls, i.e. when the window has meaningfully changed.
        if (self.seen[pid] - self.WINDOW_SIZE) % self.INFERENCE_STRIDE != 0:
            return None

        return self._predict(pid)

    def partial_score(self, pid: int, min_syscalls: int = None):
        """
        Score a PID whose buffer hasn't reached WINDOW_SIZE yet.

        DISPLAY ONLY — never use this to raise an alert.

        Measured false-positive rate vs. window size (threshold 0.9,
        real ADFA-LD normal traces):

            15 syscalls  ->  78% false positives   (unusable)
            30 syscalls  ->  50% false positives   (unusable)
            50 syscalls  ->  33% false positives   (borderline, display only)
           100 syscalls  ->  19% false positives   (alert-worthy)

        Short buffers are mostly PAD_TOKEN, and the model reads heavy padding
        as anomalous — hence the sharp false-positive curve.  We therefore
        require MIN_DISPLAY_SYSCALLS (default 50) before showing anything,
        and only ever alert on a full window.

        Returns None if too few syscalls have been observed.
        """
        if not self.ready:
            return None
        if min_syscalls is None:
            min_syscalls = self.MIN_DISPLAY_SYSCALLS
        buf = self.buffers.get(pid)
        if not buf or len(buf) < min_syscalls:
            return None
        result = self._predict(pid)
        # Mark as low-confidence so callers never treat it as alert-grade
        result["partial"]    = True
        result["confidence"] = round(len(buf) / self.WINDOW_SIZE, 2)
        return result

    def _predict(self, pid: int) -> dict:
        """Run the LSTM on the current buffer and return an anomaly score."""
        seq = list(self.buffers[pid])

        # Pad or truncate to the fixed sequence length the model expects
        if len(seq) >= self.SEQ_LEN:
            seq = seq[:self.SEQ_LEN]
        else:
            seq = seq + [self.PAD_TOKEN] * (self.SEQ_LEN - len(seq))

        # Clip any out-of-range syscall numbers
        seq = [min(max(s, 0), self.MAX_SYSCALL - 1) for s in seq]

        x = torch.tensor([seq], dtype=torch.long, device=DEVICE)
        with torch.no_grad():
            logit = self.lstm_model(x)
            prob  = torch.sigmoid(logit).item()

        is_anom = prob >= self.ALERT_SCORE
        self.scores[pid] = prob
        self.inference_count += 1
        return {
            "score":      round(prob, 4),   # 0.0 = normal, 1.0 = attack
            "is_anomaly": is_anom,
            "label":      "ANOMALY" if is_anom else "NORMAL",
            "pid":        pid,
        }

    def get_score(self, pid: int):
        """Return the latest anomaly score for a given PID, or None."""
        return self.scores.get(pid)

    def clear_pid(self, pid: int):
        """Remove all state for a PID when its process exits."""
        self.buffers.pop(pid, None)
        self.scores.pop(pid, None)


# ─── Quick self-test ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("Testing LivePredictor...")
    predictor = LivePredictor()

    if predictor.ready:
        # Normal-ish pattern — syscalls 1 and 252 dominate the training data
        normal_calls = ([1] * 40 + [252] * 40 + [6, 42, 63] * 6 + [120])
        for sc in normal_calls:
            result = predictor.add_syscall(pid=1234, syscall_nr=sc)

        print(f"Normal pattern result:  {result}")

        # Attack-like pattern — syscalls 168 and 265 are prominent in Adduser traces
        attack_calls = ([168] * 50 + [265] * 40 + [102] * 10)
        for sc in attack_calls:
            result = predictor.add_syscall(pid=9999, syscall_nr=sc)

        print(f"Attack pattern result:  {result}")
        print(f"\nAlert threshold: {predictor.ALERT_SCORE:.4f}")
        print("Score: 0.0 = normal, 1.0 = attack")
