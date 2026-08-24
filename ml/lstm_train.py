#!/usr/bin/env python3
"""
LSTM-Based Syscall Anomaly Detector
=====================================
Trained on RTX 3050 6GB GPU.

Architecture:
  syscall numbers
      |
  Embedding(350 -> 64)      <- maps each syscall ID to a 64-dim dense vector
      |
  LSTM(64->128, 2 layers)   <- learns sequential syscall patterns
      |
  Attention(128)            <- focuses on the most important timesteps
      |
  Linear(128->64->1)        <- outputs normal=0 / attack=1 probability
      |
  Sigmoid output

GPU memory estimate:
  Model parameters: ~800K -> ~3MB
  Training batch 128x200:  ~50MB
  Total: ~150MB  (only 2.5% of 6GB VRAM)
"""

import os, glob, json, random
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from torch.optim.lr_scheduler import CosineAnnealingLR
from sklearn.metrics import classification_report, roc_auc_score
import joblib

# ─── Config ───────────────────────────────────────────────────────────────────
ADFA_ROOT   = "/home/sudipto-roy-s-hawon/Downloads/ADFA-LD"
MODEL_DIR   = "/home/sudipto-roy-s-hawon/Downloads/Project/ml/saved_model"
os.makedirs(MODEL_DIR, exist_ok=True)

SEQ_LEN     = 200       # pad or truncate every sequence to this fixed length
MAX_SYSCALL = 351       # syscall numbers 0-350 plus one reserved padding token
PAD_TOKEN   = 350       # reserved token used for sequence padding
EMBED_DIM   = 64        # embedding vector size per syscall
HIDDEN_DIM  = 128       # LSTM hidden state size
NUM_LAYERS  = 2         # number of stacked LSTM layers
BATCH_SIZE  = 128       # GPU batch size (fits comfortably in 6GB VRAM)
EPOCHS      = 30
LR          = 1e-3
DEVICE      = torch.device("cuda" if torch.cuda.is_available() else "cpu")

print("=" * 60)
print("  LSTM Syscall Anomaly Detector — Training")
print("=" * 60)
print(f"\n  Device : {DEVICE}")
if DEVICE.type == "cuda":
    print(f"  GPU    : {torch.cuda.get_device_name(0)}")
    free = torch.cuda.mem_get_info()[0] / 1024**3
    print(f"  VRAM   : {free:.1f} GB free")

# ─── Step 1: Data Loading ─────────────────────────────────────────────────────
def read_trace(filepath):
    """Read one trace file and return a list of integer syscall numbers."""
    with open(filepath) as f:
        nums = [int(x) for x in f.read().split() if x.isdigit()]
    return nums

def pad_or_truncate(seq, length=SEQ_LEN):
    """Bring a sequence to exactly `length` by truncating or padding."""
    if len(seq) >= length:
        return seq[:length]                                    # truncate
    return seq + [PAD_TOKEN] * (length - len(seq))            # pad

print("\n[1/6] Loading ADFA-LD...")
X_all, y_all = [], []

# Normal traces -> label 0
for f in glob.glob(os.path.join(ADFA_ROOT, "Training_Data_Master", "*.txt")):
    t = read_trace(f)
    if len(t) > 20:
        X_all.append(pad_or_truncate(t))
        y_all.append(0)  # NORMAL

# Validation normal traces -> label 0 (more normal data improves the model)
for f in glob.glob(os.path.join(ADFA_ROOT, "Validation_Data_Master", "*.txt")):
    t = read_trace(f)
    if len(t) > 20:
        X_all.append(pad_or_truncate(t))
        y_all.append(0)

# Attack traces -> label 1
for adir in glob.glob(os.path.join(ADFA_ROOT, "Attack_Data_Master", "*")):
    if not os.path.isdir(adir): continue
    for f in glob.glob(os.path.join(adir, "*.txt")):
        t = read_trace(f)
        if len(t) > 20:
            X_all.append(pad_or_truncate(t))
            y_all.append(1)  # ATTACK

X_all = np.array(X_all, dtype=np.int64)
y_all = np.array(y_all, dtype=np.float32)
n_normal = int((y_all == 0).sum())
n_attack = int((y_all == 1).sum())
print(f"  Normal samples : {n_normal}")
print(f"  Attack samples : {n_attack}")
print(f"  Sequence length: {SEQ_LEN}")

# ─── Step 2: Train/Val Split ──────────────────────────────────────────────────
print("\n[2/6] Splitting dataset...")
idx = np.arange(len(X_all))
np.random.shuffle(idx)
split = int(0.8 * len(idx))
train_idx, val_idx = idx[:split], idx[split:]

X_train, y_train = X_all[train_idx], y_all[train_idx]
X_val,   y_val   = X_all[val_idx],   y_all[val_idx]
print(f"  Train: {len(X_train)} | Val: {len(X_val)}")

# ─── Step 3: Dataset & DataLoader ─────────────────────────────────────────────
class SyscallDataset(Dataset):
    def __init__(self, X, y):
        self.X = torch.tensor(X, dtype=torch.long)
        self.y = torch.tensor(y, dtype=torch.float32)
    def __len__(self):  return len(self.X)
    def __getitem__(self, i):  return self.X[i], self.y[i]

# Use a weighted sampler to handle class imbalance (many more normal than attack)
n0 = (y_train == 0).sum()
n1 = (y_train == 1).sum()
weights = np.where(y_train == 0, 1.0/n0, 1.0/n1)
sampler = torch.utils.data.WeightedRandomSampler(
    weights=torch.tensor(weights, dtype=torch.double),
    num_samples=len(weights), replacement=True
)

train_loader = DataLoader(SyscallDataset(X_train, y_train),
                          batch_size=BATCH_SIZE, sampler=sampler,
                          num_workers=0, pin_memory=True)
val_loader   = DataLoader(SyscallDataset(X_val, y_val),
                          batch_size=BATCH_SIZE, shuffle=False,
                          num_workers=0, pin_memory=True)

# ─── Step 4: LSTM Model Definition ────────────────────────────────────────────
class SyscallLSTM(nn.Module):
    """
    Embedding -> LSTM -> Attention -> Classifier

    Attention mechanism: assigns higher weight to timesteps that carry
    the most discriminative syscall patterns for anomaly detection.
    """
    def __init__(self):
        super().__init__()
        # Embedding: maps each syscall number to a dense vector
        self.embed = nn.Embedding(
            num_embeddings=MAX_SYSCALL + 1,
            embedding_dim=EMBED_DIM,
            padding_idx=PAD_TOKEN,
        )
        # LSTM: learns sequential syscall patterns over time
        self.lstm = nn.LSTM(
            input_size=EMBED_DIM,
            hidden_size=HIDDEN_DIM,
            num_layers=NUM_LAYERS,
            batch_first=True,
            dropout=0.3,
            bidirectional=False,
        )
        # Attention: learns which timesteps are most important
        self.attn = nn.Linear(HIDDEN_DIM, 1)

        # Classifier head: maps attended context to a binary prediction
        self.classifier = nn.Sequential(
            nn.Linear(HIDDEN_DIM, 64),
            nn.ReLU(),
            nn.Dropout(0.4),
            nn.Linear(64, 1),
        )

    def forward(self, x):
        # x shape: (batch, seq_len) — raw syscall number sequences
        emb = self.embed(x)              # (batch, seq_len, embed_dim)
        out, _ = self.lstm(emb)          # (batch, seq_len, hidden_dim)

        # Compute attention weights across all timesteps
        attn_w  = torch.softmax(self.attn(out), dim=1)   # (batch, seq_len, 1)
        context = (attn_w * out).sum(dim=1)               # (batch, hidden_dim)

        return self.classifier(context).squeeze(-1)       # (batch,)

# ─── Step 5: Training Loop ────────────────────────────────────────────────────
print("\n[3/6] Building model...")
model = SyscallLSTM().to(DEVICE)
total_params = sum(p.numel() for p in model.parameters())
print(f"  Parameters: {total_params:,} (~{total_params*4/1024**2:.1f} MB)")
if DEVICE.type == "cuda":
    print(f"  GPU memory after model load: {torch.cuda.memory_allocated()/1024**2:.1f} MB")

# BCEWithLogitsLoss = Sigmoid + Binary Cross-Entropy combined (numerically stable)
pos_weight = torch.tensor([n0/n1], device=DEVICE)  # upweight the minority attack class
criterion  = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
optimizer  = torch.optim.Adam(model.parameters(), lr=LR, weight_decay=1e-4)
scheduler  = CosineAnnealingLR(optimizer, T_max=EPOCHS, eta_min=1e-5)

print("\n[4/6] Training...")
print(f"  {'Epoch':>5} | {'Train Loss':>10} | {'Val Loss':>9} | {'Val Acc':>8} | {'Val AUC':>8}")
print("  " + "─" * 55)

best_auc   = 0.0
best_state = None

for epoch in range(1, EPOCHS + 1):
    # ── Train ──
    model.train()
    train_losses = []
    for xb, yb in train_loader:
        xb, yb = xb.to(DEVICE), yb.to(DEVICE)
        optimizer.zero_grad(set_to_none=True)
        logits = model(xb)
        loss   = criterion(logits, yb)
        loss.backward()
        nn.utils.clip_grad_norm_(model.parameters(), 1.0)  # gradient clipping prevents exploding gradients
        optimizer.step()
        train_losses.append(loss.item())
    scheduler.step()

    # ── Validate ──
    model.eval()
    val_losses, all_probs, all_labels = [], [], []
    with torch.no_grad():
        for xb, yb in val_loader:
            xb, yb = xb.to(DEVICE), yb.to(DEVICE)
            logits = model(xb)
            val_losses.append(criterion(logits, yb).item())
            probs = torch.sigmoid(logits).cpu().numpy()
            all_probs.extend(probs)
            all_labels.extend(yb.cpu().numpy())

    all_probs  = np.array(all_probs)
    all_labels = np.array(all_labels)
    preds  = (all_probs >= 0.5).astype(int)
    acc    = (preds == all_labels).mean()
    auc    = roc_auc_score(all_labels, all_probs)

    t_loss = np.mean(train_losses)
    v_loss = np.mean(val_losses)

    # Save checkpoint whenever a new best AUC is achieved
    if auc > best_auc:
        best_auc   = auc
        best_state = {k: v.clone() for k, v in model.state_dict().items()}
        marker = " ★"
    else:
        marker = ""

    if epoch % 5 == 0 or epoch == 1 or marker:
        print(f"  {epoch:>5} | {t_loss:>10.4f} | {v_loss:>9.4f} | {acc:>7.1%} | {auc:>7.4f}{marker}")

# ─── Step 6: Final Evaluation ─────────────────────────────────────────────────
print("\n[5/6] Final evaluation (best model)...")
model.load_state_dict(best_state)
model.eval()

all_probs, all_labels = [], []
with torch.no_grad():
    for xb, yb in val_loader:
        xb = xb.to(DEVICE)
        probs = torch.sigmoid(model(xb)).cpu().numpy()
        all_probs.extend(probs)
        all_labels.extend(yb.numpy())

all_probs  = np.array(all_probs)
all_labels = np.array(all_labels)
preds = (all_probs >= 0.5).astype(int)

print(f"\n  Best AUC: {best_auc:.4f}")
print(f"\n{classification_report(all_labels, preds, target_names=['Normal','Attack'])}")

# ─── Step 7: Save ─────────────────────────────────────────────────────────────
print("[6/6] Saving LSTM model...")
torch.save(best_state, os.path.join(MODEL_DIR, "lstm_model.pt"))

lstm_cfg = {
    "seq_len":     SEQ_LEN,
    "max_syscall": MAX_SYSCALL,
    "pad_token":   PAD_TOKEN,
    "embed_dim":   EMBED_DIM,
    "hidden_dim":  HIDDEN_DIM,
    "num_layers":  NUM_LAYERS,
    "threshold":   0.5,
    "best_auc":    round(best_auc, 4),
}
with open(os.path.join(MODEL_DIR, "lstm_config.json"), "w") as f:
    json.dump(lstm_cfg, f, indent=2)

print(f"\n  lstm_model.pt      — trained model weights")
print(f"  lstm_config.json   — model config & decision threshold")
print(f"\n  Best Validation AUC: {best_auc:.4f}")
print("\n" + "=" * 60)
print("  LSTM training complete! The model is ready for live detection.")
print("=" * 60)
