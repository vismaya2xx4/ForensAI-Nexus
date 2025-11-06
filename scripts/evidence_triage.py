from __future__ import annotations
import os
import joblib
import pandas as pd
from dataclasses import dataclass
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from typing import Tuple, List, Any

MODEL_DIR = os.path.join("scripts", "_models")
MODEL_PATH = os.path.join(MODEL_DIR, "rf_triage.joblib")

@dataclass
class TriageResult:
    risk_score: float  # 0..1 probability of malicious
    label: int         # 0 clean, 1 malicious

def _ensure_model_dir():
    os.makedirs(MODEL_DIR, exist_ok=True)

def load_dataset(csv_path: str) -> Tuple[pd.DataFrame, pd.Series]:
    df = pd.read_csv(csv_path)
    required = {"file_size", "entropy", "is_signed", "is_malicious"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Dataset missing required columns: {missing}")
    X = df[["file_size", "entropy", "is_signed"]]
    y = df["is_malicious"]
    return X, y

def train_model(csv_path: str, n_estimators: int = 200, random_state: int = 42) -> dict:
    """Train RF model and persist it. Returns metrics dict."""
    _ensure_model_dir()
    X, y = load_dataset(csv_path)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=random_state, stratify=y
    )
    model = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=None,
        n_jobs=-1,
        random_state=random_state
    )
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    metrics_text = classification_report(y_test, y_pred, output_dict=False, digits=3)
    joblib.dump(model, MODEL_PATH)
    return {"report": metrics_text, "model_path": MODEL_PATH}

def load_model(path: str = MODEL_PATH) -> RandomForestClassifier:
    if not os.path.exists(path):
        raise FileNotFoundError("Model not found. Train it first via train_model().")
    return joblib.load(path)

def score_sample(sample: dict, model: RandomForestClassifier | None = None) -> TriageResult:
    """sample keys: file_size (KB), entropy (0-8), is_signed (0/1)"""
    if model is None:
        model = load_model()
    df = pd.DataFrame([sample])[["file_size", "entropy", "is_signed"]]
    proba = model.predict_proba(df)[0][1]  # probability of class 1 (malicious)
    label = int(proba >= 0.5)
    return TriageResult(risk_score=float(proba), label=label)

def batch_score(samples: List[dict], model: RandomForestClassifier | None = None) -> List[TriageResult]:
    if model is None:
        model = load_model()
    df = pd.DataFrame(samples)[["file_size", "entropy", "is_signed"]]
    probas = model.predict_proba(df)[:, 1]
    return [TriageResult(risk_score=float(p), label=int(p >= 0.5)) for p in probas]
