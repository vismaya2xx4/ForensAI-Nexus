import os
import json
from scripts.evidence_triage import train_model, load_model, score_sample
from scripts.llm_summary import summarize_logs
from scripts.threat_check import vt_lookup_sha256

DATA_CSV = os.path.join("data", "sample_evidence.csv")

def test_model_training_and_scoring(tmp_path):
    m = train_model(DATA_CSV)
    assert os.path.exists(m["model_path"])
    model = load_model(m["model_path"])
    result = score_sample({"file_size": 50, "entropy": 7.5, "is_signed": 0}, model)
    assert 0.0 <= result.risk_score <= 1.0
    assert result.label in (0,1)

def test_llm_summary_offline():
    # Remove key to force offline path
    old = os.environ.pop("OPENAI_API_KEY", None)
    try:
        out = summarize_logs(["failed login from 1.2.3.4", "unsigned exe entropy=7.7"])
        assert isinstance(out, str)
        assert "Forensic Summary" in out
    finally:
        if old:
            os.environ["OPENAI_API_KEY"] = old

def test_vt_lookup_graceful():
    # Remove VT key to force graceful fallback
    old = os.environ.pop("VT_API_KEY", None)
    try:
        res = vt_lookup_sha256("e3b0c4"*10 + "55")  # any 64-hex-ish
        assert res.get("found") in (True, False)
        # Should not raise even without key
    finally:
        if old:
            os.environ["VT_API_KEY"] = old
