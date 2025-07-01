# evidence_triage.py
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

# Sample data: file_size (bytes), entropy (measure of randomness), is_signed (0/1), is_malicious (0/1)
data = {
    "file_size": [1024, 2048, 512, 4096, 100],
    "entropy": [6.1, 7.8, 5.2, 8.5, 2.1],
    "is_signed": [1, 0, 0, 1, 0],
    "is_malicious": [0, 1, 1, 0, 1]  # 1 = malicious, 0 = clean
}
df = pd.DataFrame(data)

# Features (X) and labels (y)
X = df[["file_size", "entropy", "is_signed"]]
y = df["is_malicious"]

# Train ML model
model = RandomForestClassifier()
model.fit(X, y)

def predict_risk(file_size, entropy, is_signed):
    """Predicts malware probability (0-1)."""
    return model.predict_proba([[file_size, entropy, is_signed]])[0][1]

# Example usage
if __name__ == "__main__":
    risk = predict_risk(1024, 7.2, 0)  # Test with a suspicious file (high entropy, unsigned)
    print(f"Malware probability: {risk:.0%}")
