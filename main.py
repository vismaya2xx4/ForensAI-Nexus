from __future__ import annotations
import os
import json
from pathlib import Path
from rich.console import Console
from rich.table import Table
from dotenv import load_dotenv

from scripts.evidence_triage import train_model, load_model, batch_score
from scripts.llm_summary import summarize_logs
from scripts.threat_check import vt_lookup_sha256

load_dotenv()
console = Console()

DATA_CSV = os.path.join("data", "sample_evidence.csv")
REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)

def pretty_header(title: str):
    console.rule(f"[bold blue]{title}[/]")

def keys_healthcheck():
    """Print a friendly preflight summary about API keys before the demo runs."""
    console.rule("[bold yellow]Pre-run checks[/]")
    oa = os.getenv("OPENAI_API_KEY", "")
    vt = os.getenv("VT_API_KEY", "")

    # OpenAI status
    if oa:
        console.print("🔑 OpenAI key: [green]present[/] (model: "
                      f"{os.getenv('OPENAI_MODEL', 'gpt-4o-mini')})")
        console.print("   [dim]Note: if you see 429 'insufficient_quota', add credits or remove the key to use offline fallback.[/]")
    else:
        console.print("🔑 OpenAI key: [yellow]missing[/] → using offline fallback summary.")

    # VirusTotal status
    if vt:
        # Warn if key has whitespace/newlines accidentally
        if any(c.isspace() for c in vt):
            console.print("🧬 VirusTotal key: [red]present but contains whitespace[/] → check `.env` formatting.")
        else:
            console.print("🧬 VirusTotal key: [green]present[/]")
    else:
        console.print("🧬 VirusTotal key: [yellow]missing[/] → VT section will show a graceful fallback.")

    console.print("")  # spacer

def demo_evidence_triage():
    pretty_header("Training Evidence Triage Model")
    metrics = train_model(DATA_CSV)
    console.print("[green]✅ Model trained and saved[/] ->", metrics["model_path"])
    console.print("[cyan]Classification Report:[/]\n" + metrics["report"])

    model = load_model()
    samples = [
        {"file_size": 40, "entropy": 7.6, "is_signed": 0},   # likely malicious
        {"file_size": 1500, "entropy": 5.4, "is_signed": 1}, # likely clean
        {"file_size": 85, "entropy": 7.2, "is_signed": 0},   # suspicious
    ]
    results = batch_score(samples, model)
    tbl = Table(title="AI Evidence Triage (RandomForest) 📦")
    tbl.add_column("Idx", justify="right")
    tbl.add_column("file_size (KB)")
    tbl.add_column("entropy")
    tbl.add_column("is_signed")
    tbl.add_column("risk_score")
    tbl.add_column("label")
    for i, (s, r) in enumerate(zip(samples, results)):
        tbl.add_row(
            str(i),
            str(s["file_size"]),
            str(s["entropy"]),
            str(s["is_signed"]),
            f"{r.risk_score:.3f}",
            "🛑 malicious" if r.label == 1 else "✅ clean",
        )
    console.print(tbl)
    return [{"sample": s, "risk_score": r.risk_score, "label": r.label} for s, r in zip(samples, results)]

def demo_llm_summary():
    pretty_header("LLM Forensic Summary")
    sample_logs = [
        "2025-11-05T12:01:22Z auth: failed login from 185.23.44.10 on host=win-ws-14 user=svc_backup",
        "2025-11-05T12:03:10Z edr: unsigned executable launched path=C:\\Users\\Public\\runme.exe entropy=7.6",
        "2025-11-05T12:05:03Z net: outbound connection dst=198.51.100.4:443 process=runme.exe bytes=42344",
        "2025-11-05T12:05:15Z edr: process tree shows runme.exe -> powershell.exe -enc <base64>",
    ]
    summary = summarize_logs(sample_logs)
    console.print(summary)
    return {"logs": sample_logs, "summary": summary}

def demo_threat_intel():
    pretty_header("Threat Intelligence (VirusTotal)")
    # Using a well-known empty hash for demo:
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # SHA256 of empty content
    vt = vt_lookup_sha256(sha256)

    tbl = Table(title="VirusTotal Verdict 🔬")
    tbl.add_column("Field")
    tbl.add_column("Value")
    for k, v in vt.items():
        tbl.add_row(k, str(v))
    console.print(tbl)
    return {"sha256": sha256, "vt": vt}

def save_report(components: dict) -> str:
    out = {
        "tagline": "AI-Powered Digital Forensics & Cyber Threat Intelligence Platform",
        "components": components,
    }
    path = REPORT_DIR / "demo_report.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    return str(path)

def main():
    console.print("[bold magenta]ForensAI Nexus[/] — AI-Powered Digital Forensics & CTI ⚔️")
    keys_healthcheck()
    triage = demo_evidence_triage()
    llm = demo_llm_summary()
    vt = demo_threat_intel()

    report_path = save_report({"triage": triage, "llm": llm, "virustotal": vt})
    console.print(f"[bold green]📄 Report saved:[/] {report_path}")
    console.print("[bold]Done.[/] 🎉")

if __name__ == "__main__":
    main()
