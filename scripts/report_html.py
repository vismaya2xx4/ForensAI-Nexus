from pathlib import Path
import json

TEMPLATE = """<!doctype html>
<html lang="en"><meta charset="utf-8">
<title>ForensAI Nexus Report</title>
<style>
body{font-family:ui-sans-serif,system-ui,Segoe UI,Arial;margin:40px}
h1{margin-top:0} code,pre{background:#f6f8fa;padding:.5rem;border-radius:8px;display:block}
table{border-collapse:collapse;width:100%;margin:1rem 0} th,td{border:1px solid #ddd;padding:.5rem;text-align:left}
.bad{color:#b91c1c;font-weight:600} .ok{color:#15803d;font-weight:600}
</style>
<h1>ForensAI Nexus — Report</h1>
<p><em>{tagline}</em></p>
<h2>AI Evidence Triage</h2>
<table><tr><th>#</th><th>file_size</th><th>entropy</th><th>is_signed</th><th>risk_score</th><th>label</th></tr>
{rows}
</table>
<h2>LLM Summary</h2>
<pre>{llm}</pre>
<h2>VirusTotal</h2>
<pre>{vt}</pre>
</html>
"""

def export_html(json_path="reports/demo_report.json", out_path="reports/demo_report.html"):
    data = json.loads(Path(json_path).read_text(encoding="utf-8"))
    triage = data["components"]["triage"]
    rows = []
    for i, item in enumerate(triage):
        s = item["sample"]; r = item["risk_score"]; lbl = "malicious" if item["label"] else "clean"
        rows.append(f"<tr><td>{i}</td><td>{s['file_size']}</td><td>{s['entropy']}</td>"
                    f"<td>{s['is_signed']}</td><td>{r:.3f}</td>"
                    f"<td class=\"{'bad' if lbl=='malicious' else 'ok'}\">{lbl}</td></tr>")
    llm = data["components"]["llm"]["summary"]
    vt = json.dumps(data["components"]["virustotal"], indent=2)
    html = TEMPLATE.format(tagline=data["tagline"], rows="\n".join(rows), llm=llm, vt=vt)
    Path(out_path).write_text(html, encoding="utf-8")
    return out_path

if __name__ == "__main__":
    p = export_html()
    print("HTML report saved:", p)
