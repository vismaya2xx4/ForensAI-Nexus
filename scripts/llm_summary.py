from __future__ import annotations
import os
from typing import List, Dict
from dotenv import load_dotenv

# OpenAI new-style SDK
from openai import OpenAI, APIConnectionError, RateLimitError, APIStatusError

load_dotenv()

def _client():
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return None
    return OpenAI(api_key=api_key)

def summarize_logs(log_lines: List[str], model: str | None = None) -> str:
    """
    Summarize security logs into plain English with remediation steps.
    Falls back to an offline template if OPENAI_API_KEY is not set.
    """
    if not log_lines:
        return "No logs provided."

    joined = "\n".join(log_lines[:200])  # prevent huge prompts
    model_name = model or os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    client = _client()
    if client is None:
        # Offline fallback
        return (
            "🧠 (Offline LLM) Forensic Summary\n"
            "• Observed {n} log lines.\n"
            "• Noted potential anomalies where failed auth, high entropy, or unsigned executables were present.\n"
            "• Recommend: isolate suspicious hosts, compute file hashes, scan with VirusTotal, and review admin logins.\n"
        ).format(n=len(log_lines))

    try:
        resp = client.chat.completions.create(
            model=model_name,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a digital forensics analyst. Summarize logs in bullet points, "
                        "call out IOCs (IPs, hashes, hostnames) and provide 3 concise remediation steps."
                    ),
                },
                {
                    "role": "user",
                    "content": f"Security logs:\n```\n{joined}\n```",
                },
            ],
            temperature=0.2,
            max_tokens=350,
        )
        text = resp.choices[0].message.content.strip()
        return f"🧠 LLM Forensic Summary\n{text}"
    except (APIConnectionError, RateLimitError, APIStatusError) as e:
        return (
            "🧠 (LLM degraded) Could not reach OpenAI API. "
            f"Reason: {getattr(e, 'message', str(e))}\n"
            "Fallback guidance: quarantine suspicious binaries, review admin sessions, and run VT checks."
        )
