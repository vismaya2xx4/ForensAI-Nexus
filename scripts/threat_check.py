from __future__ import annotations
import os
import hashlib
import requests
from typing import Optional, Dict
from dotenv import load_dotenv

load_dotenv()

VT_API = "https://www.virustotal.com/api/v3/files/{}"

def sha256_of_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def sha256_of_path(path: str) -> str:
    with open(path, "rb") as f:
        return sha256_of_bytes(f.read())

def vt_lookup_sha256(sha256: str) -> Dict:
    """
    Query VirusTotal for a known hash.
    Returns a normalized dict with keys: found, malicious_count, suspicious_count, harmless_count, undetected_count, permalink
    If VT key is missing or request fails, returns a graceful fallback.
    """
    api_key = os.getenv("VT_API_KEY")
    headers = {"x-apikey": api_key} if api_key else None

    if not api_key:
        return {
            "found": False,
            "reason": "VT_API_KEY not configured",
            "malicious_count": 0,
            "suspicious_count": 0,
            "harmless_count": 0,
            "undetected_count": 0,
            "permalink": None,
        }

    try:
        r = requests.get(VT_API.format(sha256), headers=headers, timeout=15)
        if r.status_code == 404:
            return {
                "found": False,
                "reason": "Not in VT dataset",
                "malicious_count": 0,
                "suspicious_count": 0,
                "harmless_count": 0,
                "undetected_count": 0,
                "permalink": None,
            }
        r.raise_for_status()
        data = r.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        link = data.get("data", {}).get("links", {}).get("self")
        return {
            "found": True,
            "malicious_count": int(stats.get("malicious", 0)),
            "suspicious_count": int(stats.get("suspicious", 0)),
            "harmless_count": int(stats.get("harmless", 0)),
            "undetected_count": int(stats.get("undetected", 0)),
            "permalink": link,
        }
    except requests.RequestException as e:
        return {
            "found": False,
            "reason": f"VT request failed: {e}",
            "malicious_count": 0,
            "suspicious_count": 0,
            "harmless_count": 0,
            "undetected_count": 0,
            "permalink": None,
        }
