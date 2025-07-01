# threat_check.py
import requests
from dotenv import load_dotenv
import os

load_dotenv()
API_KEY = os.getenv("RAPIDAPI_KEY")

def check_virustotal(file_hash):
    url = f"https://virustotal-community.p.rapidapi.com/file/report?resource={file_hash}"
    headers = {"X-RapidAPI-Key": API_KEY}
    response = requests.get(url, headers=headers)
    return response.json().get("positives", 0)  # Number of AV engines detecting malware
