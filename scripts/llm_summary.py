# llm_summary.py
from langchain.llms import OpenAI
from dotenv import load_dotenv
import os

load_dotenv()
llm = OpenAI(model="gpt-3.5-turbo-instruct", temperature=0)

def summarize_logs(logs):
    prompt = f"""Analyze these forensic logs and list critical threats:
    {logs}
    """
    return llm(prompt)

# Example: print(summarize_logs("Failed logins: 192.168.1.100 (5 times)"))
