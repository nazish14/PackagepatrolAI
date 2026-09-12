import os
import streamlit as st
from groq import Groq

def get_groq_client():
    api_key = os.getenv("GROQ_API_KEY") or st.secrets.get("GROQ_API_KEY")
    if not api_key:
        raise ValueError("GROQ_API_KEY is missing. Add it to .streamlit/secrets.toml or your environment variables.")
    return Groq(api_key=api_key)

def generate_ai_explanation(scan_result):
    client = get_groq_client()
    
    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {
                "role": "system",
                "content": "You are a cybersecurity expert explaining dependency risk scan results.",
            },
            {
                "role": "user",
                "content": f"Explain these package scan results: {scan_result}",
            },
        ],
        temperature=0.2,
    )
    return response.choices[0].message.content
