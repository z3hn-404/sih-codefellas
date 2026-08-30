from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from google import genai
import re

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

client = genai.Client(api_key="API-KEY")

class ScamRequest(BaseModel):
    text: str

@app.post("/detect")
async def detect_scam(data: ScamRequest):
    message = data.text.replace("\u200b", "")

    md_link_pattern = r'\[([^\]]+)\]\((https?://[^\s)]+)\)'
    raw_link_pattern = r'https?://[^\s]+'
    
    found_links = []
    
    md_matches = re.findall(md_link_pattern, message)
    for text, url in md_matches:
        found_links.append(url)
        
    raw_matches = re.findall(raw_link_pattern, message)
    for url in raw_matches:
        if url not in found_links:
            found_links.append(url)
            
    links_formatted = "\n".join(found_links) if found_links else "None"

    text_only = re.sub(md_link_pattern, '', message)
    text_only = re.sub(raw_link_pattern, '', text_only).strip()

    prompt = f"""
    You are an expert financial fraud and cybercrime analyst. Evaluate the following message content to determine if it is a scam (financial fraud, banking scam, or brand impersonation).

    Analyze the text against these exact indicators:
    1. Financial Urgency / Pressure (forcing immediate action regarding money/accounts).
    2. Impersonation of Trusted Entities (banks, government agencies, official payment apps, law enforcement).
    3. Requests for Sensitive Financial Data (PIN, OTP, passwords, UPI handles, full card numbers, or direct fund transfers).
    4. Unsolicited Monetary Rewards or Prizes requiring a fee.

    CRITICAL INSTRUCTION: Do NOT flag normal financial notifications, standard bank alerts, legitimate marketing, or casual conversations as scams unless clear malicious intent or pressure tactics are present.

    Provide your evaluation in this exact format:
    Result: [Yes or No]
    Reason: [One brief sentence explaining why]

    Text to analyze: {text_only}
    """
    
    response = client.models.generate_content(
        model="gemini-3.5-flash-lite",
        contents=prompt
    )
    
    output_text = response.text.strip()
    is_scam = "Result: Yes" in output_text or "Yes" in output_text.split("\n")[0]
    
    return {
        "scam": "Yes" if is_scam else "No",
        "links": links_formatted,
        "details": output_text
    }