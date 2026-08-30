from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from google import genai
import re
import cv2
from pyzbar.pyzbar import decode
import pytesseract
import numpy as np
import requests
import os

pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

client = genai.Client(api_key="GEMINI-API-KEY")

GSB_API_KEY = os.getenv("GSB_API_KEY", "GSB-API-KEY")  # Replace with your actual Google Safe Browsing API key or set it as an environment variable

def check_url_safety(url: str) -> str:
    """Cross-checks a single URL against the Google Safe Browsing API v4. 
    Returns 'Unknown' if network or API issues occur so the program proceeds smoothly."""
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
    
    payload = {
        "client": {
            "clientId": "heimdall-scam-detector",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "entries": [{"url": url}]
        }
    }
    
    try:
        response = requests.post(endpoint, json=payload, timeout=4)
        
        # If API key is unauthorized or returns non-200, return Unknown instead of breaking
        if response.status_code != 200:
            return "Unknown ⚠️ (API Limit/Error)"
            
        result = response.json()
        if result and "matches" in result:
            return "Unsafe ❌ (Flagged by Database)"
            
        return "Safe ✅"
    except Exception:
        # Fails gracefully without stopping the app
        return "Unknown ⚠️ (Connection Failed)"

def process_image_to_text(image_bytes: bytes) -> str:
    nparr = np.frombuffer(image_bytes, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    
    if img is None:
        raise HTTPException(status_code=400, detail="Invalid image file format.")

    qr_codes = decode(img)
    if qr_codes:
        return qr_codes[0].data.decode("utf-8")

    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    ocr_text = pytesseract.image_to_string(gray).strip()
    
    if ocr_text:
        return ocr_text

    raise HTTPException(status_code=400, detail="Unable to read image. Please upload a clearer screenshot.")

async def run_fraud_analysis(message: str):
    clean_message = message.replace("\u200b", "")

    md_link_pattern = r'\[([^\]]+)\]\((https?://[^\s)]+)\)'
    raw_link_pattern = r'https?://[^\s]+'
    
    found_links = []
    for text, url in re.findall(md_link_pattern, clean_message):
        if url not in found_links:
            found_links.append(url)
    for url in re.findall(raw_link_pattern, clean_message):
        if url not in found_links:
            found_links.append(url)
            
    formatted_links_list = []
    for link in found_links:
        status = check_url_safety(link)
        formatted_links_list.append(f"{link} -> {status}")

    links_formatted = "\n".join(formatted_links_list) if formatted_links_list else "None"

    text_only = re.sub(md_link_pattern, '', clean_message)
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

@app.post("/detect")
async def detect_scam(
    text: str = Form(None),
    file: UploadFile = File(None)
):
    combined_message = ""

    if text and text.strip():
        combined_message += text.strip() + "\n"

    if file and file.filename:
        image_bytes = await file.read()
        extracted_text = process_image_to_text(image_bytes)
        combined_message += "\n" + extracted_text

    if not combined_message.strip():
        raise HTTPException(status_code=400, detail="Please provide text or upload an image to analyze.")

    return await run_fraud_analysis(combined_message)