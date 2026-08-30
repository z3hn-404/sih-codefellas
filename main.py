from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from google import genai
import re
import json
import cv2
from pyzbar.pyzbar import decode
import pytesseract
import numpy as np
import requests
import os
from urllib.parse import urlparse
from datetime import datetime, timezone

pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

client = genai.Client(api_key="AQ.Ab8RN6IqNgNe7MwgPQbafKlc_QCoJ0PhQQ_IN_lYh8iHUI65cQ")

GSB_API_KEY = "AIzaSyCbHwJqBmzxY14bnE65qjxYfuuzgfWNT2s"
WHOIS_API_KEY = os.getenv("WHOIS_API_KEY", "")  # Optional free token from whoisjson.com or similar provider


def unshorten_url(url: str) -> str:
    """Resolves short links (bit.ly, tinyurl, etc.) to their target URL."""
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.head(
            url, allow_redirects=True, timeout=5, headers=headers
        )
        return response.url
    except Exception:
        return url


def get_domain_age_days(domain: str) -> int:
    """Performs a WHOIS lookup to calculate how many days ago the domain was created."""
    try:
        # Utilizing a standard open RDAP/WHOIS endpoint or fallback service
        # Using WhoisJSON free public endpoint style or public RDAP query
        rdap_url = f"https://rdap.org/domain/{domain}"
        headers = {"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
        response = requests.get(rdap_url, headers=headers, timeout=4)
        
        if response.status_code == 200:
            data = response.json()
            events = data.get("events", [])
            for event in events:
                if event.get("eventAction") == "registration":
                    reg_date_str = event.get("eventDate")
                    reg_date = datetime.fromisoformat(reg_date_str.replace("Z", "+00:00"))
                    age_days = (datetime.now(timezone.utc) - reg_date).days
                    return max(0, age_days)
    except Exception:
        pass
    
    return -1  # Unknown age


def check_url_safety(url: str) -> dict:
    """Cross-checks a single URL against GSB and evaluates domain age via WHOIS/RDAP."""
    if not url or not url.strip():
        return {"url": url, "status": "Unknown ⚠️ (No URL provided)", "is_unsafe": False, "age_days": -1}

    real_url = unshorten_url(url)
    parsed_url = urlparse(real_url)
    domain = parsed_url.netloc.lower()
    if domain.startswith("www."):
        domain = domain[4:]

    # 1. Check Domain Age via WHOIS/RDAP logic
    age_days = get_domain_age_days(domain) if domain else -1

    # 2. Check Google Safe Browsing
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
    payload = {
        "client": {
            "clientId": "heimdall-scam-detector",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": real_url}],
        },
    }

    is_unsafe = False
    safety_label = "Safe ✅"

    try:
        response = requests.post(
            endpoint,
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
            timeout=5,
        )

        if response.status_code == 200:
            result = response.json()
            if result and "matches" in result and result["matches"]:
                threat_type = result["matches"][0].get("threatType", "unknown")
                safety_label = f"Unsafe ❌ (Flagged: {threat_type})"
                is_unsafe = True
        else:
            safety_label = "Unknown ⚠️ (API Limit/Error)"
    except Exception:
        safety_label = "Unknown ⚠️ (Connection Failed)"

    # Heuristic fallback: If domain was registered less than 30 days ago, flag dynamically as risky/unsafe
    if not is_unsafe and 0 <= age_days < 30:
        safety_label = f"Unsafe ❌ (Newly Registered Domain: {age_days} days old)"
        is_unsafe = True

    age_text = f" | Age: {age_days} days" if age_days >= 0 else " | Age: Unknown"
    return {
        "url": url,
        "display_str": f"{url} -> {safety_label}{age_text}",
        "is_unsafe": is_unsafe
    }


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
            
    # Check all URLs and track if ANY link is malicious
    any_url_malicious = False
    formatted_links_list = []
    
    for link in found_links:
        link_result = check_url_safety(link)
        formatted_links_list.append(link_result["display_str"])
        if link_result["is_unsafe"]:
            any_url_malicious = True

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
    Probability: [Integer percentage score from 0 to 100 representing scam likelihood]
    Reason: [One brief sentence explaining why]

    Text to analyze: {text_only}
    """
    
    response = client.models.generate_content(
        model="gemini-3.5-flash-lite",
        contents=prompt
    )
    
    output_text = response.text.strip()
    
    # Extract probability score via regex search from LLM response
    prob_match = re.search(r'Probability:\s*([0-9]+)%?', output_text, re.IGNORECASE)
    ai_probability = int(prob_match.group(1)) if prob_match else (85 if "Result: Yes" in output_text else 10)

    # RULE 1 IMPLEMENTATION: If even ONE URL is flagged malicious/unsafe, override final status to Yes and force probability to 99%
    if any_url_malicious:
        is_scam = "Yes"
        probability = 99
        if "Result: No" in output_text:
            output_text = output_text.replace("Result: No", "Result: Yes")
        elif "Result: Yes" not in output_text:
            output_text = "Result: Yes\n" + output_text
        if not re.search(r'Probability:', output_text, re.IGNORECASE):
            output_text += f"\nProbability: {probability}%"
        else:
            output_text = re.sub(r'Probability:\s*[0-9]+%?', f"Probability: {probability}%", output_text, flags=re.IGNORECASE)
    else:
        is_scam = "Yes" if ("Result: Yes" in output_text or ai_probability >= 50) else "No"
        probability = ai_probability

    detailed_output = f"{output_text}\nCalculated Scam Probability: {probability}%"

    return {
        "scam": is_scam,
        "probability": f"{probability}%",
        "links": links_formatted,
        "details": detailed_output
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