from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from google import genai
import re
import cv2
from pyzbar.pyzbar import decode
import pytesseract
import numpy as np

pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

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

def process_image_to_text(image_bytes: bytes) -> str:
    nparr = np.frombuffer(image_bytes, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    
    if img is None:
        raise HTTPException(status_code=400, detail="Invalid image file format.")

    # Step 1: QR Code Scanner Fallback Gate
    qr_codes = decode(img)
    if qr_codes:
        return qr_codes[0].data.decode("utf-8")

    # Step 2: OCR Text Extraction Fallback Gate
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    ocr_text = pytesseract.image_to_string(gray).strip()
    
    if ocr_text:
        return ocr_text

    # Step 3: Failure Trap (Neither QR nor text found)
    raise HTTPException(status_code=400, detail="Unable to read image. Please upload a clearer screenshot or enter text manually.")

async def run_fraud_analysis(message: str):
    clean_message = message.replace("\u200b", "")

    md_link_pattern = r'\[([^\]]+)\]\((https?://[^\s)]+)\)'
    raw_link_pattern = r'https?://[^\s]+'
    
    found_links = []
    for text, url in re.findall(md_link_pattern, clean_message):
        found_links.append(url)
    for url in re.findall(raw_link_pattern, clean_message):
        if url not in found_links:
            found_links.append(url)
            
    links_formatted = "\n".join(found_links) if found_links else "None"

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
async def detect_scam_text(data: ScamRequest):
    return await run_fraud_analysis(data.text)

@app.post("/detect-image")
async def detect_scam_image(file: UploadFile = File(...)):
    image_bytes = await file.read()
    extracted_text = process_image_to_text(image_bytes)
    return await run_fraud_analysis(extracted_text)