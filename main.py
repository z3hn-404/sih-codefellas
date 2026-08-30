import os
import re
import json
import io
from typing import List, Optional
from urllib.parse import urlparse

from fastapi import FastAPI, Form, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import whois
from PIL import Image
import google.generativeai as genai

# Setup FastAPI App
app = FastAPI(title="Heimdall Omniscient Backend")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure Gemini API
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
else:
    print("WARNING: GEMINI_API_KEY environment variable is not set!")


def extract_urls(text: str) -> List[str]:
    """Extract unique URLs or domains from input text."""
    url_pattern = r'https?://[^\s]+|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}'
    matches = re.findall(url_pattern, text)
    return list(set(matches))


def get_whois_creation_date(urls: List[str]) -> str:
    """Returns WHOIS creation date if exactly 1 link is found.

    Returns 'N/A' if 0 or >1 links are detected.
    """
    if len(urls) != 1:
        return "N/A"

    raw_url = urls[0]
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "http://" + raw_url

    try:
        domain = urlparse(raw_url).netloc or urlparse(raw_url).path
        domain = domain.split(":")[0]  # Strip port if present
        w = whois.whois(domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            return creation_date.strftime("%Y-%m-%d")
    except Exception as e:
        print(f"WHOIS lookup error for domain {raw_url}: {e}")
        return "N/A"

    return "N/A"


async def analyze_with_gemini(text_content: str, image_bytes: Optional[bytes]) -> dict:
    """Queries Gemini API for scam evaluation and structured response."""
    if not GEMINI_API_KEY:
        return {
            "likely_scam": "Unknown",
            "scam_probability": "0%",
            "explanation": "Gemini API key is missing on the server. Please set GEMINI_API_KEY.",
        }

    try:
        model = genai.GenerativeModel("gemini-1.5-flash")
        contents = []

        if text_content.strip():
            contents.append(f"User submitted text:\n{text_content}")

        if image_bytes:
            img = Image.open(io.BytesIO(image_bytes))
            contents.append(img)

        prompt = """
        Analyze the provided text and/or image content to determine if it is a scam, phishing attempt, or fraudulent activity.
        
        Respond ONLY with a valid JSON object matching this schema strictly:
        {
            "likely_scam": "Yes" or "No",
            "scam_probability": "XX%",
            "explanation": "A detailed, clear explanation (3-5 sentences) explaining why this content is or is not a scam, pointing out specific red flags (urgency, fake domains, phishing language, suspicious UI elements) if present."
        }
        
        Ensure output is valid JSON without code block wrappers or markdown formatting.
        """
        contents.append(prompt)

        response = model.generate_content(
            contents,
            generation_config={"response_mime_type": "application/json"}
        )

        return json.loads(response.text)

    except Exception as e:
        print(f"Gemini API error: {e}")
        return {
            "likely_scam": "Error",
            "scam_probability": "0%",
            "explanation": f"Error running Gemini AI analysis: {str(e)}",
        }


@app.post("/api/scan")
async def scan_content(
    content: str = Form(""),
    image: Optional[UploadFile] = File(None)
):
    # Read image bytes if uploaded
    image_bytes = None
    if image and image.filename:
        image_bytes = await image.read()

    # If both inputs are empty, return early
    if not content.strip() and not image_bytes:
        raise HTTPException(status_code=400, detail="Please provide text or attach an image.")

    # 1. Extract URLs & run WHOIS check
    detected_urls = extract_urls(content)
    whois_date = get_whois_creation_date(detected_urls)

    # 2. Run Gemini AI analysis
    gemini_result = await analyze_with_gemini(content, image_bytes)

    # 3. Consolidate payload for frontend UI
    return {
        "likely_scam": gemini_result.get("likely_scam", "No"),
        "scam_probability": gemini_result.get("scam_probability", "0%"),
        "whois_date": whois_date,
        "explanation": gemini_result.get("explanation", "No analysis provided.")
    }


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)