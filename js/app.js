document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('check-form');
    const resultBox = document.getElementById('result');
    const statusText = document.getElementById('result-status');
    const submitBtn = form.querySelector('.submit');
    
    // Select metric slots
    const likelyScamSlot = document.querySelector('[data-slot="likely-scam"]');
    const scamProbSlot = document.querySelector('[data-slot="scam-prob"]');
    const whoisDateSlot = document.querySelector('[data-slot="whois-date"]');
    const geminiExplanation = document.getElementById('gemini-explanation');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        // 1. Loading UI State
        submitBtn.disabled = true;
        submitBtn.innerHTML = 'Scanning...';
        resultBox.hidden = false;
        
        // Reset metrics to skeleton state
        [likelyScamSlot, scamProbSlot, whoisDateSlot].forEach(slot => {
            slot.textContent = '—';
            slot.classList.add('skeleton');
        });
        statusText.textContent = 'Awaiting Sentinel Analysis...';
        geminiExplanation.textContent = 'Gemini AI is analyzing content and visual cues...';

        // 2. Package form data
        const formData = new FormData(form);

        try {
            // 3. Request FastAPI Backend
            const response = await fetch('http://127.0.0.1:8000/api/scan', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                throw new Error(`Server returned status ${response.status}`);
            }

            const data = await response.json();

            // 4. Populate UI elements
            likelyScamSlot.textContent = data.likely_scam; // Yes / No
            scamProbSlot.textContent = data.scam_probability; // e.g. 85%
            whoisDateSlot.textContent = data.whois_date; // YYYY-MM-DD or N/A
            geminiExplanation.textContent = data.explanation;

            // Highlight status styling
            if (data.likely_scam.toLowerCase() === 'yes') {
                statusText.textContent = 'Threat Detected';
                statusText.style.color = '#ff4a4a';
                likelyScamSlot.style.color = '#ff4a4a';
            } else {
                statusText.textContent = 'Content Appears Safe';
                statusText.style.color = '#4ade80';
                likelyScamSlot.style.color = '#4ade80';
            }

            // Remove skeleton loaders
            [likelyScamSlot, scamProbSlot, whoisDateSlot].forEach(slot => {
                slot.classList.remove('skeleton');
            });

        } catch (error) {
            console.error('Error scanning content:', error);
            statusText.textContent = 'Analysis Error';
            geminiExplanation.textContent = 'Unable to connect to the backend server or process the request. Please check if FastAPI is running.';
        } finally {
            submitBtn.disabled = false;
            submitBtn.innerHTML = 'Scan Content <span class="arrow" aria-hidden="true">→</span>';
        }
    });
});