function updateFileName() {
    const input = document.getElementById('imageInput');
    const display = document.getElementById('fileNameDisplay');
    if (input.files && input.files[0]) {
        display.innerText = "Selected: " + input.files[0].name;
    } else {
        display.innerText = "📁 Click to browse or drop screenshot here";
    }
}

document.getElementById('scamForm').addEventListener('submit', async function(event) {
    event.preventDefault();
    
    const textValue = document.getElementById('userInput').value;
    const fileInput = document.getElementById('imageInput').files[0];

    const formData = new FormData();
    if (textValue) formData.append('text', textValue);
    if (fileInput) formData.append('file', fileInput);

    const submitBtn = document.getElementById('submitBtn');
    const resultContainer = document.getElementById('resultContainer');
    
    submitBtn.innerText = "Running Deep Threat Scan...";
    submitBtn.disabled = true;
    resultContainer.classList.add('hidden');

    try {
        const response = await fetch('http://127.0.0.1:8000/detect', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.detail || "Processing pipeline failure.");
        }

        // Populate elements dynamically after completion
        document.getElementById('scamResult').innerText = "Verdict: " + (data.scam === "Yes" ? "MALICIOUS / SCAM ❌" : "SAFE ✅");
        document.getElementById('probabilityBadge').innerText = "Probability: " + data.probability;
        document.getElementById('linksResult').innerText = data.links;
        document.getElementById('detailsResult').innerText = data.details;

        const banner = document.getElementById('verdictBanner');
        banner.className = "verdict-banner " + (data.scam === "Yes" ? "is-scam" : "is-safe");

        resultContainer.classList.remove('hidden');
    } catch (error) {
        alert("Error: " + error.message);
    } finally {
        submitBtn.innerText = "Analyze Content Simultaneously";
        submitBtn.disabled = false;
    }
});