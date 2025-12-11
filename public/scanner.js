document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('scannerForm');
    const inputField = document.getElementById('inputCommand');

    form.addEventListener('submit', (e) => {
        e.preventDefault();
        const command = inputField.value.trim();
        const groundTruth = document.getElementById('groundTruth').value;
        
        if (!command) {
            alert('Please enter a command or payload to scan');
            return;
        }

        // Encode the input for URL
        const encodedInput = encodeURIComponent(command);
        let url = `/search?mode=vulnerable&q=${encodedInput}`;
        
        // Add ground truth if specified
        if (groundTruth) {
            url += `&truth=${encodeURIComponent(groundTruth)}`;
        }
        
        // Navigate to results page
        window.location.href = url;
    });
});

function loadExample(payload, groundTruth = '') {
    document.getElementById('inputCommand').value = payload;
    if (groundTruth) {
        document.getElementById('groundTruth').value = groundTruth;
    }
}

