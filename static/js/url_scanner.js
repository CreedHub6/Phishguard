document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('urlScannerForm');
    const ajaxForm = document.getElementById('urlScannerAjaxForm');
    const urlInput = document.getElementById('urlInput');
    const ajaxUrlInput = document.getElementById('ajaxUrlInput');
    const scanProgress = document.getElementById('scanProgress');
    const progressFill = document.getElementById('progressFill');
    const scanSteps = document.getElementById('scanSteps');
    const scanResult = document.getElementById('scanResult');
    
    // Check if we should use AJAX (modern browsers)
    const useAjax = typeof window.fetch === 'function';
    
    if (useAjax) {
        // Use AJAX for modern browsers
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const url = urlInput.value.trim();
            if (!url) return;
            
            // Set the value for AJAX form
            ajaxUrlInput.value = url;
            
            // Show loading animation
            scanProgress.style.display = 'block';
            scanResult.style.display = 'none';
            
            // Simulate progress animation
            simulateProgress();
            
            // Send AJAX request
            fetch('/api/scan-url/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCookie('csrftoken')
                },
                body: JSON.stringify({ url: url })
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json();
            })
            .then(data => {
                displayResults(data);
            })
            .catch(error => {
                console.error('Error:', error);
                // Fall back to regular form submission
                form.submit();
            });
        });
    }
    // If not using AJAX, the form will submit normally
    
    function simulateProgress() {
        let width = 0;
        const steps = [
            'Initializing scan',
            'Analyzing URL structure',
            'Extracting domain information',
            'Checking domain registration',
            'Analyzing redirects',
            'Checking threat databases',
            'Checking security protocols',
            'Finalizing results'
        ];
        
        steps.forEach((step, index) => {
            setTimeout(() => {
                width = ((index + 1) / steps.length) * 100;
                progressFill.style.width = width + '%';
                
                const stepElement = document.createElement('div');
                stepElement.className = 'scan-step';
                stepElement.innerHTML = `
                    <i class="fas fa-spinner fa-spin"></i>
                    <span>${step}</span>
                `;
                scanSteps.appendChild(stepElement);
                
                // Mark previous steps as completed
                if (index > 0) {
                    const previousSteps = scanSteps.querySelectorAll('.scan-step');
                    previousSteps.forEach((prevStep, i) => {
                        if (i < index) {
                            prevStep.innerHTML = `
                                <i class="fas fa-check-circle text-success"></i>
                                <span>${steps[i]}</span>
                            `;
                        }
                    });
                }
            }, index * 800);
        });
    }
    
    function displayResults(data) {
        scanProgress.style.display = 'none';
        
        // Create result container if it doesn't exist
        if (!scanResult) {
            const resultDiv = document.createElement('div');
            resultDiv.id = 'scanResult';
            resultDiv.className = 'result-container';
            form.parentNode.insertBefore(resultDiv, form.nextSibling);
        }
        
        scanResult.style.display = 'block';
        scanResult.innerHTML = '';
        
        // Create and populate results
        const resultTemplate = document.createElement('div');
        resultTemplate.innerHTML = `
            <h2>Scan Results for: ${data.url}</h2>
            
            <div class="result-card ${data.is_safe ? 'safe' : 'warning'}">
                <div class="result-header">
                    <i class="fas fa-${data.is_safe ? 'check-circle' : 'exclamation-triangle'}"></i>
                    <h3>${data.message}</h3>
                </div>
                
                ${data.warnings && data.warnings.length > 0 ? `
                <div class="result-details">
                    <h4>Security Warnings:</h4>
                    <ul>
                        ${data.warnings.map(warning => `<li><i class="fas fa-exclamation-circle"></i> ${warning}</li>`).join('')}
                    </ul>
                </div>
                ` : ''}
                
                ${data.domain_info && Object.keys(data.domain_info).length > 0 ? `
                <div class="result-details">
                    <h4>Domain Information:</h4>
                    <div class="info-grid">
                        ${Object.entries(data.domain_info).map(([key, value]) => `
                            <div class="info-item">
                                <strong>${key.replace(/_/g, ' ').toUpperCase()}:</strong> ${value || 'Not available'}
                            </div>
                        `).join('')}
                    </div>
                </div>
                ` : ''}
                
                ${data.redirects && data.redirects.length > 0 ? `
                <div class="result-details">
                    <h4>Redirects:</h4>
                    <ol>
                        ${data.redirects.map(redirect => `<li>${redirect.url} (Status: ${redirect.status})</li>`).join('')}
                    </ol>
                </div>
                ` : ''}
                
                <div class="result-actions">
                    <button class="btn btn-secondary" onclick="window.location.reload()">
                        <i class="fas fa-redo"></i> Scan Another URL
                    </button>
                </div>
            </div>
        `;
        
        scanResult.appendChild(resultTemplate);
    }
    
    // Helper function to get CSRF token
    function getCookie(name) {
        let cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                if (cookie.substring(0, name.length + 1) === (name + '=')) {
                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                    break;
                }
            }
        }
        return cookieValue;
    }
});
