document.addEventListener('DOMContentLoaded', () => {
    // Check if already logged in
    const token = localStorage.getItem('vendor_token');
    if (token) {
        showDashboard();
    }

    // Login Form Submission
    document.getElementById('login-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const errorMsg = document.getElementById('login-error');
        errorMsg.textContent = '';
        
        const formData = new FormData();
        formData.append('username', document.getElementById('username').value);
        formData.append('password', document.getElementById('password').value);

        try {
            const res = await fetch('/api/login', {
                method: 'POST',
                body: formData
            });

            if (res.ok) {
                const data = await res.json();
                localStorage.setItem('vendor_token', data.access_token);
                showDashboard();
            } else {
                errorMsg.textContent = 'Invalid credentials. Please try again.';
            }
        } catch (err) {
            errorMsg.textContent = 'Network error. Make sure the server is running.';
        }
    });

    // Logout
    document.getElementById('logout-btn').addEventListener('click', () => {
        localStorage.removeItem('vendor_token');
        showLogin();
    });

    // Generate License Form
    let lastOfflineResponse = null;

    document.getElementById('generate-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const generateBtn = document.getElementById('generate-btn');
        const generateText = document.getElementById('generate-text');
        const loader = document.getElementById('generate-loader');
        
        // Show loader
        generateBtn.disabled = true;
        generateText.classList.add('hidden');
        loader.classList.remove('hidden');

        // Gather checked features
        const features = [];
        document.querySelectorAll('input[type="checkbox"]:checked').forEach(cb => features.push(cb.value));

        const payload = {
            customer_name: document.getElementById('customer_name').value,
            tier: document.getElementById('tier').value,
            validity_days: parseInt(document.getElementById('validity_days').value, 10),
            machine_fingerprint: document.getElementById('machine_fingerprint').value,
            features: features
        };

        try {
            const token = localStorage.getItem('vendor_token');
            const res = await fetch('/api/generate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify(payload)
            });

            if (res.status === 401) {
                localStorage.removeItem('vendor_token');
                showLogin();
                return;
            }

            if (res.ok) {
                const data = await res.json();
                document.getElementById('display-key').textContent = data.license_key;
                lastOfflineResponse = data.offline_response;
                
                document.getElementById('result-section').classList.remove('hidden');
            } else {
                const error = await res.json();
                let errMsg = error.detail;
                if (Array.isArray(errMsg)) {
                    errMsg = errMsg.map(e => `${e.loc.join('.')}: ${e.msg}`).join(', ');
                }
                alert(`Error generating license: ${errMsg}`);
            }
        } catch (err) {
            alert('Network error while communicating with server.');
        } finally {
            generateBtn.disabled = false;
            generateText.classList.remove('hidden');
            loader.classList.add('hidden');
        }
    });

    // Copy to clipboard
    document.getElementById('copy-btn').addEventListener('click', () => {
        const key = document.getElementById('display-key').textContent;
        navigator.clipboard.writeText(key).then(() => {
            const btn = document.getElementById('copy-btn');
            btn.textContent = '✅';
            setTimeout(() => btn.textContent = '📋', 2000);
        });
    });

    // Download offline response
    document.getElementById('download-btn').addEventListener('click', () => {
        if (!lastOfflineResponse) return;
        
        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(lastOfflineResponse, null, 4));
        const downloadAnchorNode = document.createElement('a');
        downloadAnchorNode.setAttribute("href", dataStr);
        downloadAnchorNode.setAttribute("download", "governexa-license-response.json");
        document.body.appendChild(downloadAnchorNode); // required for firefox
        downloadAnchorNode.click();
        downloadAnchorNode.remove();
    });
});

function showDashboard() {
    document.getElementById('login-container').classList.remove('active');
    document.getElementById('login-container').classList.add('hidden');
    
    document.getElementById('dashboard-container').classList.remove('hidden');
    document.getElementById('dashboard-container').classList.add('active');
}

function showLogin() {
    document.getElementById('dashboard-container').classList.remove('active');
    document.getElementById('dashboard-container').classList.add('hidden');
    
    document.getElementById('login-container').classList.remove('hidden');
    document.getElementById('login-container').classList.add('active');
    document.getElementById('result-section').classList.add('hidden');
}
