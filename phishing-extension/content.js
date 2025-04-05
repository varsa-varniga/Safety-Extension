(async () => {
    const url = window.location.href;
  
    // Call your phishing detection API or model here
    const response = await fetch('http://127.0.0.1:5000/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: window.location.href })
      });
      
    const result = await response.json();
  
    // Display result as banner on the website
    const banner = document.createElement('div');
    banner.style.position = 'fixed';
    banner.style.top = '0';
    banner.style.left = '0';
    banner.style.width = '100%';
    banner.style.padding = '10px';
    banner.style.zIndex = '9999';
    banner.style.color = '#fff';
    banner.style.textAlign = 'center';
    banner.style.fontWeight = 'bold';
  
    if (result.is_phishing) {
      banner.style.backgroundColor = '#e74c3c'; // red
      banner.textContent = '⚠️ Warning: This site might be phishing!';
    } else {
      banner.style.backgroundColor = '#2ecc71'; // green
      banner.textContent = '✅ This site appears to be legitimate.';
    }
  
    document.body.appendChild(banner);
  })();
  