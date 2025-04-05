document.getElementById("checkButton").addEventListener("click", async () => {
    const url = document.getElementById("urlInput").value;
  
    if (!url) {
      alert("Please enter a URL");
      return;
    }
  
    try {
      const res = await fetch("http://127.0.0.1:5000/predict", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url: url }),
      });
  
      const data = await res.json();
      document.getElementById("result").textContent =
        `🛡️ Result: ${data.result} (Confidence: ${data.confidence})`;
    } catch (err) {
      document.getElementById("result").textContent =
        "❌ Failed to connect to backend. Is Flask running?";
    }
  });
  