function fetchPhishingPrediction(url) {
  fetch("http://127.0.0.1:5000/predicturl", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ url: url })
  })
    .then(response => response.json())
    .then(data => {
      const resultDiv = document.getElementById("result");
      const noteDiv = document.getElementById("note");

      if (data.prediction) {
        if (data.prediction.toLowerCase() === "phishing") {
          resultDiv.className = "phishing";
          resultDiv.innerHTML = `⚠️ Phishing Detected! (${data.phishing_probability}%)`;
          noteDiv.innerHTML = "This site may try to steal your data!";
        } else {
          resultDiv.className = "safe";
          resultDiv.innerHTML = `✅ Legitimate Website`;
          noteDiv.innerHTML = "This URL seems safe.";
        }
      } else {
        resultDiv.className = "";
        resultDiv.innerHTML = "❌ No prediction received.";
      }
    })
    .catch(err => {
      const resultDiv = document.getElementById("result");
      resultDiv.className = "";
      resultDiv.innerHTML = "❌ Server error. Try again.";
      console.error("Error:", err);
    });
}

// Automatically runs when popup is opened
document.addEventListener("DOMContentLoaded", function () {
  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    const currentUrl = tabs[0].url;
    fetchPhishingPrediction(currentUrl);
  });
});
