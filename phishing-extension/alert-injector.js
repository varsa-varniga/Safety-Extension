(function () {
  // Check the URL and send a phishing alert if it's detected
  const url = window.location.href;

  fetch("http://127.0.0.1:5000/predicturl", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ url: url })
  })
  .then(response => response.json())
  .then(data => {
    if (data.prediction === "phishing") {
      alert("⚠️ Phishing website detected! Phishing score: " + data.phishing_probability + "%");
    }
  })
  .catch(err => console.log("Error in phishing detection:", err));
})();
