chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === "complete" && tab.url) {
      const currentUrl = tab.url;
  
      // Replace with your actual backend URL
      fetch("https://your-backend-url.com/predict", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ url: currentUrl })
      })
        .then(response => response.json())
        .then(data => {
          if (data.result === "phishing") {
            chrome.scripting.executeScript({
              target: { tabId: tabId },
              func: () => {
                alert("⚠️ Warning: This site may be a phishing site!");
              }
            });
          }
        })
        .catch(error => {
          console.error("Error fetching from backend:", error);
        });
    }
  });
  