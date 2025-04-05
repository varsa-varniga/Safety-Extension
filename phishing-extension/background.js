const alertedTabs = new Set();

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && /^https?:/.test(tab.url)) {
    // Avoid alerting the same tab again
    if (alertedTabs.has(tabId)) return;

    fetch("http://127.0.0.1:5000/predicturl", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url: tab.url })
    })
    .then(response => response.json())
    .then(data => {
      if (data.prediction && data.prediction.toLowerCase() === "phishing") {
        // Mark this tab as alerted
        alertedTabs.add(tabId);

        chrome.scripting.executeScript({
          target: { tabId: tabId },
          files: ["alert-injector.js"]
        });
      }
    })
    .catch(err => {
      console.error("Error checking phishing:", err);
    });
  }
});

// Clear flagged tabs if they are closed
chrome.tabs.onRemoved.addListener((tabId) => {
  alertedTabs.delete(tabId);
});
