const scannedTabs = new Map();

chrome.webNavigation.onCommitted.addListener(async (details) => {
  // Only main frame
  if (details.frameId !== 0) return;
  const url = details.url;
  const tabId = details.tabId;
  
  // Only http/https
  if (!url.startsWith("http://") && !url.startsWith("https://")) return;
  
  // Deduplicate per tab
  if (scannedTabs.get(tabId) === url) return;
  scannedTabs.set(tabId, url);
  
  console.log("SCANNING:", url);
  
  try {
    const res = await fetch("http://localhost:8000/detect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    
    if (!res.ok) {
      console.error("Server error:", res.status);
      return;
    }
    
    const data = await res.json();
    
    if (data.verdict === "scam") {
      chrome.tabs.update(tabId, {
        url: chrome.runtime.getURL("blocked.html")
      });
    }
  } catch (error) {
    console.error("Failed to scan URL:", error);
  }
});