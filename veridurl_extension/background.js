// VeridURL Background Service Worker

const tabStates = new Map(); // { tabId: { domain: string, previousUrl: string } }
const MAX_HISTORY_ITEMS = 50; // Keep up to 50 items in history

// Top 50 highly spoofed brand domains for Levenshtein and substring check
const FAMOUS_BRANDS = [
  "google.com", "gmail.com", "youtube.com", "facebook.com", "instagram.com", 
  "whatsapp.com", "messenger.com", "microsoft.com", "outlook.com", "office.com", 
  "apple.com", "icloud.com", "amazon.com", "netflix.com", "disneyplus.com", 
  "twitter.com", "x.com", "linkedin.com", "reddit.com", "pinterest.com", 
  "tumblr.com", "tiktok.com", "snapchat.com", "paypal.com", "stripe.com", 
  "ebay.com", "walmart.com", "target.com", "bestbuy.com", "chase.com", 
  "bankofamerica.com", "wellsfargo.com", "citibank.com", "capitalone.com", 
  "binance.com", "coinbase.com", "blockchain.com", "github.com", "gitlab.com", 
  "bitbucket.org", "stackoverflow.com", "adobe.com", "dropbox.com", "slack.com", 
  "zoom.us", "discord.com", "spotify.com", "steampowered.com", "twitch.tv"
];

// Helper to get domain/hostname from a URL
function getDomain(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch (e) {
    return url.toLowerCase();
  }
}

// Extract registrable domain (e.g. "paypal.com" from "secure.paypal.com")
function getRegistrableDomain(hostname) {
  const parts = hostname.split('.');
  if (parts.length <= 2) return hostname;
  
  const lastTwo = parts.slice(-2).join('.');
  const commonDoubleTlds = ['co.uk', 'com.br', 'org.uk', 'gov.uk', 'co.in', 'net.in', 'org.in', 'com.au', 'co.jp'];
  if (commonDoubleTlds.includes(lastTwo)) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

// Levenshtein distance algorithm
function getLevenshteinDistance(a, b) {
  const tmp = [];
  const alen = a.length;
  const blen = b.length;
  if (alen === 0) return blen;
  if (blen === 0) return alen;
  for (let i = 0; i <= alen; i++) tmp[i] = [i];
  for (let j = 0; j <= blen; j++) tmp[0][j] = j;
  for (let i = 1; i <= alen; i++) {
    for (let j = 1; j <= blen; j++) {
      tmp[i][j] = Math.min(
        tmp[i - 1][j] + 1,
        tmp[i][j - 1] + 1,
        tmp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
      );
    }
  }
  return tmp[alen][blen];
}

// Local Brand Imitation (Typosquatting) Guard
function checkTyposquatting(hostname) {
  const currentReg = getRegistrableDomain(hostname);
  const currentName = currentReg.split('.')[0];

  for (const brand of FAMOUS_BRANDS) {
    const brandReg = getRegistrableDomain(brand);
    const brandName = brandReg.split('.')[0];

    // If it's an exact match of the famous brand domain or its subdomains, it's trusted
    if (hostname === brandReg || hostname.endsWith('.' + brandReg)) {
      return { isLookalike: false, brand: brandReg };
    }

    // 1. Check edit distance on registrable domain name (e.g. "goog1e" vs "google")
    const dist = getLevenshteinDistance(currentName, brandName);
    if (dist > 0 && dist <= 2) {
      return { isLookalike: true, brand: brandReg, reason: `Lookalike domain detected (edit distance of ${dist} from ${brandReg})` };
    }

    // 2. Check brand name containment (e.g. "paypal-security-update.com" containing "paypal")
    // If the hostname contains the brand name, but the registrable domain is not that brand
    if (currentName.includes(brandName) && currentName !== brandName) {
      // Exclude simple subdomains (e.g. brandName.com as host is already handled)
      return { isLookalike: true, brand: brandReg, reason: `Brand name hijacking ('${brandName}') detected in domain` };
    }
  }
  return { isLookalike: false };
}

// Save the scan result to browser local storage and update stats
function storeScanHistory(result) {
  chrome.storage.local.get(["scanHistory", "stats"], (res) => {
    const history = res.scanHistory || [];
    const stats = res.stats || { totalScanned: 0, phishingBlocked: 0, safeAllowed: 0 };
    
    // Add to history
    history.unshift({
      url: result.url,
      isPhishing: result.isPhishing,
      reason: result.reason || "ML Model Prediction",
      score: result.score !== undefined ? result.score : (result.isPhishing ? 0.15 : 0.85),
      timestamp: new Date().toLocaleString()
    });
    
    // Keep within bounds
    if (history.length > MAX_HISTORY_ITEMS) {
      history.pop();
    }

    // Update stats
    stats.totalScanned += 1;
    if (result.isPhishing) {
      stats.phishingBlocked += 1;
    } else {
      stats.safeAllowed += 1;
    }
    
    chrome.storage.local.set({ scanHistory: history, stats: stats });
  });
}

// Injects warning overlays or safe alerts with premium sky-blue / white themes
function injectPopup(tabId, url, isPhishing, reason = "ML Model Scan", isSamePage = false) {
  const hostname = getDomain(url);
  
  if (isPhishing) {
    // Generate overlay HTML with glassmorphism + sky blue & white aesthetic
    const warningHTML = `
      <div id="veridurl-warning-overlay" style="
        position: fixed;
        top: 0;
        left: 0;
        width: 100vw;
        height: 100vh;
        background: rgba(15, 23, 42, 0.6);
        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 999999999;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        color: #0f172a;
      ">
        <div style="
          background: #ffffff;
          width: 90%;
          max-width: 520px;
          border-radius: 20px;
          border: 1px solid #bae6fd;
          box-shadow: 0 25px 50px -12px rgba(2, 132, 199, 0.25);
          padding: 35px;
          text-align: center;
          animation: veridurl-slide-in 0.4s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        ">
          <!-- Shield Icon -->
          <div style="
            width: 72px;
            height: 72px;
            background: #f0f9ff;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 20px auto;
            border: 2px solid #38bdf8;
            box-shadow: 0 0 15px rgba(56, 189, 248, 0.4);
            animation: veridurl-pulse 2s infinite;
          ">
            <svg style="width: 38px; height: 38px; fill: #0284c7;" viewBox="0 0 24 24">
              <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/>
            </svg>
          </div>

          <h2 style="margin: 0 0 10px 0; font-size: 24px; font-weight: 700; color: #0284c7; letter-spacing: -0.025em;">
            VeridURL Shield Active
          </h2>
          <h3 style="margin: 0 0 15px 0; font-size: 18px; font-weight: 600; color: #ef4444;">
            Phishing Danger Blocked
          </h3>

          <p style="margin: 0 0 25px 0; font-size: 14px; color: #64748b; line-height: 1.6; background: #f0f9ff; padding: 12px; border-radius: 10px; border-left: 4px solid #0284c7;">
            The website <strong>${hostname}</strong> has been flagged as suspicious. <br>
            <span style="font-weight: 600; color: #0369a1; font-size: 13px;">Reason: ${reason}</span>
          </p>

          <div style="display: flex; flex-direction: column; gap: 10px;">
            <button id="veridurl-btn-close" style="
              background: #0284c7;
              color: #ffffff;
              border: none;
              padding: 14px;
              border-radius: 12px;
              font-size: 15px;
              font-weight: 600;
              cursor: pointer;
              transition: background 0.2s;
              box-shadow: 0 4px 6px -1px rgba(2, 132, 199, 0.2);
            ">
              Close This Tab (Recommended)
            </button>
            
            <div style="display: flex; gap: 10px; margin-top: 5px;">
              <button id="veridurl-btn-whitelist" style="
                flex: 1;
                background: #ffffff;
                color: #0284c7;
                border: 1px solid #bae6fd;
                padding: 12px;
                border-radius: 12px;
                font-size: 13px;
                font-weight: 600;
                cursor: pointer;
                transition: background 0.2s;
              ">
                Trust Domain
              </button>
              
              <button id="veridurl-btn-bypass" style="
                flex: 1;
                background: #f8fafc;
                color: #94a3b8;
                border: 1px solid #e2e8f0;
                padding: 12px;
                border-radius: 12px;
                font-size: 13px;
                font-weight: 500;
                cursor: pointer;
                transition: color 0.2s;
              ">
                Proceed Anyway
              </button>
            </div>
          </div>
        </div>

        <style>
          @keyframes veridurl-slide-in {
            from { transform: translateY(20px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
          }
          @keyframes veridurl-pulse {
            0% { box-shadow: 0 0 0 0 rgba(56, 189, 248, 0.4); }
            70% { box-shadow: 0 0 0 10px rgba(56, 189, 248, 0); }
            100% { box-shadow: 0 0 0 0 rgba(56, 189, 248, 0); }
          }
          #veridurl-btn-close:hover { background: #0369a1; }
          #veridurl-btn-whitelist:hover { background: #f0f9ff; }
          #veridurl-btn-bypass:hover { color: #64748b; background: #f1f5f9; }
        </style>
      </div>
    `;

    chrome.scripting.executeScript({
      target: { tabId: tabId },
      func: (html, urlToWhitelist) => {
        // Clear any previous indicators/overlays
        document.getElementById('veridurl-warning-overlay')?.remove();
        document.getElementById('veridurl-safe-indicator')?.remove();

        const overlay = document.createElement('div');
        overlay.id = 'veridurl-warning-overlay';
        overlay.innerHTML = html;
        document.body.appendChild(overlay);

        // Close tab handler
        document.getElementById('veridurl-btn-close').addEventListener('click', () => {
          chrome.runtime.sendMessage({ action: "closeTab" });
        });

        // Add to whitelist
        document.getElementById('veridurl-btn-whitelist').addEventListener('click', () => {
          chrome.runtime.sendMessage({ action: "addToWhitelist", domain: new URL(urlToWhitelist).hostname }, () => {
            overlay.remove();
            window.location.reload();
          });
        });

        // Bypass warning
        document.getElementById('veridurl-btn-bypass').addEventListener('click', () => {
          chrome.runtime.sendMessage({ action: "bypassWarning", url: urlToWhitelist }, () => {
            overlay.remove();
          });
        });
      },
      args: [warningHTML, url]
    });
  } else if (!isSamePage) {
    // Inject a beautiful sky-blue / white safe indicator badge that slides in and vanishes
    const safeHTML = `
      <div id="veridurl-safe-indicator" style="
        position: fixed;
        bottom: 24px;
        right: 24px;
        background: rgba(255, 255, 255, 0.95);
        backdrop-filter: blur(8px);
        -webkit-backdrop-filter: blur(8px);
        border: 1px solid #bae6fd;
        border-left: 4px solid #0284c7;
        color: #0369a1;
        padding: 12px 20px;
        border-radius: 12px;
        box-shadow: 0 10px 15px -3px rgba(2, 132, 199, 0.1), 0 4px 6px -2px rgba(2, 132, 199, 0.05);
        z-index: 99999999;
        font-family: 'Inter', -apple-system, sans-serif;
        font-size: 13px;
        font-weight: 600;
        display: flex;
        align-items: center;
        gap: 10px;
        animation: veridurl-slide-up 0.5s cubic-bezier(0.16, 1, 0.3, 1) forwards,
                   veridurl-fade-out 0.5s cubic-bezier(0.16, 1, 0.3, 1) 3.5s forwards;
      ">
        <svg style="width: 18px; height: 18px; fill: #0284c7;" viewBox="0 0 24 24">
          <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>
        </svg>
        <div>
          <span style="display: block; font-size: 13px; color: #0284c7;">VeridURL Verified</span>
          <span style="display: block; font-size: 11px; color: #64748b; font-weight: 400;">Legitimate Site</span>
        </div>
        <button id="veridurl-close-safe-btn" style="
          background: none;
          border: none;
          color: #94a3b8;
          cursor: pointer;
          font-size: 16px;
          line-height: 1;
          padding: 0 0 0 5px;
        ">×</button>
      </div>

      <style>
        @keyframes veridurl-slide-up {
          from { transform: translateY(30px); opacity: 0; }
          to { transform: translateY(0); opacity: 1; }
        }
        @keyframes veridurl-fade-out {
          from { transform: translateY(0); opacity: 1; }
          to { transform: translateY(15px); opacity: 0; pointer-events: none; }
        }
      </style>
    `;

    chrome.scripting.executeScript({
      target: { tabId: tabId },
      func: (html) => {
        document.getElementById('veridurl-warning-overlay')?.remove();
        document.getElementById('veridurl-safe-indicator')?.remove();

        const indicator = document.createElement('div');
        indicator.id = 'veridurl-safe-indicator';
        indicator.innerHTML = html;
        document.body.appendChild(indicator);

        document.getElementById('veridurl-close-safe-btn').addEventListener('click', () => {
          indicator.remove();
        });

        setTimeout(() => {
          indicator.remove();
        }, 4000);
      },
      args: [safeHTML]
    });
  }
}

// Core scan trigger function
async function scanUrl(url, tabId, isReload = false) {
  if (!url || url.startsWith("chrome://") || url.startsWith("chrome-extension://") || url.startsWith("edge://") || url.startsWith("about:")) {
    return { error: "Internal browser URL skipped" };
  }

  try {
    const hostname = getDomain(url);

    // 1. Whitelist check
    const storage = await new Promise(r => chrome.storage.local.get(["whitelist", "blacklist", "bypassedUrls", "settings"], r));
    const whitelist = storage.whitelist || [];
    const blacklist = storage.blacklist || [];
    const bypassedUrls = storage.bypassedUrls || [];
    const settings = storage.settings || { engine: "cloud", autoScan: true };

    if (whitelist.includes(hostname)) {
      injectPopup(tabId, url, false, "Whitelisted Domain", false);
      return { url, isPhishing: false, reason: "Whitelisted Domain", score: 0.99 };
    }

    // 2. Blacklist check
    if (blacklist.includes(hostname)) {
      injectPopup(tabId, url, true, "User Blacklisted Domain", false);
      return { url, isPhishing: true, reason: "User Blacklisted Domain", score: 0.01 };
    }

    // 3. Warning Bypassed in current session check
    if (bypassedUrls.includes(url)) {
      return { url, isPhishing: false, reason: "Bypassed Warn", score: 0.5 };
    }

    // 4. Local Lookalike / Typosquatting Check
    const lookalikeCheck = checkTyposquatting(hostname);
    if (lookalikeCheck.isLookalike) {
      injectPopup(tabId, url, true, lookalikeCheck.reason, false);
      const res = { url, isPhishing: true, reason: lookalikeCheck.reason, score: 0.05 };
      storeScanHistory(res);
      return res;
    }

    // 5. If brand check is exact, it is a trusted domain
    if (lookalikeCheck.brand) {
      injectPopup(tabId, url, false, "Trusted Brand Domain", false);
      return { url, isPhishing: false, reason: "Trusted Brand Domain", score: 0.98 };
    }

    // 6. ML Model Scan (FastAPI call)
    let apiEndpoint = "https://phishshield-11y5.onrender.com/predict_url";
    if (settings.engine === "local") {
      apiEndpoint = "http://127.0.0.1:8000/predict_url";
    }

    const fetchPromise = fetch(apiEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url })
    });

    // Handle fetch with a timeout
    const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error("Scanner timeout")), 12000));
    const response = await Promise.race([fetchPromise, timeoutPromise]);

    if (!response.ok) throw new Error(`HTTP Status ${response.status}`);
    const data = await response.json();

    if (data.error) {
      throw new Error(data.error);
    }

    const isPhishing = data.prediction === 0; // 0 is Phishing, 1 is Safe
    const score = data.score !== undefined ? data.score : (isPhishing ? 0.2 : 0.8);
    const result = {
      url,
      isPhishing,
      reason: isPhishing ? "AI flagged suspicious structures" : "AI confirmed clean structures",
      score,
      features: data.features
    };

    storeScanHistory(result);
    injectPopup(tabId, url, isPhishing, result.reason, false);
    
    // Save tab states
    tabStates.set(tabId, { domain: hostname, previousUrl: url });

    return result;

  } catch (error) {
    console.error("VeridURL scan error:", error);
    return { error: error.message, url };
  }
}

// Debounce scanner to prevent spamming server
function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

const debouncedScan = debounce(scanUrl, 600);

// WebNavigation commits
chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId === 0) { // Only scan main page
    chrome.storage.local.get(["settings"], (res) => {
      const settings = res.settings || { engine: "cloud", autoScan: true };
      if (settings.autoScan) {
        debouncedScan(details.url, details.tabId, details.transitionType === 'reload');
      }
    });
  }
});

// Switch active tab listener
chrome.tabs.onActivated.addListener((activeInfo) => {
  chrome.tabs.get(activeInfo.tabId, (tab) => {
    if (tab && tab.url && tab.url.startsWith("http")) {
      chrome.storage.local.get(["settings"], (res) => {
        const settings = res.settings || { engine: "cloud", autoScan: true };
        if (settings.autoScan) {
          debouncedScan(tab.url, activeInfo.tabId, false);
        }
      });
    }
  });
});

// Tab closed cleanup
chrome.tabs.onRemoved.addListener((tabId) => {
  tabStates.delete(tabId);
});

// Extension communication channel
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "getCurrentStatus") {
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      if (tabs.length === 0 || !tabs[0].url || !tabs[0].url.startsWith("http")) {
        sendResponse({ error: "Unsupported tab content" });
        return;
      }
      const result = await scanUrl(tabs[0].url, tabs[0].id, false);
      sendResponse(result);
    });
    return true; // Keep channel open for async response
  } 
  
  else if (request.action === "manualCheck") {
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      const tabId = tabs.length > 0 ? tabs[0].id : 99999;
      const result = await scanUrl(request.url, tabId, false);
      sendResponse(result);
    });
    return true;
  } 
  
  else if (request.action === "closeTab") {
    if (sender.tab && sender.tab.id) {
      chrome.tabs.remove(sender.tab.id);
    }
    sendResponse({ success: true });
  } 
  
  else if (request.action === "addToWhitelist") {
    chrome.storage.local.get(["whitelist"], (res) => {
      const whitelist = res.whitelist || [];
      if (!whitelist.includes(request.domain)) {
        whitelist.push(request.domain);
        chrome.storage.local.set({ whitelist }, () => {
          sendResponse({ success: true });
        });
      } else {
        sendResponse({ success: true });
      }
    });
    return true;
  } 
  
  else if (request.action === "bypassWarning") {
    chrome.storage.local.get(["bypassedUrls"], (res) => {
      const bypassed = res.bypassedUrls || [];
      if (!bypassed.includes(request.url)) {
        bypassed.push(request.url);
        chrome.storage.local.set({ bypassedUrls: bypassed }, () => {
          sendResponse({ success: true });
        });
      } else {
        sendResponse({ success: true });
      }
    });
    return true;
  }
});

// Periodic memory flush of tabStates
setInterval(() => {
  tabStates.clear();
}, 20 * 60 * 1000);

console.log("VeridURL Protection Service Worker online.");
