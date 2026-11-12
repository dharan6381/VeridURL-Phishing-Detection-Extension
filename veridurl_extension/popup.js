// VeridURL Extension Controller

document.addEventListener("DOMContentLoaded", () => {
  // Elements
  const navButtons = document.querySelectorAll(".nav-btn");
  const tabPanels = document.querySelectorAll(".tab-panel");
  const circle = document.querySelector(".progress-ring__circle");
  const gaugeScoreText = document.getElementById("gauge-score");
  const verdictBadge = document.getElementById("verdict-badge");
  const currentDomainText = document.getElementById("current-domain-name");
  const btnToggleWhitelist = document.getElementById("btn-toggle-whitelist");
  const btnToggleBlacklist = document.getElementById("btn-toggle-blacklist");
  
  // Rules elements
  const rulesTabs = document.querySelectorAll(".rules-sub-tab");
  const rulesPanels = document.querySelectorAll(".subtab-panel");
  const ruleDomainInput = document.getElementById("rule-domain-input");
  const btnAddRule = document.getElementById("btn-add-rule");
  const whitelistUl = document.getElementById("whitelist-list");
  const blacklistUl = document.getElementById("blacklist-list");
  
  // Manual check elements
  const manualUrlInput = document.getElementById("manual-url-input");
  const btnManualScan = document.getElementById("btn-manual-scan");
  const manualScanLoading = document.getElementById("manual-scan-loading");
  const manualScanResult = document.getElementById("manual-scan-result");
  const manualBadge = document.getElementById("manual-badge");
  const manualScoreText = document.getElementById("manual-score");
  const manualReasonText = document.getElementById("manual-reason");
  const manualLenText = document.getElementById("manual-len");

  // Analytics elements
  const statScanned = document.getElementById("stat-scanned");
  const statBlocked = document.getElementById("stat-blocked");
  const statAllowed = document.getElementById("stat-allowed");
  const btnExportCsv = document.getElementById("btn-export-csv");
  const btnResetStats = document.getElementById("btn-reset-stats");
  const scansHistoryList = document.getElementById("scans-history-list");

  // Settings elements
  const settingAutoScan = document.getElementById("setting-auto-scan");
  const settingWarningOverlay = document.getElementById("setting-warning-overlay");
  const settingEngineSelect = document.getElementById("setting-engine-select");

  // SVG Gauge constants
  const radius = circle.r.baseVal.value;
  const circumference = radius * 2 * Math.PI;

  let activeTabName = "tab-overview";
  let activeRulesSubtab = "whitelist-view";
  let currentScannedUrl = "";
  let currentScannedHost = "";

  // ----------------------------------------------------
  // Tab Navigation Controls
  // ----------------------------------------------------
  navButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      const targetPanelId = btn.getAttribute("data-tab");
      
      navButtons.forEach(b => b.classList.remove("active"));
      tabPanels.forEach(p => p.classList.remove("active"));
      
      btn.classList.add("active");
      const targetPanel = document.getElementById(targetPanelId);
      targetPanel.classList.add("active");
      
      activeTabName = targetPanelId;
      onTabActivated(targetPanelId);
    });
  });

  function onTabActivated(tabId) {
    if (tabId === "tab-overview") {
      updateActiveTabStatus();
    } else if (tabId === "tab-rules") {
      loadRulesLists();
    } else if (tabId === "tab-analytics") {
      loadStatsAndHistory();
    }
  }

  // ----------------------------------------------------
  // SVG Gauge Animation
  // ----------------------------------------------------
  circle.style.strokeDasharray = `${circumference} ${circumference}`;
  circle.style.strokeDashoffset = circumference;

  function setGaugeScore(scorePercent) {
    const offset = circumference - (scorePercent / 100) * circumference;
    circle.style.strokeDashoffset = offset;
    gaugeScoreText.textContent = `${scorePercent}%`;
    
    // Gradient coloring
    if (scorePercent >= 80) {
      circle.style.stroke = "#10b981"; // Safe Green
    } else if (scorePercent >= 50) {
      circle.style.stroke = "#eab308"; // Warn Yellow
    } else {
      circle.style.stroke = "#ef4444"; // Phish Red
    }
  }

  // ----------------------------------------------------
  // Current Site State Logic
  // ----------------------------------------------------
  function updateActiveTabStatus() {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs.length === 0 || !tabs[0].url) {
        setSystemPagePlaceholder("No Active Domain");
        return;
      }
      
      const url = tabs[0].url;
      currentScannedUrl = url;
      
      try {
        currentScannedHost = new URL(url).hostname;
      } catch (e) {
        setSystemPagePlaceholder("Invalid URL Structure");
        return;
      }

      // Check for internal browser URLs
      if (url.startsWith("chrome://") || url.startsWith("chrome-extension://") || url.startsWith("edge://") || url.startsWith("about:")) {
        setSystemPagePlaceholder("Internal Browser Tab");
        return;
      }

      currentDomainText.textContent = currentScannedHost;
      document.getElementById("diagnostics-not-available").style.display = "none";
      document.getElementById("diagnostics-content").style.display = "block";

      // Query background script for actual scan results
      chrome.runtime.sendMessage({ action: "getCurrentStatus" }, (response) => {
        if (!response || response.error) {
          const errorMsg = response?.error || "Connection timed out";
          verdictBadge.textContent = "Offline/Skipped";
          verdictBadge.className = "badge badge-unknown";
          setGaugeScore(100);
          document.getElementById("typo-guard-status").textContent = `Scan failed: ${errorMsg}`;
          document.getElementById("ml-engine-status").textContent = "Check settings or network connection.";
          clearDiagnostics();
          updateRuleButtons(currentScannedHost);
          return;
        }

        // Handle Verdict
        if (response.isPhishing) {
          verdictBadge.textContent = "Phishing Detected";
          verdictBadge.className = "badge badge-phishing";
          // Compute score
          const finalScore = Math.round((response.score || 0.1) * 100);
          setGaugeScore(finalScore);
        } else {
          verdictBadge.textContent = "Safe Website";
          verdictBadge.className = "badge badge-safe";
          const finalScore = Math.round((response.score || 0.9) * 100);
          setGaugeScore(finalScore);
        }

        // Update Scan Timings & Details
        document.getElementById("scan-time").textContent = `Verified at: ${response.timestamp || new Date().toLocaleTimeString()}`;
        document.getElementById("typo-guard-status").textContent = response.isPhishing && response.reason.includes("Lookalike") 
          ? `Blocked: ${response.reason}` 
          : "Domain structure verified as clean";
        
        document.getElementById("ml-engine-status").textContent = response.isPhishing 
          ? "AI detected threat parameters on page" 
          : "AI detected no safety irregularities";

        // Update Diagnostics panel with exact extracted values
        if (response.features) {
          renderDiagnostics(response.features, response.isPhishing);
        } else {
          clearDiagnostics();
        }

        // Whitelist/Blacklist button updates
        updateRuleButtons(currentScannedHost);
      });
    });
  }

  function setSystemPagePlaceholder(label) {
    currentDomainText.textContent = label;
    verdictBadge.textContent = "System Bypassed";
    verdictBadge.className = "badge badge-safe";
    setGaugeScore(100);
    document.getElementById("scan-time").textContent = "Not scanned";
    document.getElementById("typo-guard-status").textContent = "Internal page bypass active";
    document.getElementById("ml-engine-status").textContent = "Inference is not run on browser settings";
    
    // Disable diagnostics
    document.getElementById("diagnostics-content").style.display = "none";
    document.getElementById("diagnostics-not-available").style.display = "flex";
    
    btnToggleWhitelist.style.display = "none";
    btnToggleBlacklist.style.display = "none";
  }

  function clearDiagnostics() {
    const list = ["diag-url-len", "diag-domain-len", "diag-lookalike", "diag-https", "diag-social", "diag-submit", "diag-js", "diag-css", "diag-iframe"];
    list.forEach(id => {
      const el = document.getElementById(id);
      if (el) el.querySelector(".diag-value").textContent = "N/A";
    });
  }

  function renderDiagnostics(features, isPhishing) {
    // 1. Lexical
    document.querySelector("#diag-url-len .diag-value").textContent = features.URLLength || 0;
    document.querySelector("#diag-domain-len .diag-value").textContent = features.DomainLength || 0;
    
    const isLookalike = isPhishing && (features.Abnormal_URL === 1);
    const lookValue = document.querySelector("#diag-lookalike .diag-value");
    lookValue.textContent = isLookalike ? "High Risk" : "Normal";
    lookValue.className = isLookalike ? "diag-value diag-val-warn" : "diag-value diag-val-safe";

    // 2. HTTPS / Structure
    const httpsEl = document.querySelector("#diag-https .diag-value");
    httpsEl.textContent = features.IsHTTPS === 1 ? "SSL Active" : "No SSL";
    httpsEl.className = features.IsHTTPS === 1 ? "diag-value diag-val-safe" : "diag-value diag-val-warn";

    const socialEl = document.querySelector("#diag-social .diag-value");
    socialEl.textContent = features.HasSocialNet === 1 ? "Present" : "None";

    const submitEl = document.querySelector("#diag-submit .diag-value");
    submitEl.textContent = features.HasSubmitButton === 1 ? "Form Button Detected" : "None";

    // 3. Composition
    document.querySelector("#diag-js .diag-value").textContent = features.NoOfJS || 0;
    document.querySelector("#diag-css .diag-value").textContent = features.NoOfCSS || 0;
    
    const iframeEl = document.querySelector("#diag-iframe .diag-value");
    iframeEl.textContent = features.Iframe === 1 ? "Yes (Risk)" : "No";
    iframeEl.className = features.Iframe === 1 ? "diag-value diag-val-warn" : "diag-value diag-val-safe";
  }

  // ----------------------------------------------------
  // Rules Management (Whitelist / Blacklist)
  // ----------------------------------------------------
  rulesTabs.forEach(tab => {
    tab.addEventListener("click", () => {
      const targetSubtab = tab.getAttribute("data-subtab");
      
      rulesTabs.forEach(t => t.classList.remove("active"));
      rulesPanels.forEach(p => p.classList.remove("active"));
      
      tab.classList.add("active");
      document.getElementById(targetSubtab).classList.add("active");
      
      activeRulesSubtab = targetSubtab;
    });
  });

  function updateRuleButtons(domain) {
    btnToggleWhitelist.style.display = "inline-block";
    btnToggleBlacklist.style.display = "inline-block";

    chrome.storage.local.get(["whitelist", "blacklist"], (res) => {
      const whitelist = res.whitelist || [];
      const blacklist = res.blacklist || [];

      if (whitelist.includes(domain)) {
        btnToggleWhitelist.textContent = "Remove Trust";
        btnToggleWhitelist.className = "action-btn fill";
      } else {
        btnToggleWhitelist.textContent = "Trust Site";
        btnToggleWhitelist.className = "action-btn outline";
      }

      if (blacklist.includes(domain)) {
        btnToggleBlacklist.textContent = "Unblock Site";
        btnToggleBlacklist.className = "action-btn fill danger-outline";
      } else {
        btnToggleBlacklist.textContent = "Block Site";
        btnToggleBlacklist.className = "action-btn danger-outline";
      }
    });
  }

  btnToggleWhitelist.addEventListener("click", () => {
    if (!currentScannedHost) return;
    chrome.storage.local.get(["whitelist", "blacklist"], (res) => {
      let whitelist = res.whitelist || [];
      let blacklist = res.blacklist || [];

      if (whitelist.includes(currentScannedHost)) {
        // Remove from Whitelist
        whitelist = whitelist.filter(d => d !== currentScannedHost);
      } else {
        // Add to Whitelist and clear from Blacklist
        whitelist.push(currentScannedHost);
        blacklist = blacklist.filter(d => d !== currentScannedHost);
      }
      
      chrome.storage.local.set({ whitelist, blacklist }, () => {
        updateActiveTabStatus();
      });
    });
  });

  btnToggleBlacklist.addEventListener("click", () => {
    if (!currentScannedHost) return;
    chrome.storage.local.get(["whitelist", "blacklist"], (res) => {
      let whitelist = res.whitelist || [];
      let blacklist = res.blacklist || [];

      if (blacklist.includes(currentScannedHost)) {
        // Remove from Blacklist
        blacklist = blacklist.filter(d => d !== currentScannedHost);
      } else {
        // Add to Blacklist and clear from Whitelist
        blacklist.push(currentScannedHost);
        whitelist = whitelist.filter(d => d !== currentScannedHost);
      }

      chrome.storage.local.set({ whitelist, blacklist }, () => {
        updateActiveTabStatus();
      });
    });
  });

  function loadRulesLists() {
    chrome.storage.local.get(["whitelist", "blacklist"], (res) => {
      const whitelist = res.whitelist || [];
      const blacklist = res.blacklist || [];

      // Render Whitelist
      whitelistUl.innerHTML = whitelist.length === 0 
        ? `<li class="placeholder-item" style="color:#94a3b8; text-align:center; display:block;">No whitelisted websites</li>` 
        : "";
      whitelist.forEach(domain => {
        const li = document.createElement("li");
        li.innerHTML = `
          <span>${domain}</span>
          <button class="delete-rule-btn" data-domain="${domain}" data-type="whitelist">&times;</button>
        `;
        whitelistUl.appendChild(li);
      });

      // Render Blacklist
      blacklistUl.innerHTML = blacklist.length === 0 
        ? `<li class="placeholder-item" style="color:#94a3b8; text-align:center; display:block;">No blacklisted websites</li>` 
        : "";
      blacklist.forEach(domain => {
        const li = document.createElement("li");
        li.innerHTML = `
          <span>${domain}</span>
          <button class="delete-rule-btn" data-domain="${domain}" data-type="blacklist">&times;</button>
        `;
        blacklistUl.appendChild(li);
      });

      // Attach Delete Listeners
      document.querySelectorAll(".delete-rule-btn").forEach(btn => {
        btn.addEventListener("click", (e) => {
          const dom = btn.getAttribute("data-domain");
          const type = btn.getAttribute("data-type");
          removeDomainRule(dom, type);
        });
      });
    });
  }

  function removeDomainRule(domain, type) {
    chrome.storage.local.get([type], (res) => {
      let list = res[type] || [];
      list = list.filter(d => d !== domain);
      chrome.storage.local.set({ [type]: list }, () => {
        loadRulesLists();
        updateActiveTabStatus();
      });
    });
  }

  btnAddRule.addEventListener("click", () => {
    const rawVal = ruleDomainInput.value.trim().toLowerCase();
    if (!rawVal) return;
    
    let domain = rawVal;
    try {
      if (rawVal.startsWith("http")) {
        domain = new URL(rawVal).hostname;
      }
    } catch(e) {}

    const type = activeRulesSubtab === "whitelist-view" ? "whitelist" : "blacklist";
    
    chrome.storage.local.get(["whitelist", "blacklist"], (res) => {
      let whitelist = res.whitelist || [];
      let blacklist = res.blacklist || [];

      if (type === "whitelist") {
        if (!whitelist.includes(domain)) whitelist.push(domain);
        blacklist = blacklist.filter(d => d !== domain);
      } else {
        if (!blacklist.includes(domain)) blacklist.push(domain);
        whitelist = whitelist.filter(d => d !== domain);
      }

      chrome.storage.local.set({ whitelist, blacklist }, () => {
        ruleDomainInput.value = "";
        loadRulesLists();
        updateActiveTabStatus();
      });
    });
  });

  // ----------------------------------------------------
  // Manual URL Scan
  // ----------------------------------------------------
  btnManualScan.addEventListener("click", () => {
    const url = manualUrlInput.value.trim();
    if (!url) return;

    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      alert("Please enter a complete URL starting with http:// or https://");
      return;
    }

    manualScanLoading.style.display = "flex";
    manualScanResult.style.display = "none";

    chrome.runtime.sendMessage({ action: "manualCheck", url: url }, (response) => {
      manualScanLoading.style.display = "none";
      manualScanResult.style.display = "block";

      if (!response || response.error) {
        manualBadge.textContent = "Failed";
        manualBadge.className = "badge badge-unknown";
        manualScoreText.textContent = "0%";
        manualReasonText.textContent = response?.error || "Timeout checking URL";
        manualLenText.textContent = `${url.length} chars`;
        return;
      }

      const scorePercent = Math.round((response.score || 0) * 100);
      manualScoreText.textContent = `${scorePercent}%`;
      
      if (response.isPhishing) {
        manualBadge.textContent = "Phishing";
        manualBadge.className = "badge badge-phishing";
        manualScoreText.style.color = "#ef4444";
      } else {
        manualBadge.textContent = "Safe";
        manualBadge.className = "badge badge-safe";
        manualScoreText.style.color = "#10b981";
      }

      manualReasonText.textContent = response.reason || "ML features evaluated";
      manualLenText.textContent = `${url.length} chars`;
    });
  });

  // ----------------------------------------------------
  // Analytics and Logs
  // ----------------------------------------------------
  function loadStatsAndHistory() {
    chrome.storage.local.get(["scanHistory", "stats"], (res) => {
      const stats = res.stats || { totalScanned: 0, phishingBlocked: 0, safeAllowed: 0 };
      const history = res.scanHistory || [];

      statScanned.textContent = stats.totalScanned;
      statBlocked.textContent = stats.phishingBlocked;
      statAllowed.textContent = stats.safeAllowed;

      scansHistoryList.innerHTML = history.length === 0
        ? `<div class="placeholder-view" style="padding: 20px;">No scan logs tracked yet.</div>`
        : "";

      history.forEach(item => {
        const div = document.createElement("div");
        div.className = `history-item ${item.isPhishing ? 'is-phish' : 'is-safe'}`;
        
        let scorePercent = Math.round((item.score || 0) * 100);
        
        div.innerHTML = `
          <div class="history-info">
            <span class="history-domain">${item.url}</span>
            <span class="history-meta">${item.timestamp} • Score: ${scorePercent}%</span>
          </div>
          <span class="history-badge ${item.isPhishing ? 'phish' : 'safe'}">
            ${item.isPhishing ? 'Phish' : 'Safe'}
          </span>
        `;
        scansHistoryList.appendChild(div);
      });
    });
  }

  btnResetStats.addEventListener("click", () => {
    if (confirm("Clear all scanned logs and safety statistics?")) {
      chrome.storage.local.set({
        scanHistory: [],
        stats: { totalScanned: 0, phishingBlocked: 0, safeAllowed: 0 }
      }, () => {
        loadStatsAndHistory();
        updateActiveTabStatus();
      });
    }
  });

  btnExportCsv.addEventListener("click", () => {
    chrome.storage.local.get(["scanHistory"], (res) => {
      const history = res.scanHistory || [];
      if (history.length === 0) {
        alert("No scan logs found to export.");
        return;
      }

      let csvContent = "URL,Is Phishing,Threat Reason,Safety Score,Timestamp\n";
      history.forEach(item => {
        const row = [
          `"${item.url.replace(/"/g, '""')}"`,
          item.isPhishing ? "TRUE" : "FALSE",
          `"${(item.reason || "").replace(/"/g, '""')}"`,
          `${Math.round((item.score || 0) * 100)}%`,
          `"${item.timestamp}"`
        ];
        csvContent += row.join(",") + "\n";
      });

      const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.setAttribute("href", url);
      link.setAttribute("download", `veridurl_scan_report_${new Date().toLocaleDateString().replace(/\//g, '-')}.csv`);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    });
  });

  // ----------------------------------------------------
  // Settings Integration
  // ----------------------------------------------------
  function loadSettings() {
    chrome.storage.local.get(["settings"], (res) => {
      const settings = res.settings || { engine: "cloud", autoScan: true, warnings: true };
      
      settingAutoScan.checked = settings.autoScan !== false;
      settingWarningOverlay.checked = settings.warnings !== false;
      settingEngineSelect.value = settings.engine || "cloud";
    });
  }

  function saveSettings() {
    const settings = {
      autoScan: settingAutoScan.checked,
      warnings: settingWarningOverlay.checked,
      engine: settingEngineSelect.value
    };
    chrome.storage.local.set({ settings });
  }

  [settingAutoScan, settingWarningOverlay, settingEngineSelect].forEach(element => {
    element.addEventListener("change", saveSettings);
  });

  // ----------------------------------------------------
  // Initializer Calls
  // ----------------------------------------------------
  updateActiveTabStatus();
  loadSettings();
});
