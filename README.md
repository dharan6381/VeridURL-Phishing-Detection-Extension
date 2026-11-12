# VeridURL - Realtime Phishing Detection Browser Extension

**VeridURL** is a premium, browser-based cybersecurity extension designed to block phishing attempts in real-time. By leveraging a hybrid security architecture combining local heuristics, typosquatting domain analysis, and a machine learning model, VeridURL protects users from malicious links without slowing down their browsing experience.

The frontend is styled in a modern, premium **white and sky-blue theme** featuring glassmorphism cards and smooth micro-animations.

---

## 🚀 Key Features

1. **Typosquatting & Lookalike Domain Guard**: Runs client-side. Instantly detects if a URL is spoofing a popular brand (e.g. `paypa1.com` instead of `paypal.com` or `goog1e.com` instead of `google.com`) using Levenshtein distance algorithms.
2. **XGBoost Machine Learning Model**: Uses a lightweight XGBoost model with over 98% accuracy. The FastAPI backend extracts 22 structural, connection, and code characteristics of the target webpage to calculate a precise safety classification.
3. **Detailed Security Diagnostics**: Displays a breakdown of URL properties, SSL encryption status, JavaScript/CSS scripts, and hidden frames in a dedicated tab.
4. **Flexible Scanning Engines**: Users can toggle between **Cloud Node Engine** (deployed on Render) and a **Local Engine** (running locally on port 8000 for developers).
5. **Custom Rules Engine**: Allows users to whitelist domains they trust or blacklist domains they want to block immediately.
6. **Analytics Dashboard**: Tracks the number of scanned, blocked, and allowed pages. Includes an export tool to download scan history logs as a CSV file.

---

## 📂 Project Structure

```
VeridURL/
├── veridurl_extension/         # Chrome Extension Files (Manifest V3)
│   ├── assets/                 # Brand logos (16x16, 48x48, 128x128)
│   ├── background.js           # Background service worker (Navigation & local guards)
│   ├── popup.html              # Extension Popup Panel UI
│   ├── popup.css               # Sky-blue & white styled stylesheet
│   ├── popup.js                # Extension popup controller
│   └── manifest.json           # Extension configuration metadata
├── veridurl_backend/           # FastAPI Machine Learning Engine
│   ├── ml_models/              # Serialized XGBoost Model and Scalers
│   │   ├── scaler.pkl          # Scikit-learn Feature Scaler
│   │   └── xgboost_model.json  # XGBoost Model Weights
│   ├── api_server.py           # REST API endpoints (fastapi)
│   ├── extractor.py            # Feature Extractor Module (BeautifulSoup4/TLD)
│   └── requirements.txt        # Backend dependencies
├── run_backend.bat             # One-click Windows runner for local engine
└── README.md                   # This instruction documentation
```

---

## 🛠️ Installation & Setup

### 1. Installing the Browser Extension
1. Open Google Chrome (or any Chromium browser like Brave, Edge).
2. Navigate to `chrome://extensions/` in the URL bar.
3. Enable **Developer mode** (toggle in the top-right corner).
4. Click **Load unpacked** in the top-left corner.
5. Select the `veridurl_extension` folder inside this directory.
6. Pin the **VeridURL** extension to your browser toolbar!

### 2. Running the Local API Server (Optional)
By default, VeridURL uses the Cloud Engine. To run the analysis engine on your own machine:
1. Double-click the `run_backend.bat` file in the root folder.
2. The script will automatically create a Python virtual environment, install the required packages (`fastapi`, `xgboost`, `pandas`, etc.), and launch the server.
3. Once running, you can open `http://127.0.0.1:8000/docs` to view the interactive API docs.
4. Click the extension popup, go to **Settings**, and change the engine to **Local Developer Node (FastAPI)**.

---

## 📊 Feature Extraction Schema

The XGBoost model processes the following 22 attributes extracted from raw web pages:
- **Lexical**: URL Length, Domain Length, Top Level Domain (TLD) Length, Letter-to-Digit Ratio, Lookalike Host Indicators.
- **Connection**: SSL status (HTTPS), URL redirects history.
- **HTML Content**: Number of Images, Scripts (JS), Stylesheets (CSS), Local vs. External Resource References, Form Submit Buttons, favicon link headers, Copyright Info, Hidden IFrames, Obfuscated JavaScript scripts, and Popup window triggers.

---

## 📜 License
This project is open-source and released under the MIT License.
