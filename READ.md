

# 🛡️ AI-Powered Phishing Detection Chrome Extension

This project is a Chrome Extension designed to detect phishing URLs and suspicious messages using AI/ML models. It provides real-time protection by analyzing links or texts that users encounter while browsing.

---

## 🚀 Features

- 🔍 Scan URLs or messages for phishing threats  
- 🤖 AI-powered classification of suspicious content  
- 🧠 Trained NLP model for text/email phishing detection  
- 🌐 Chrome extension UI for quick and easy access  
- ✅ Real-time threat response (Safe, Suspicious, or Dangerous)

---

## 🧠 How It Works

1. User interacts with the Chrome extension popup.
2. They paste a **message or URL** they suspect to be phishing.
3. The extension sends the input to an **AI model via API**.
4. The model analyzes it and returns:
   - ✅ Safe
   - ⚠️ Suspicious
   - 🚫 Phishing
5. Based on the risk level, the extension shows a response and educates the user if needed.

---

## 🛠️ Tech Stack

| Component         | Technology Used                     |
|------------------|--------------------------------------|
| Frontend (UI)    | HTML, CSS, JavaScript (Vanilla)      |
| Extension Engine | Chrome Extension APIs                |
| AI Model         | Python (Scikit-learn / Transformers) |
| Backend API      | Flask (Python) or Express (Node.js)  |
| NLP (Text Scan)  | Fine-tuned BERT / DistilBERT         |
| URL Scan         | Random Forest (with custom features) |

---

## 📁 Folder Structure

```
project-root/
├── extension/
│   ├── manifest.json
│   ├── popup.html
│   ├── popup.js
│   └── style.css
├── backend/
│   ├── app.py (Flask API)
│   ├── phishing_model.pkl
│   └── phishing_detector.py
├── README.md
```

---

## 🧪 How to Run

### 🔹 1. Run the Backend (Flask)
```bash
cd backend
pip install -r requirements.txt
python app.py
```

### 🔹 2. Load Chrome Extension
- Go to `chrome://extensions/`
- Enable **Developer Mode**
- Click **Load Unpacked**
- Select the `extension/` folder

---

## 🧠 AI Models Used

| Model       | Use Case                  |
|-------------|---------------------------|
| RandomForest | URL-based phishing detection |
| DistilBERT  | Message/email phishing detection |

Both models are trained on phishing datasets and integrated via an API call.

---

## 🎯 Future Enhancements

- 🧩 Auto-highlight phishing links on webpages using `content.js`
- 🔔 Real-time alert system
- 📈 Dashboard for threat stats
- 🌐 Multilingual phishing detection

---



---

## 📜 License

This project is for educational use only. Not for commercial distribution.

---

