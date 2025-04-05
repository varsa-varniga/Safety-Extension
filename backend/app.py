from flask import Flask, request, jsonify
import pickle
import numpy as np
from urllib.parse import urlparse
import re

app = Flask(__name__)

# Load the trained model
with open("phishing_model.pkl", "rb") as f:
    model = pickle.load(f)

# Safe domains
SAFE_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "twitter.com", "linkedin.com",
    "amazon.com", "microsoft.com", "apple.com", "github.com", "stackoverflow.com",
    "openai.com", "wikipedia.org", "instagram.com", "reddit.com", "netflix.com",
    "https://www.github.com",
"https://www.linkedin.com/in/some-profile",
"https://www.amazon.com/product/B00X4WHP5E",
"https://stackoverflow.com/questions/12345",
"https://www.wikipedia.org/",
"https://openai.com/research",
"amazon.com",
    "microsoft.com",
    "apple.com",
    "github.com",
    "stackoverflow.com",
    "openai.com",
    "wikipedia.org",
    "instagram.com",
    "reddit.com",
    "netflix.com"

]

def extract_features(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    features = [
        url.count('.'),  # NumDots
        hostname.count('.') if hostname else 0,  # SubdomainLevel
        len(parsed.path.strip('/').split('/')) if parsed.path else 0,  # PathLevel
        len(url),  # UrlLength
        url.count('-'),  # NumDash
        hostname.count('-') if hostname else 0,  # NumDashInHostname
        1 if '@' in url else 0,  # AtSymbol
        1 if '~' in url else 0,  # TildeSymbol
        url.count('_'),  # NumUnderscore
        url.count('%'),  # NumPercent
        len(parsed.query.split('&')) if parsed.query else 0,  # NumQueryComponents
        url.count('&'),  # NumAmpersand
        url.count('#'),  # NumHash
        sum(c.isdigit() for c in url),  # NumNumericChars
        1 if not url.startswith("https") else 0,  # NoHttps
        1 if re.search(r"[a-zA-Z]{10,}", parsed.netloc or "") else 0,  # RandomString
        1 if re.match(r"\d+\.\d+\.\d+\.\d+", hostname or "") else 0,  # IpAddress
        0,  # DomainInSubdomains
        0,  # DomainInPaths
        1 if 'https' in hostname else 0,  # HttpsInHostname
        len(hostname),  # HostnameLength
        len(parsed.path),  # PathLength
        len(parsed.query),  # QueryLength
        1 if '//' in parsed.path else 0,  # DoubleSlashInPath
        0,  # NumSensitiveWords
        0,  # EmbeddedBrandName
        0,  # PctExtHyperlinks
        0,  # PctExtResourceUrls
        0,  # ExtFavicon
        0,  # InsecureForms
        0,  # RelativeFormAction
        0,  # ExtFormAction
        0,  # AbnormalFormAction
        0,  # PctNullSelfRedirectHyperlinks
        0,  # FrequentDomainNameMismatch
        0,  # FakeLinkInStatusBar
        0,  # RightClickDisabled
        0,  # PopUpWindow
        0,  # SubmitInfoToEmail
        0,  # IframeOrFrame
        0,  # MissingTitle
        0,  # ImagesOnlyInForm
        0,  # SubdomainLevelRT
        0,  # UrlLengthRT
        0,  # PctExtResourceUrlsRT
        0,  # AbnormalExtFormActionR
        0,  # ExtMetaScriptLinkRT
        0,  # PctExtNullSelfRedirectHyperlinksRT
        0   # Final Placeholder (e.g., MissingFavicon)
    ]
    
    return features

@app.route('/')
def home():
    return "✅ URL-based Phishing Detection API is running!"

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        url = data.get('url')
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        # ✅ Safe list check
        if any(domain in hostname for domain in SAFE_DOMAINS):
            return jsonify({
                "url": url,
                "prediction": 1,
                "result": "Legitimate (Safe-listed)",
                "confidence": 1.0
            })

        # ✅ Extract features and predict
        features = extract_features(url)
        features = np.array([features])
        
        prediction = model.predict(features)[0]
        confidence = float(model.predict_proba(features)[0][prediction])

        result = "Legitimate" if prediction == 1 else "Phishing"

        return jsonify({
            "url": url,
            "prediction": int(prediction),
            "result": result,
            "confidence": round(confidence, 4)
        })

    except Exception as e:
        print("❌ Error during prediction:", e)
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
