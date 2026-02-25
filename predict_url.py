import re
import socket
import requests
import joblib
import numpy as np
import tldextract

# ===============================
# Load ML Model
# ===============================
model = joblib.load("phishing_model.pkl")

# ===============================
# Normalize URL
# ===============================
def normalize_url(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url

# ===============================
# URL Format Validation
# ===============================
def is_valid_url_format(url):
    pattern = re.compile(
        r'^(https?:\/\/)?'
        r'([a-zA-Z0-9-]+\.)+'
        r'[a-zA-Z]{2,}'
        r'(\/.*)?$'
    )
    return bool(pattern.match(url))

# ===============================
# Website Existence (DNS + HTTP)
# ===============================
def website_exists(url):
    url = normalize_url(url)
    try:
        domain = url.split("//")[-1].split("/")[0]
        socket.gethostbyname(domain)
    except:
        return False

    try:
        r = requests.get(url, timeout=5, allow_redirects=True)
        if r.status_code < 400:
            return True
    except:
        return False

    return False

# ===============================
# Suspicious Hosting / Tunnel Detection
# ===============================
def suspicious_hosting_check(url):
    suspicious_domains = [
        "trycloudflare.com",
        "ngrok.io",
        "duckdns.org",
        "serveo.net",
        "vercel.app",
        "netlify.app",
        "github.io"
    ]

    ext = tldextract.extract(url)
    full_domain = ext.domain + "." + ext.suffix

    return full_domain in suspicious_domains

# ===============================
# Brand Impersonation Detection
# ===============================
def brand_impersonation_check(url):
    brands = [
        "facebook", "instagram", "google", "paypal",
        "amazon", "twitter", "snapchat", "netflix"
    ]

    ext = tldextract.extract(url)
    real_domain = ext.domain + "." + ext.suffix

    for brand in brands:
        if brand in url.lower() and brand not in real_domain:
            return True
    return False

# ===============================
# Feature Extraction (MATCH TRAINING)
# ===============================
def extract_features(url):
    url = normalize_url(url)
    return np.array([[
        len(url),
        url.count('.'),
        url.count('-'),
        url.count('@')
    ]])

# ===============================
# MAIN EXECUTION
# ===============================
url_input = input("Enter URL: ").strip()

# 1️⃣ Invalid / malformed URL
if not is_valid_url_format(url_input):
    print("🚨 PHISHING DETECTED (Invalid / Malformed URL)")
    exit()

# 2️⃣ Website does not exist
if not website_exists(url_input):
    print("⚠️ SUSPICIOUS: Website does NOT exist")
    exit()

# 3️⃣ Suspicious hosting (Cloudflare / Ngrok etc.)
if suspicious_hosting_check(url_input):
    print("🚨 PHISHING DETECTED (Suspicious Hosting / Tunnel Domain)")
    exit()

# 4️⃣ Brand impersonation
if brand_impersonation_check(url_input):
    print("🚨 PHISHING DETECTED (Brand Impersonation)")
    exit()

# 5️⃣ ML prediction
features = extract_features(url_input)
prediction = model.predict(features)[0]

if prediction == 1:
    print("🚨 PHISHING WEBSITE DETECTED")
else:
    print("✅ LEGITIMATE WEBSITE")
