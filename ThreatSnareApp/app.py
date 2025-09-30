from flask import Flask, request, render_template, redirect, url_for, session
import pickle
import numpy as np
from tld import get_tld
from urllib.parse import urlparse
import re
import os

app = Flask(__name__)
app.secret_key = "sk_Hhishiqsio$qiost@45123"

BASE_DIR = os.path.dirname(__file__)
model_path = os.path.join(BASE_DIR, "malicious_url_model.pkl")

with open(model_path, "rb") as f:
    model = pickle.load(f)

# Feature Extraction
def having_ip_address(url):
    match = re.search(
        r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\/)|'
        r'((0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\/)|'
        r'(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)
    return 1 if match else 0

def abnormal_url(url):
    hostname = str(urlparse(url).hostname)
    return 1 if hostname not in url else 0

def count_dot(url):
    return url.count('.')

def count_www(url):
    return url.count('www')

def count_atrate(url):
    return url.count('@')

def no_of_dir(url):
    return urlparse(url).path.count('/')

def no_of_embed(url):
    return urlparse(url).path.count('//')

def shortening_service(url):
    match = re.search(
        r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
        r'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
        r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
        r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
        r'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
        r'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
        r'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
        r'tr\.im|link\.zip\.net', url)
    return 1 if match else 0

def count_https(url):
    return url.count('https')

def count_http(url):
    return url.count('http')

def count_per(url):
    return url.count('%')

def count_ques(url):
    return url.count('?')

def count_hyphen(url):
    return url.count('-')

def count_equal(url):
    return url.count('=')

def url_length(url):
    return len(url)

def hostname_length(url):
    return len(urlparse(url).netloc)

def suspicious_words(url):
    match = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr', url)
    return 1 if match else 0

def digit_count(url):
    return sum(c.isdigit() for c in url)

def letter_count(url):
    return sum(c.isalpha() for c in url)

def fd_length(url):
    urlpath = urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0

def tld_length(url):
    try:
        tld = get_tld(url, as_object=True, fix_protocol=True)
        return len(tld.tld) if tld else 0
    except:
        return 0

def extract_features(url):
    return [
        having_ip_address(url),
        abnormal_url(url),
        count_dot(url),
        count_www(url),
        count_atrate(url),
        no_of_dir(url),
        no_of_embed(url),
        shortening_service(url),
        count_https(url),
        count_http(url),
        count_per(url),
        count_ques(url),
        count_hyphen(url),
        count_equal(url),
        url_length(url),
        hostname_length(url),
        suspicious_words(url),
        fd_length(url),
        tld_length(url),
        digit_count(url),
        letter_count(url)
    ]

label_map = {0: "SAFE", 1: "DEFACEMENT", 2: "PHISHING", 3: "MALWARE"}

def map_prediction(pred):
    if pred == "SAFE":
        return "This site is safe"
    elif pred == "DEFACEMENT":
        return "This site might not be safe"
    elif pred in ["PHISHING", "MALWARE"]:
        return "This site is not safe"
    else:
        return "Unknown"
    
# Flask Routes
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form["url"]

        # --- Convert features to DataFrame with proper column names ---
        feature_names = [
            "having_ip_address", "abnormal_url", "count_dot", "count_www", "count_atrate",
            "no_of_dir", "no_of_embed", "shortening_service", "count_https", "count_http",
            "count_per", "count_ques", "count_hyphen", "count_equal", "url_length",
            "hostname_length", "suspicious_words", "fd_length", "tld_length",
            "digit_count", "letter_count"
        ]
        features = pd.DataFrame([extract_features(url)], columns=feature_names)

        # Predict
        pred_num = model.predict(features)[0]
        original_label = label_map.get(int(pred_num), "UNKNOWN")
        mapped_label = map_prediction(original_label)

        # Save to session and redirect
        session["url"] = url
        session["prediction"] = mapped_label
        return redirect(url_for("index"))
    
    url = session.pop("url", None)
    prediction = session.pop("prediction", None)
    return render_template("index.html", url=url, prediction=prediction)

if __name__ == "__main__":
    app.run(debug=True)
