import re
import tkinter as tk
from tkinter import scrolledtext, messagebox
from langdetect import detect
import requests

# Add your VirusTotal API key here (string in quotes)
VT_API_KEY = "3fdc2382239ece9ee54762c980228e787bc9e27447fcd2d52ca463e225912201"

# ----------------- Keyword lists per language -----------------
spam_keywords = {
    "en": [
        "free money", "make money fast", "earn cash", "double your income",
        "extra income", "cash bonus", "million dollars", "get paid",
        "no investment", "risk-free", "lowest price", "save big", "big bucks",
        "debt free", "financial freedom", "act now", "apply now", "be your own boss",
        "best price", "billion dollars", "call now", "cancel anytime", "cheap", "claim now",
        "congratulations", "credit card offer", "double your money", "earn per week",
        "exclusive deal", "fast cash", "get rich", "guaranteed", "instant access",
        "limited time", "money back", "no fees", "one time offer", "urgent", "winner"
    ],
    "hi": [
        "मुफ़्त", "मुफ्त पैसा", "जल्दी पैसा कमाओ", "कैश बोनस", "खास ऑफर", "बिना निवेश",
        "जोखिम मुक्त", "सबसे कम कीमत", "विशेष प्रमोशन", "घर बैठे काम", "तुरंत लाभ", "जीत"
    ],
    "ar": [
        "مال مجاني", "اربح المال بسرعة", "مكافأة نقدية", "عرض حصري", "بدون استثمار",
        "بدون مخاطر", "أدنى سعر", "فرصة العمر", "اربح الآن", "رابح", "عاجل"
    ],
    "es": [
        "dinero gratis", "gana dinero rápido", "bono en efectivo", "oferta exclusiva",
        "sin inversión", "sin riesgo", "precio más bajo", "gran oferta", "trabaja desde casa",
        "promoción especial", "ganador", "tiempo limitado"
    ]
}

SPAM_THRESHOLD = 2  # matches required to mark as spam
live_detection = False

# ----------------- Helper functions -----------------

def detect_language(text):
    try:
        lang = detect(text)
    except Exception:
        return "en"
    if lang.startswith("en"):
        return "en"
    if lang.startswith("hi") or lang.startswith("hi-"):
        return "hi"
    if lang.startswith("ar"):
        return "ar"
    if lang.startswith("es"):
        return "es"
    return "en"

def keyword_matches(email_lower, keyword):
    if any(ord(ch) > 127 for ch in keyword):
        return keyword in email_lower
    return bool(re.search(rf"\b{re.escape(keyword)}\b", email_lower))

def extract_urls(text):
    url_pattern = re.compile(r'https?://[^\s]+')
    return url_pattern.findall(text)

def is_url_suspicious(url):
    suspicious_patterns = [
        r"\d{1,3}(\.\d{1,3}){3}",
        r"@",
        r"(login|secure|update|account|verify)",
    ]
    for pattern in suspicious_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            return True
    if len(url) > 75:
        return True
    return False

def check_url_virustotal(url):
    headers = {
        "x-apikey": VT_API_KEY
    }
    api_url = f"https://www.virustotal.com/api/v3/urls"
    
    # VirusTotal API requires URL to be URL-encoded and base64-encoded without padding
    import base64
    url_bytes = url.encode('utf-8')
    url_b64 = base64.urlsafe_b64encode(url_bytes).decode('utf-8').strip("=")
    full_url = f"https://www.virustotal.com/api/v3/urls/{url_b64}"
    
    try:
        response = requests.get(full_url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            # Extract malicious count or categories
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            if malicious > 0 or suspicious > 0:
                return True, f"URL flagged malicious by VirusTotal: malicious={malicious}, suspicious={suspicious}"
            else:
                return False, "URL not flagged as malicious by VirusTotal."
        else:
            return False, f"VirusTotal API error: HTTP {response.status_code}"
    except Exception as e:
        return False, f"VirusTotal API exception: {str(e)}"

def generate_simple_explanation(spam_score, matched_keywords, urls, suspicious_urls, vt_results):
    explanation = []
    if spam_score > 0 and matched_keywords:
        explanation.append(f"Detected suspicious keywords: {', '.join(matched_keywords)}.")
    if suspicious_urls:
        explanation.append(f"Found suspicious URLs based on heuristics: {', '.join(suspicious_urls)}.")
    for url, (is_malicious, vt_msg) in vt_results.items():
        if is_malicious:
            explanation.append(f"VirusTotal flagged URL: {url}. Details: {vt_msg}")
        else:
            explanation.append(f"VirusTotal clean URL: {url}.")
    if not explanation:
        explanation.append("No suspicious content detected.")
    return " ".join(explanation)

def analyze_single_email(email_text):
    lang = detect_language(email_text)
    keywords_for_lang = [kw.lower() for kw in spam_keywords.get(lang, spam_keywords["en"])]
    email_lower = email_text.lower()

    spam_score = 0
    matched = []
    for kw in keywords_for_lang:
        if keyword_matches(email_lower, kw):
            spam_score += 1
            matched.append(kw)

    urls = extract_urls(email_text)
    suspicious_urls = [url for url in urls if is_url_suspicious(url)]

    # Check URLs via VirusTotal API
    vt_results = {}
    for url in urls:
        vt_results[url] = check_url_virustotal(url)

    explanation = generate_simple_explanation(spam_score, matched, urls, suspicious_urls, vt_results)

    is_spam = (spam_score >= SPAM_THRESHOLD) or any(vt_results[url][0] for url in urls) or (len(suspicious_urls) > 0)

    return {
        "lang": lang,
        "spam_score": spam_score,
        "matched_keywords": matched,
        "keyword_count": len(keywords_for_lang),
        "urls": urls,
        "suspicious_urls": suspicious_urls,
        "vt_results": vt_results,
        "explanation": explanation,
        "is_spam": is_spam
    }

# ----------------- Main check (batch) -----------------

def check_spam_batch():
    content = input_area.get("1.0", tk.END).strip()
    if not content:
        messagebox.showwarning("Input Error", "Please paste at least one email in the input box.")
        return

    emails = [e.strip() for e in content.split('---') if e.strip()]
    if not emails:
        messagebox.showwarning("Format Error", "No emails found. Use '---' on a separate line to separate multiple emails.")
        return

    results_area.config(state="normal")
    results_area.delete("1.0", tk.END)

    for idx, email in enumerate(emails, start=1):
        result = analyze_single_email(email)
        header = f"Email #{idx} [{result['lang'].upper()}] : "
        if result['is_spam']:
            results_area.insert(tk.END, header + "🚫 SPAM or Phishing Suspected\n", "spam")
        else:
            results_area.insert(tk.END, header + "✅ Not Spam\n", "notspam")

        results_area.insert(tk.END, f"Spam Score: {result['spam_score']} / {result['keyword_count']}\n", "normal")
        results_area.insert(tk.END, "Matched Keywords: " + (", ".join(result['matched_keywords']) if result['matched_keywords'] else "None") + "\n", "keyword")

        if result['urls']:
            results_area.insert(tk.END, "URLs found:\n", "normal")
            for url in result['urls']:
                mark = ""
                if url in result['suspicious_urls']:
                    mark += " (Suspicious)"
                if result['vt_results'].get(url, (False,))[0]:
                    mark += " (VirusTotal Malicious)"
                results_area.insert(tk.END, f"  {url}{mark}\n", "normal")
        else:
            results_area.insert(tk.END, "URLs found: None\n", "normal")

        results_area.insert(tk.END, "Explanation:\n" + result['explanation'] + "\n", "normal")
        results_area.insert(tk.END, "-"*70 + "\n", "sep")

    results_area.config(state="disabled")

# ----------------- Live detection handler -----------------
def live_handler(event=None):
    check_spam_batch()

# ----------------- Toggle live -----------------
def toggle_live():
    global live_detection
    live_detection = not live_detection
    if live_detection:
        live_btn.config(text="Live: ON", bg="green")
        input_area.bind("<KeyRelease>", live_handler)
    else:
        live_btn.config(text="Live: OFF", bg="gray")
        input_area.unbind("<KeyRelease>")

# ----------------- Clear -----------------
def clear_all():
    input_area.delete("1.0", tk.END)
    results_area.config(state="normal")
    results_area.delete("1.0", tk.END)
    results_area.config(state="disabled")

# ----------------- GUI -----------------
root = tk.Tk()
root.title("Email Spam Checker - Pro (Batch + Live + VirusTotal)")
root.geometry("820x700")
root.resizable(False, False)
root.config(bg="#f7f7fb")

title = tk.Label(root, text="📧 Email Spam Checker - Pro", font=("Helvetica", 18, "bold"), bg="#f7f7fb", fg="#222")
title.pack(pady=(12,4))

instr = tk.Label(root, text="Paste one or more emails below. Use a line with --- to separate emails.",
                 font=("Helvetica", 10), bg="#f7f7fb", fg="#0b63d6", justify="center")
instr.pack()

sep = tk.Frame(root, height=2, bg="#cccccc")
sep.pack(fill="x", padx=20, pady=(6,10))

input_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=95, height=18, font=("Arial", 11))
input_area.pack(padx=12, pady=(0,10))

btn_frame = tk.Frame(root, bg="#f7f7fb")
btn_frame.pack(pady=6)

check_btn = tk.Button(btn_frame, text="Check Emails", command=check_spam_batch, width=16, bg="#e63946", fg="white", font=("Arial", 11))
check_btn.grid(row=0, column=0, padx=6)

clear_btn = tk.Button(btn_frame, text="Clear", command=clear_all, width=12, bg="#ff914d", fg="white", font=("Arial", 11))
clear_btn.grid(row=0, column=1, padx=6)

live_btn = tk.Button(btn_frame, text="Live: OFF", command=toggle_live, width=12, bg="gray", fg="white", font=("Arial", 11))
live_btn.grid(row=0, column=2, padx=6)

hint_lbl = tk.Label(root, text="Tip: Separate multiple emails with a line containing only ---",
                    font=("Helvetica", 9), bg="#f7f7fb", fg="#555")
hint_lbl.pack()

res_title = tk.Label(root, text="Results:", font=("Helvetica", 12, "bold"), bg="#f7f7fb")
res_title.pack(pady=(8,0))

results_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=95, height=12, font=("Arial", 10), state="disabled")
results_area.pack(padx=12, pady=(4,12))

results_area.tag_config("spam", foreground="red", font=("Arial", 11, "bold"))
results_area.tag_config("notspam", foreground="green", font=("Arial", 11, "bold"))
results_area.tag_config("keyword", foreground="#6a1b9a")
results_area.tag_config("normal", foreground="#111")
results_area.tag_config("sep", foreground="#888")

root.mainloop()
