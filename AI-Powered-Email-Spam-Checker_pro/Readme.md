# 📧 Email Spam Checker

An **AI-powered desktop application** that detects spam or phishing emails using **keyword analysis**, **suspicious URL detection**, and **VirusTotal API** scanning.  
The tool features a **Tkinter-based GUI** for easy use — no command-line skills needed!

---

## 🚀 Features
- 🖥 **User-friendly GUI** — Simple and clean interface
- 🔍 **Keyword & URL Analysis** — Detect common spam patterns
- 🛡 **VirusTotal API Integration** — Scan URLs & attachments for threats
- 📊 **Machine Learning Support** — Optional classification with Scikit-learn
- 🌐 **Environment Variables** — Secure API key management with `.env` file

---

## 📂 Project Structure
Email-Spam-Checker/
│
├── spam_checker.py # Main application (GUI + detection logic)
├── requirements.txt # Project dependencies
├── README.md # Documentation (this file)
├── LICENSE # Project license
├── .env.example # Example API key configuration
└── .gitignore # Ignore unnecessary files

---

## 🛠 Installation Guide

Follow these steps to set up and run the project on your local machine:

### 1️⃣ Clone the repository
```bash
git clone https:

### 2️⃣ Install dependencies
Make sure Python 3.8+ is installed, then run:
```bash
pip install -r requirements.txt
https://github.com/ghostempireis/AI-Powered-Projects.git
```

### 3️⃣ Configure API Key
This project uses VirusTotal API for advanced threat detection.

insert your API key:
```
VIRUSTOTAL_API_KEY=your_api_key_here
```
You can get a free API key from [VirusTotal](https://www.virustotal.com/).

---

## ▶️ Usage Instructions
Run the main application:
```bash
python spam_checker.py
```
The GUI will open — paste your email text or suspicious link in the input box.

Click **"Check Spam"**:

The app will analyze:
- Spam-related keywords
- Suspicious URLs
- VirusTotal API reports

Results will be displayed in the output panel.

---

## 📷 Example Workflow
Paste suspicious email text:
```text
Congratulations! You have won $1000. Click here to claim: http://bit.ly/scam
```
Press **Check Spam**

Output:
```yaml
[!] Potential Spam Detected
Reason: Suspicious URL, Common Scam Keywords
VirusTotal: 12/70 engines flagged the link
```

---

## 📜 License
This project is licensed under the MIT License – see the LICENSE file for details.

---

## 💡 Author
**Ranjan Kumar**  
🚀 Passionate about Cybersecurity & AI  
📧 Email - ranjan.osint@gmail.com

LinkedIn profile -https://www.linkedin.com/in/ranjanchauhan-cybersec/
