# Email Phishing Analyzer

Automated SOC tool for analyzing and investigating phishing emails with a full pipeline: header analysis, URL extraction, attachment inspection, VirusTotal reputation checks, HTML phishing detection, and PDF report generation.

---

## 🚀 Features
- ✅ Email fetching via IMAP  
- ✅ Header authentication analysis (SPF, DKIM, DMARC)  
- ✅ URL extraction + reputation lookup  
- ✅ Attachment analysis and hashing  
- ✅ HTML phishing pattern detection  
- ✅ VirusTotal integration  
- ✅ PDF report generation  
- ✅ Web dashboard (Flask)  

---

## ⚡ Quick Start

### **Requirements**
- Python 3.9+
- IMAP-enabled email account
- VirusTotal API key (optional)

### **Installation**
```bash
git clone https://github.com/ahmddd1/email-phishing-analyzer.git
cd email-phishing-analyzer
pip install -r requirements.txt
```

### **Configuration**
Edit `config/settings.yaml`:
```yaml
imap:
  server: "imap.gmail.com"
  username: "your-email"
  password: "app-password"

virustotal:
  api_key: "your-api-key"

web:
  host: "0.0.0.0"
  port: 5000
```

### **Run**
```bash
python src/web/app.py
```

Access the dashboard:  
```
http://localhost:5000
```

---

## 📂 Project Structure
```
email-phish-analyzer/
├── src/
│   ├── inbox/
│   ├── parsers/
│   ├── analysis/
│   ├── reporting/
│   └── web/
├── config/
├── samples/
├── docker/
└── tests/
```

---

## 🧪 Testing
```bash
pytest -v tests/
```

---

## 🛠 Development Notes
- Add new analyzers under `src/analysis/`
- Add tests under `tests/`
- Follow modular structure for pipeline integrations

---

## 🔮 Roadmap
- ML-based phishing detection  
- Additional threat-intel feeds  
- SIEM integration  
- Sandbox analysis for attachments  

---

## 📜 License
MIT License

---

## 👤 Author
Ahmed — [GitHub Profile](https://github.com/ahmddd1)
