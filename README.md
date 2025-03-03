# 🚀 ReconSense - AI-Powered Bug Bounty Reconnaissance Framework

![FastAPI](https://img.shields.io/badge/FastAPI-Framework-blue.svg) ![Status](https://img.shields.io/badge/Status-Active-green) ![License](https://img.shields.io/badge/License-MIT-blue)

**ReconSense** is an **AI-powered bug bounty reconnaissance framework** built on **FastAPI**. It automates reconnaissance using **Hadix Methodology v4**, integrating multiple APIs (Shodan, SecurityTrails, Slack) for **deep target analysis**.

---

## 📌 Features

- ✅ **Active & Passive Reconnaissance**
- ✅ **Shodan & SecurityTrails API Integration**
- ✅ **Slack Webhooks for Notifications**
- ✅ **AI-driven Threat Analysis (Upcoming)**
- ✅ **GraphQL & REST API support**
- ✅ **FastAPI-powered lightweight backend**

---

## 📂 Project Structure

```
ReconSense/
│── src/
│   ├── recon/                # Reconnaissance Modules
│   │   ├── active_scan.py    # Active scanning module
│   │   ├── passive_scan.py   # Passive reconnaissance
│   │   ├── shodan_recon.py   # Shodan API integration
│   │   ├── securitytrails.py # SecurityTrails API integration
│   │   ├── slack_config.py   # Slack webhook alerts
│   ├── routes.py             # FastAPI routes
│   ├── schemas.py            # Data models
│── venv/                     # Virtual environment (ignored)
│── requirements.txt          # Python dependencies
│── README.md                 # Project documentation
│── .gitignore                # Git ignore rules
```

---

## 🛠️ Installation

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/m0ni01/ReconSense.git
cd ReconSense
```

### 2️⃣ Set Up a Virtual Environment

```bash
python -m venv venv
source venv/bin/activate   # Linux/macOS
venv\Scripts\activate    # Windows
```

### 3️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 🚀 Usage

### Run the FastAPI Server

```bash
uvicorn src.main:app --reload
```

### API Documentation

Once the server is running, open:

- **Swagger UI**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc UI**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

---

## 🕵️‍♂️ Reconnaissance Modules

| Module             | Description                                  | Status |
|--------------------|----------------------------------------------|--------|
| **Active Scan**    | Scans for live hosts, open ports, and vulnerabilities | ✅ Completed |
| **Passive Scan**   | Gathers intelligence from external sources (OSINT) | ✅ Completed |
| **Shodan Recon**   | Uses the Shodan API to fetch target information | ✅ Completed |
| **SecurityTrails** | Uses SecurityTrails API to find DNS & domain data | ✅ Completed |
| **Slack Alerts**   | Sends alerts to Slack channels | ✅ Completed |
| **AI-based Analysis** | AI-driven threat intelligence & risk assessment | ⏳ In Progress |

---

## ⚙️ Configuration

### 🔑 API Key Setup

Create a `.env` file in the root directory and add:

```ini
SHODAN_API_KEY="your_shodan_api_key"
SECURITYTRAILS_API_KEY="your_securitytrails_api_key"
SLACK_WEBHOOK_URL="your_slack_webhook_url"
```

💡 **Never share API keys!** Make sure to add `.env` to `.gitignore`.

---

## 💻 Development

### Code Formatting

```bash
black .
```

### Linting

```bash
flake8 src/
```

### Running Tests

```bash
pytest
```

---

## 🛡️ Security Considerations

- Store API keys in **environment variables**.
- Use **secure API endpoints** and validate user input.
- Restrict API access using **authentication & authorization**.

---

## 👨‍💻 Contributing

💡 **We welcome contributions!** Follow these steps:

1. **Fork** the repository  
2. **Create a feature branch**:  
   ```bash
   git checkout -b feature-xyz
   ```
3. **Commit changes**:  
   ```bash
   git commit -m "Added new feature"
   ```
4. **Push to your fork**:  
   ```bash
   git push origin feature-xyz
   ```
5. Open a **Pull Request (PR)** on GitHub

---

## 🔗 Resources & Documentation

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Shodan API](https://developer.shodan.io/)
- [SecurityTrails API](https://docs.securitytrails.com/)
- [Hadix Recon Methodology](https://github.com/jhaddix/)

---

## 📜 License

This project is licensed under the **MIT License**.

```
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software...
```

---

## 📬 Contact

For any inquiries or contributions, feel free to reach out!
linkabdulmonam@gmail.com
---



---


