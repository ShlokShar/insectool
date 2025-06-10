# 🕷 insectool

**insectool** is a lightweight Python script that automates the early-stage scanning process when assessing a potentially vulnerable website.

Instead of manually testing payloads for XSS, SQL injection, or cookie misconfigurations, **insectool** automatically injects multiple payloads across input parameters and headers, analyzes responses, and then flags any behavior that suggests a vulnerability. This lets you to focus your manual efforts on specific vulnerabilities the program finds.

---

## 🚀 Features

- Tests for reflected **XSS** vulnerabilities via URL parameters and headers
- Injects common **SQL payloads**  via URL parameters
- Scans for insecure **Cookie** configurations:
  - Checks missing `HttpOnly`, `Secure`, and `SameSite` flags
  - Checks for **short cookie lengths** (possible brute forcing)
  - Scans raw & base64-decoded cookie values for keywords (e.g. 'admin', 'user', 'loggedIn', etc.) to identify exposed roles or manipulatable data
- Simple stdin/stdout interface for easy usage and debugging

---

## 📦 Installation

Clone this repository and install the required packages listed in requirements.txt.

```bash
git clone https://github.com/ShlokShar/insectool
cd insectool
pip install -r requirements.txt
```

---

## 💻 Usage

Run the script using python:
```python3
python3 insect.py
```
After entering a target URL, the tool will automatically start vulnerability tests.

Example:  
![example image](https://github.com/ShlokShar/insectool/blob/master/assets/example.png?raw=true "Example")
