# NGINX Log Generator

Generate realistic NGINX access logs with customizable malicious patterns for security testing.

---

## 🚀 Features

- 🛡️ **Configurable Traffic Ratios** - Control benign vs. malicious traffic distribution.
- ⚙️ **Modular Attack Profiles** - Simulate C2, DDoS, scanning, and more.
- 📈 **Realistic User Behavior** - Emulates human-like browsing patterns.
- 🕵️ **Stealth Malicious Traffic** - Hidden attacks blended within normal traffic.
- ⏱️ **Time-Series Log Generation** - Logs maintain realistic timestamps.

---

## 📥 Installation

```bash
git clone https://github.com/jxkx1/nginx-log-generator
cd nginx-log-generator
pip install -r requirements.txt
```

---

## ⚡ Usage

### Basic Log Generation
```bash
python log_generator.py -n 10000 -m 50 -o test.log
```
- `-n 10000` → Total log entries
- `-m 50` → Number of malicious log entries
- `-o test.log` → Output file

### Simulating Specific Attacks
```bash
python log_generator.py --profile ddos -m 200
```
- `--profile ddos` → Use the DDoS attack profile
- `-m 200` → Generate 200 malicious requests

---

## 🛠️ Configuration

### 1️⃣ **Main Settings (`config.py`)**
- Define **target domain**, traffic ratios, status codes, and user agents.
- Example:
  ```python
  DOMAIN = "example.com"
  MALICIOUS_TRAFFIC_RATIO = 0.05
  STATUS_CODE_PROBABILITIES = {200: 0.9, 403: 0.05, 404: 0.05}
  ```

### 2️⃣ **Attack Profiles (`malicious_profiles.py`)**
- Pre-built and customizable attack patterns.
- Example: **SQL Injection Attack**
  ```python
  "sqli": {
      "patterns": [
          "GET /products?id=1' UNION SELECT password FROM users--",
          "GET /login?user=admin' OR 1=1--"
      ]
  }
  ```
- Run the attack:
  ```bash
  python log_generator.py --profile sqli -m 100
  ```

---

## 📊 Sample Log Output

```
192.168.1.1 - - [02/Feb/2025:19:35:12 +0000] "GET /products?category=electronics HTTP/1.1" 200 3421 "https://acmesolutions.shop/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36..."
198.18.0.253 - - [02/Feb/2025:19:35:15 +0000] "GET /wp-login.php HTTP/1.1" 200 285 "-" "curl/7.88.1"
```

---

## 🔥 Use Cases

- 🚨 **SIEM Rule Validation** - Train security detection systems.
- 🔍 **Forensic Analysis Training** - Enhance incident response capabilities.
- 🛡️ **WAF Testing** - Simulate and improve web security.
- 📊 **Log Analysis Pipeline Testing** - Benchmark processing performance.
- 🏋️ **Detection Engineering** - Develop advanced detection rules.

---

## 🔑 Key Features for Security Testing

### 1️⃣ **Realistic Traffic Blending**
- Malicious requests mimic real-world behavior.
- 5-10% of attack requests receive 404 responses.
- Randomized request timing to avoid easy detection.

### 2️⃣ **Custom Attack Simulation**
```python
"apt": {
    "ips": ['172.16.{}'.format(i) for i in range(100, 150)],
    "paths": ['/api/v1/data', '/export.csv'],
    "user_agents": ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "curl/7.79.1"],
    "patterns": [
        "GET /backup.zip HTTP/1.1",
        "POST /api/exportData HTTP/1.1"
    ]
}
```

### 3️⃣ **Log Analysis Challenges**
- Slow DDoS patterns (e.g., 5 requests/sec from 200 IPs).
- Obfuscated command strings (e.g., Base64 encoded payloads).
- Malicious requests use legitimate-looking user agents.

---

## 🏗️ Recommended Workflow

1️⃣ **Generate Baseline Logs** (No malicious traffic):
```bash
python log_generator.py -n 100000 -m 0 -o baseline.log
```

2️⃣ **Create a Custom Attack Profile**:
```python
"my_attack": {
     "ips": [''],
     "paths": [''],
     "user_agents": [""],
     "patterns": [""]
}
```

3️⃣ **Generate Test Logs**:
```bash
python log_generator.py --profile my_attack -m 500 -o test.log
```

4️⃣ **Mix Logs for Training**:
```bash
cat baseline.log test.log > training.log
```

5️⃣ **Analyze with Security Tools**:
```bash
cat training.log | your-analysis-tool --rules detection-rules.yara
```

---

## 📌 Future Enhancements
- 📍 Custom log formats
- 🌎 Geographic IP distribution
- 🌐 Browser version simulation
- 📅 Seasonal traffic trends
- 🔐 Authentication flow modeling

---

## 📜 License
MIT License. See `LICENSE` for details.

